// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/*!
XDP (eXpress Data Path).

XDP provides high performance network processing capabilities in the kernel.
For an overview of XDP and how it works, see
<https://www.iovisor.org/technology/xdp>.

# Example

Block all traffic directed to port 80:

```
#![no_std]
#![no_main]
use redbpf_probes::bindings::*;
use redbpf_probes::xdp::{XdpAction, XdpContext};
use redbpf_macros::{program, xdp};

program!(0xFFFFFFFE, "GPL");

#[xdp]
pub extern "C" fn block_port_80(ctx: XdpContext) -> XdpAction {
    if let Some(transport) = ctx.transport() {
        if transport.dest() == 80 {
            return XdpAction::Drop;
        }
    }

    XdpAction::Pass
}
```
 */
use core::mem;
use core::slice;
use cty::*;

use crate::bindings::*;
use crate::maps::{PerfMap as PerfMapBase, PerfMapFlags};

use redbpf_macros::impl_xdp_array;

pub trait XdpArray {}
impl_xdp_array!();

/// The return type of XDP probes}
#[repr(u32)]
pub enum XdpAction {
    /// Signals that the program had an unexpected anomaly. Should only be used
    /// for debugging purposes.
    ///
    /// Results in the packet being dropped.
    Aborted = xdp_action_XDP_ABORTED,
    /// The simplest and fastest action. It simply instructs the driver to drop
    /// the packet.
    Drop = xdp_action_XDP_DROP,
    /// Pass the packet to the normal network stack for processing. Note that the
    /// XDP program is allowed to have modified the packet-data.
    Pass = xdp_action_XDP_PASS,
    /// Results in TX bouncing the received packet back to the same NIC it
    /// arrived on. This is usually combined with modifying the packet contents
    /// before returning.
    Tx = xdp_action_XDP_TX,
    /// Similar to `Tx`, but through another NIC.
    Redirect = xdp_action_XDP_REDIRECT,
}

/// The packet transport header.
///
/// Currently only `TCP` and `UDP` transports are supported.
pub enum Transport {
    TCP(*const tcphdr),
    UDP(*const udphdr),
}

impl Transport {
    /// Returns the source port.
    #[inline]
    pub fn source(&self) -> u16 {
        let source = match *self {
            Transport::TCP(hdr) => unsafe { (*hdr).source },
            Transport::UDP(hdr) => unsafe { (*hdr).source },
        };
        u16::from_be(source)
    }

    /// Returns the destination port.
    #[inline]
    pub fn dest(&self) -> u16 {
        let dest = match *self {
            Transport::TCP(hdr) => unsafe { (*hdr).dest },
            Transport::UDP(hdr) => unsafe { (*hdr).dest },
        };
        u16::from_be(dest)
    }
}

/// Context object provided to XDP programs.
///
/// XDP programs are passed a `XdpContext` instance as their argument. Through
/// the context, programs can inspect and modify the packet.
#[derive(Clone)]
pub struct XdpContext {
    pub ctx: *mut xdp_md,
}

impl XdpContext {
    /// Returns the raw `xdp_md` context.
    #[inline]
    pub fn inner(&self) -> *mut xdp_md {
        self.ctx
    }

    #[inline]
    unsafe fn ptr_at<U>(&self, addr: usize) -> Option<*const U> {
        if !self.check_bounds(addr, addr + mem::size_of::<U>()) {
            return None;
        }

        Some(addr as *const U)
    }

    #[inline]
    unsafe fn ptr_after<T, U>(&self, prev: *const T) -> Option<*const U> {
        self.ptr_at(prev as usize + mem::size_of::<T>())
    }

    #[inline]
    fn check_bounds(&self, start: usize, end: usize) -> bool {
        let ctx = unsafe { *self.ctx };
        if start >= end {
            return false;
        }

        if start < ctx.data as usize {
            return false;
        }

        if end > ctx.data_end as usize {
            return false;
        }

        return true;
    }

    /// Returns the packet length.
    #[inline]
    pub fn len(&self) -> u32 {
        unsafe {
            let ctx = *self.ctx;
            ctx.data_end - ctx.data
        }
    }

    /// Returns the packet's `Ethernet` header if present.
    #[inline]
    pub fn eth(&self) -> Option<*const ethhdr> {
        unsafe { self.ptr_at((*self.ctx).data as usize) }
    }

    /// Returns the packet's `IP` header if present.
    #[inline]
    pub fn ip(&self) -> Option<*const iphdr> {
        let eth = self.eth()?;
        unsafe {
            if (*eth).h_proto != u16::from_be(ETH_P_IP as u16) {
                return None;
            }

            self.ptr_after(eth)
        }
    }

    /// Returns the packet's transport header if present.
    #[inline]
    pub fn transport(&self) -> Option<Transport> {
        unsafe {
            let ip = self.ip()?;
            let addr = ip as usize + ((*ip).ihl() * 4) as usize;
            let transport = match (*ip).protocol as u32 {
                IPPROTO_TCP => (Transport::TCP(self.ptr_at(addr)?)),
                IPPROTO_UDP => (Transport::UDP(self.ptr_at(addr)?)),
                _ => return None,
            };

            Some(transport)
        }
    }

    /// Returns the packet's data starting after the transport headers.
    #[inline]
    pub fn data(&self) -> Option<Data> {
        use Transport::*;
        unsafe {
            let base: *const c_void = match self.transport()? {
                TCP(hdr) => {
                    let mut addr = hdr as usize + mem::size_of::<tcphdr>();
                    let data_offset = (*hdr).doff();
                    if data_offset > 5 {
                        addr += ((data_offset - 5) * 4) as usize;
                    }
                    self.ptr_at(addr)
                }
                UDP(hdr) => self.ptr_after(hdr),
            }?;

            Some(Data {
                ctx: self.clone(),
                base: base as usize,
            })
        }
    }
}

/// Data type returned by calling `XdpContext::data()`
pub struct Data {
    ctx: XdpContext,
    base: usize
}

impl Data {
    /// Returns the offset from the first byte of the packet.
    #[inline]
    pub fn offset(&self) -> usize {
        let ctx = unsafe { *self.ctx.inner() };
        unsafe { (self.base - ctx.data as usize) }
    }

    /// Returns the length of the data.
    ///
    /// This is equivalent to the length of the packet minus the length of the headers.
    #[inline]
    pub fn len(&self) -> usize {
        let ctx = unsafe { *self.ctx.inner() };
        unsafe { (ctx.data_end as usize - self.base) }
    }

    /// Returns a `slice` of `len` bytes from the data.
    #[inline]
    pub fn slice(&self, len: usize) -> Option<&[u8]> {
        unsafe {
            if !self.ctx.check_bounds(self.base, self.base + len) {
                return None;
            }
            let s = slice::from_raw_parts(self.base as *const u8, len);
            Some(s)
        }
    }

    #[inline]
    pub fn read<T: XdpArray>(&self) -> Option<T> {
        unsafe {
            let len = mem::size_of::<T>();
            if !self.ctx.check_bounds(self.base, self.base + len) {
                return None;
            }
            Some((self.base as *const T).read_unaligned())
        }
    }
}
/* NB: this needs to be kept in sync with redbpf::xdp::MapData */
/// Convenience data type to exchange payload data.
#[repr(C)]
pub struct MapData<T> {
    data: T,
    offset: u32,
    size: u32,
    payload: [u8; 0],
}

impl<T> MapData<T> {
    /// Create a new `MapData` value that includes only `data` and no packet
    /// payload.
    pub fn new(&self, data: T) -> Self {
        MapData::<T>::with_payload(data, 0, 0)
    }

    /// Create a new `MapData` value that includes `data` and `size` payload
    /// bytes, where the interesting part of the payload starts at `offset`.
    ///
    /// The payload can then be retrieved calling `MapData::payload()`.
    pub fn with_payload(data: T, offset: u32, size: u32) -> Self {
        Self {
            data,
            payload: [],
            offset,
            size,
        }
    }
}

/// Perf events map.
///
/// Similar to `PerfMap`, with additional XDP-only API.
#[repr(transparent)]
pub struct PerfMap<T>(PerfMapBase<MapData<T>>);

impl<T> PerfMap<T> {
    /// Creates a perf map with the specified maximum number of elements.
    pub const fn with_max_entries(max_entries: u32) -> Self {
        Self(PerfMapBase::with_max_entries(max_entries))
    }

    /// Insert a new event in the perf events array keyed by the current CPU number.
    ///
    /// Each array can hold up to `max_entries` events, see `with_max_entries`.
    /// If you want to use a key other than the current CPU, see
    /// `insert_with_flags`.
    ///
    /// `packet_size` specifies the number of bytes from the current packet that
    /// the kernel should append to the event data.
    #[inline]
    pub fn insert(&mut self, ctx: &XdpContext, data: MapData<T>) {
        let size = data.size;
        self.0
            .insert_with_flags(ctx.inner(), data, PerfMapFlags::with_xdp_size(size))
    }

    /// Insert a new event in the perf events array keyed by the index and with
    /// the additional xdp payload data specified in the given `PerfMapFlags`.
    #[inline]
    pub fn insert_with_flags(
        &mut self,
        ctx: &XdpContext,
        data: MapData<T>,
        mut flags: PerfMapFlags,
    ) {
        flags.xdp_size = data.size;
        self.0.insert_with_flags(ctx.inner(), data, flags)
    }
}
