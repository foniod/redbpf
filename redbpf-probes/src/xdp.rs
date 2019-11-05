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
use redbpf_macros::{probe, xdp};

probe!(0xFFFFFFFE, "GPL");

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
use core::ops::{Index, Range};
use core::slice;
use cty::*;

use crate::bindings::*;
use crate::maps::{PerfMap as PerfMapBase, PerfMapFlags};
use redbpf_macros::internal_helpers as helpers;

/// The return type of XDP probes.
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
pub struct XdpContext {
    ctx: *mut xdp_md,
}

impl XdpContext {
    /// Returns the raw `xdp_md` context.
    #[inline]
    pub fn inner(&self) -> *mut xdp_md {
        self.ctx
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
        let ctx = unsafe { *self.ctx };
        let eth = ctx.data as *const ethhdr;
        let end = ctx.data_end as *const c_void;
        unsafe {
            if eth.add(1) as *const c_void > end {
                return None;
            }
        }
        Some(eth)
    }

    /// Returns the packet's `IP` header if present.
    #[inline]
    pub fn ip(&self) -> Option<*const iphdr> {
        let eth = self.eth()?;
        unsafe {
            if (*eth).h_proto != u16::from_be(ETH_P_IP as u16) {
                return None;
            }

            let ip = eth.add(1) as *const iphdr;
            if ip.add(1) as *const c_void > (*self.ctx).data_end as *const c_void {
                return None;
            }
            Some(ip)
        }
    }

    /// Returns the packet's transport header if present.
    #[inline]
    pub fn transport(&self) -> Option<Transport> {
        let ip = self.ip()?;
        let base = unsafe { ip.add(1) as *const u8 };
        let (transport, size) = match unsafe { (*ip).protocol } as u32 {
            IPPROTO_TCP => (Transport::TCP(base.cast()), mem::size_of::<tcphdr>()),
            IPPROTO_UDP => (Transport::UDP(base.cast()), mem::size_of::<udphdr>()),
            _ => return None,
        };
        unsafe {
            if base.add(size) > (*self.ctx).data_end as *const u8 {
                return None;
            }
        }

        Some(transport)
    }

    /// Returns the packet's data starting after the transport headers.
    #[inline]
    pub fn data(&self) -> Option<Data> {
        use Transport::*;
        unsafe {
            let base = match self.transport()? {
                TCP(hdr) => hdr.add(1) as *mut u8,
                UDP(hdr) => hdr.add(1) as *mut u8,
            };
            Some(Data {
                ctx: self.ctx,
                base,
            })
        }
    }
}

/// Data type returned by calling `XdpContext::data()`
pub struct Data {
    ctx: *const xdp_md,
    base: *const u8,
}

impl Data {
    /// Returns the offset from the first byte of the packet.
    #[inline]
    pub fn offset(&self) -> usize {
        unsafe { (self.base as u32 - (*self.ctx).data) as usize }
    }

    /// Returns the length of the data.
    ///
    /// This is equivalent to the length of the packet minus the length of the headers.
    #[inline]
    pub fn len(&self) -> usize {
        unsafe { ((*self.ctx).data_end - self.base as u32) as usize }
    }

    /// Returns a `slice` of `len` bytes from the data.
    #[inline]
    pub fn slice(&self, len: usize) -> Option<&[u8]> {
        unsafe {
            if self.base.add(len) > (*self.ctx).data_end as *const u8 {
                return None;
            }
            Some(slice::from_raw_parts(self.base, len))
        }
    }
}

/// Perf events map.
///
/// Similar to `PerfMap`, with additional XDP-only API.
#[repr(transparent)]
pub struct PerfMap<T>(PerfMapBase<T>);

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
    #[helpers]
    pub fn insert(&mut self, ctx: &XdpContext, data: T, packet_size: u32) {
        self.0
            .insert_with_flags(ctx.inner(), data, PerfMapFlags::with_xdp_size(packet_size))
    }

    /// Insert a new event in the perf events array keyed by the index and with
    /// the additional xdp payload data specified in the given `PerfMapFlags`.
    #[inline]
    #[helpers]
    pub fn insert_with_flags(&mut self, ctx: &XdpContext, data: T, flags: PerfMapFlags) {
        self.0.insert_with_flags(ctx.inner(), data, flags)
    }
}
