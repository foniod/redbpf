use crate::bindings::*;
use core::mem;
use core::slice;
use cty::*;
use redbpf_macros::impl_network_buffer_array;

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

pub trait NetworkBuffer
where
    Self: Clone + Sized,
{
    fn data_start(&self) -> usize;
    fn data_end(&self) -> usize;

    /// Returns the packet length.
    #[inline]
    fn len(&self) -> usize {
        self.data_end() - self.data_start()
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
        if start >= end {
            return false;
        }

        if start < self.data_start() as usize {
            return false;
        }

        if end > self.data_end() as usize {
            return false;
        }

        return true;
    }

    /// Returns the packet's `Ethernet` header if present.
    #[inline]
    fn eth(&self) -> Option<*const ethhdr> {
        unsafe { self.ptr_at(self.data_start() as usize) }
    }

    /// Returns the packet's `IP` header if present.
    #[inline]
    fn ip(&self) -> Option<*const iphdr> {
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
    fn transport(&self) -> Option<Transport> {
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
    fn data(&self) -> Option<Data<Self>> {
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

            let ctx: Self = self.clone();
            Some(Data {
                ctx,
                base: base as usize,
            })
        }
    }
}

/// Data type returned by calling `NetworkBuffer::data()`
pub struct Data<T: NetworkBuffer> {
    ctx: T,
    base: usize,
}

impl<T: NetworkBuffer> Data<T> {
    /// Returns the offset from the first byte of the packet.
    #[inline]
    pub fn offset(&self) -> usize {
        self.base - self.ctx.data_start()
    }

    /// Returns the length of the data.
    ///
    /// This is equivalent to the length of the packet minus the length of the headers.
    #[inline]
    pub fn len(&self) -> usize {
        self.ctx.data_end() - self.base
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
    pub fn read<U: NetworkBufferArray>(&self) -> Option<U> {
        unsafe {
            let len = mem::size_of::<U>();
            if !self.ctx.check_bounds(self.base, self.base + len) {
                return None;
            }
            Some((self.base as *const U).read_unaligned())
        }
    }
}

pub trait NetworkBufferArray {}
impl_network_buffer_array!();
