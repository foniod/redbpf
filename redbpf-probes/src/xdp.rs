use core::mem;
use core::slice;
use cty::*;

pub use crate::bindings::*;

#[repr(u32)]
pub enum XdpAction {
    Aborted = xdp_action_XDP_ABORTED,
    Drop = xdp_action_XDP_DROP,
    Pass = xdp_action_XDP_PASS,
    Tx = xdp_action_XDP_TX,
    Redirect = xdp_action_XDP_REDIRECT
}

pub enum Transport {
    TCP(*const tcphdr),
    UDP(*const udphdr)
}

impl Transport {
    #[inline]
    pub fn source(&self) -> u16 {
        let source = match *self {
            Transport::TCP(hdr) => unsafe { (*hdr).source },
            Transport::UDP(hdr) => unsafe { (*hdr).source }
        };
        u16::from_be(source)
    }

    #[inline]
    pub fn dest(&self) -> u16 {
        let dest = match *self {
            Transport::TCP(hdr) => unsafe { (*hdr).dest },
            Transport::UDP(hdr) => unsafe { (*hdr).dest }
        };
        u16::from_be(dest)
    }
}

impl xdp_md {
    #[inline]
    pub fn ip(&self) -> Option<*const iphdr> {
        let eth = self.data as *const ethhdr;
        let end = self.data_end as *const c_void;
        let next = unsafe { eth.add(1) as *const c_void };
        if next > end {
            return None;
        }
        if unsafe { (*eth).h_proto } != u16::from_be(ETH_P_IP as u16) {
            return None;
        }
        let ip = next as *const iphdr;
        let next = unsafe { ip.add(1) as *const c_void };
        if next > end {
            return None;
        }

        Some(ip)
    }

    #[inline]
    pub fn transport(&self) -> Option<Transport> {
        let ip = self.ip()?;
        let base = unsafe { ip.add(1) as *const u8 };
        let (transport, size) = match unsafe { (*ip).protocol } as u32 {
            IPPROTO_TCP => (Transport::TCP(base.cast()), mem::size_of::<tcphdr>()),
            IPPROTO_UDP => (Transport::UDP(base.cast()), mem::size_of::<udphdr>()),
            _ => return None
        };
        unsafe {
            if base.add(size) > self.data_end as *const u8 {
                return None;
            }
        }

        Some(transport)
    }
}