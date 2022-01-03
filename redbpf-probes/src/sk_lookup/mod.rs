pub mod prelude;

use crate::bindings::*;

#[derive(Clone)]
pub struct SkLookupContext {
    pub ctx: *mut bpf_sk_lookup,
}

impl SkLookupContext {
    /// Returns the raw `bpf_sk_lookup` context passed by the kernel.
    #[inline]
    pub fn inner(&self) -> *mut bpf_sk_lookup {
        self.ctx
    }

    pub fn family(&self) -> u32 {
        unsafe { (*self.ctx).family }
    }

    pub fn protocol(&self) -> u32 {
        unsafe { (*self.ctx).protocol }
    }

    pub fn remote_ip4(&self) -> u32 {
        unsafe { (*self.ctx).remote_ip4 }
    }

    pub fn remote_ip6(&self) -> [u32; 4] {
        unsafe { (*self.ctx).remote_ip6 }
    }

    pub fn remote_port(&self) -> u16 {
        // ctx.remote_port is u32, however highest port number is currently 2^16 - 1
        // useful to return as u16 to reduce memory reqs of large hash maps of ports
        unsafe { (*self.ctx).remote_port as u16 }
    }

    pub fn local_ip4(&self) -> u32 {
        unsafe { (*self.ctx).local_ip4 }
    }

    pub fn local_ip6(&self) -> [u32; 4] {
        unsafe { (*self.ctx).local_ip6 }
    }

    pub fn local_port(&self) -> u16 {
        // ctx.local_port is u32, however highest port number is currently 2^16 - 1
        // useful to return as u16 to reduce memory reqs of large hash maps of ports
        unsafe { (*self.ctx).local_port as u16 }
    }
}
