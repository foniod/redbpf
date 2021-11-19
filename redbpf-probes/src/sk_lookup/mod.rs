// Copyright 2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Utilities to work with sk_lookup programs.

pub mod prelude;

use crate::xdp::prelude::bpf_sk_assign;
use crate::{bindings::*, socket::Socket};
use cty::*;

/// Context object provided to sk_lookup programs.
#[derive(Copy, Clone)]
pub struct SkLookupCtx {
    /// The low level bpf_sk_lookup instance.
    pub ctx: *mut bpf_sk_lookup,
}

/// An IP address, either IPv4 or IPv6.
#[derive(Copy, Clone)]
pub enum IpAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

/// IP protocol, either TCP or UDP.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum IpProtocol {
    TCP,
    UDP,
}

/// An IPv4 address.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Ipv4Addr(pub u32);

/// An IPv6 address.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Ipv6Addr(pub [u32; 4]);

/// Convenience functions wrapping the raw `struct bpf_sk_lookup`
impl SkLookupCtx {
    /// Get the protocol of the incoming connection.
    #[inline]
    pub fn protocol(&self) -> IpProtocol {
        match unsafe { (*self.ctx).protocol } {
            IPPROTO_TCP => IpProtocol::TCP,
            _ => IpProtocol::UDP,
        }
    }

    /// Get the local address of the incoming connection.
    #[inline]
    pub fn local_addr(&self) -> IpAddr {
        match unsafe { (*self.ctx).family } {
            AF_INET => IpAddr::V4(Ipv4Addr(unsafe { (*self.ctx).local_ip4 })),
            _ => IpAddr::V6(Ipv6Addr(unsafe { (*self.ctx).local_ip6 })),
        }
    }

    /// Get the local port of the incoming connection.
    #[inline]
    pub fn local_port(&self) -> u32 {
        unsafe { (*self.ctx).local_port }
    }

    /// Get the remote address of the incoming connection.
    #[inline]
    pub fn remote_addr(&self) -> IpAddr {
        match unsafe { (*self.ctx).family } {
            AF_INET => IpAddr::V4(Ipv4Addr(unsafe { (*self.ctx).remote_ip4 })),
            AF_INET6 => IpAddr::V6(Ipv6Addr(unsafe { (*self.ctx).remote_ip6 })),
            _ => unreachable!(),
        }
    }

    /// Get the remote port of the incoming connection.
    #[inline]
    pub fn remote_port(&self) -> u32 {
        unsafe { (*self.ctx).remote_port }
    }

    /// Assigns this connection to the specified socket.
    #[inline]
    pub fn assign(&self, socket: &mut Socket) -> Result<(), i64> {
        let ret = unsafe { bpf_sk_assign(self.ctx as *mut c_void, socket.inner, 0) };
        if ret >= 0 {
            Ok(())
        } else {
            Err(ret)
        }
    }
}
