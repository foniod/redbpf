// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/*!
Linux Socket Filtering API.

This module exposes the original Socket Filtering API. While still useful,
you can often use
[`XDP`](https://ingraind.org/api/redbpf_probes/xdp/index.html)
for faster performance and a nicer API.

# Example

In the following example, all TCP traffic is forwarded to userspace.

```
use core::mem;
use memoffset::offset_of;
use redbpf_probes::socket_filter::prelude::*;

#[socket_filter]
fn forward_tcp(skb: SkBuff) -> SkBuffResult {
    let eth_len = mem::size_of::<ethhdr>();
    let eth_proto: u16 = skb.load(offset_of!(ethhdr, h_proto))?;
    let ip_proto: u8 = skb.load(eth_len + offset_of!(iphdr, protocol))?;

    // only parse TCP
    if !(eth_proto as u32 == ETH_P_IP && ip_proto as u32 == IPPROTO_TCP) {
        return Ok(SkBuffAction::Ignore);
    }
    Ok(SkBuffAction::SendToUserspace)
}
```
*/
pub mod prelude;

use crate::bindings::*;
use crate::helpers::bpf_skb_load_bytes;
use core::mem;

pub trait FromBe {
    fn from_be(&self) -> Self;
}

macro_rules! impl_from_be {
    ($T:ident) => {
        impl FromBe for $T {
            fn from_be(&self) -> $T {
                $T::from_be(*self)
            }
        }
    };
}

impl_from_be!(u8);
impl_from_be!(u16);
impl_from_be!(u32);

/// The return type for successful socket filter programs.
pub enum SkBuffAction {
    /// Ignore the data in the buffer.
    Ignore,
    /// Send the data in the buffer to user space.
    ///
    /// The user space app that attached the socket filter will receive the data
    /// via `Socket::recv`.
    SendToUserspace,
}

/// The error type for socket filter programs.
pub enum SkBuffError {
    /// Loading data from the socket buffer failed.
    LoadFailed,
}

/// Result type for socket filter programs.
pub type SkBuffResult = Result<SkBuffAction, SkBuffError>;

/// Context object provided to Socket Filter programs.
///
/// Socket Filter programs are passed a `SkBuff` instance as their argument.
pub struct SkBuff {
    /// The low level skb instance.
    pub skb: *const __sk_buff,
}

impl SkBuff {
    #[inline]
    /// Loads data from the socket buffer.
    ///
    /// This is typically used to parse payloads before deciding whether to
    /// forward them to userspace or not.
    ///
    /// # Example
    /// ```
    /// use core::mem;
    /// use memoffset::offset_of;
    ///
    /// let eth_len = mem::size_of::<ethhdr>();
    /// let eth_proto: u16 = skb.load(offset_of!(ethhdr, h_proto))?;
    /// let ip_proto: u8 = skb.load(eth_len + offset_of!(iphdr, protocol))?;
    ///
    /// // only parse TCP
    /// if !(eth_proto as u32 == ETH_P_IP && ip_proto as u32 == IPPROTO_TCP) {
    ///     return Ok(SkBuffAction::Ignore);
    /// }
    /// Ok(SkBuffAction::SendToUserspace)
    /// ```
    pub fn load<T: FromBe>(&self, offset: usize) -> Result<T, SkBuffError> {
        unsafe {
            let mut data = mem::MaybeUninit::<T>::uninit();
            let ret = bpf_skb_load_bytes(
                self.skb as *const _,
                offset as u32,
                &mut data as *mut _ as *mut _,
                mem::size_of::<T>() as u32,
            );
            if ret < 0 {
                return Err(SkBuffError::LoadFailed);
            }

            Ok(data.assume_init().from_be())
        }
    }
}
