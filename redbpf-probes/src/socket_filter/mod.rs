// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/*!
Linux Socket Filtering API.

This module exposes the original Socket Filtering API. While still useful, you
can often use [`XDP`](../../api/redbpf_probes/xdp/index.html) for faster
performance and a nicer API.

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

use crate::socket::SocketError;

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

pub use crate::tc::prelude::SkBuff;
/// Result type for socket filter programs.
pub type SkBuffResult = Result<SkBuffAction, SocketError>;
