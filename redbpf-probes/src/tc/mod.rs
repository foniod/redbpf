// Copyright 2021 Authors of redBPF
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
/*!
BPF for tc utility

tc supports attaching BPF programs to `clsact` qdisc as a direct action. You
can write BPF programs and BPF maps using `redBPF`.

# Example

```no_run
#![no_std]
#![no_main]

use redbpf_macros::map;
use redbpf_probes::tc::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[map(link_section = "maps")]
static mut blocked_packets: TcHashMap<u16, u64> =
    TcHashMap::<u16, u64>::with_max_entries(1024, TcMapPinning::GlobalNamespace);

#[tc_action]
fn block_ports(skb: SkBuff) -> TcActionResult {
    // do some stuff ...
    let port = 714;
    if let Some(count) = unsafe { blocked_packets.get(&port) } {
        *count += 1;
        Ok(TcAction::Shot)
    } else {
        Ok(TcAction::Ok)
    }
}
```
*/
use crate::socket::SocketError;

/// Possible actions in tc programs
///
/// Allowed return opcodes from BPF programs are listed at
/// <https://elixir.bootlin.com/linux/v5.13.2/source/net/sched/cls_bpf.c#L65>
#[repr(i32)]
pub enum TcAction {
    /// Use the default action configured from `tc`
    Unspec = -1,
    /// Terminate the packet processing pipeline and allows the packet to
    /// proceed
    Ok = 0,
    /// Terminate the packet processing pipeline and drops the packet
    Shot = 2,
    /// TC_ACT_SHOT will indicate to the kernel that the skb was released
    /// through kfree_skb() and return NET_XMIT_DROP to the callers for
    /// immediate feedback, whereas TC_ACT_STOLEN will release the skb through
    /// consume_skb() and pretend to upper layers that the transmission was
    /// successful through NET_XMIT_SUCCESS. The perf’s drop monitor which
    /// records traces of kfree_skb() will therefore also not see any drop
    /// indications from TC_ACT_STOLEN since its semantics are such that the
    /// skb has been “consumed” or queued but certainly not “dropped”.
    /// cf) <https://docs.cilium.io/en/latest/bpf/#tc-traffic-control>
    Stolen = 4,
    /// Allow to redirect the skb to the same or another’s device ingress or
    /// egress path together with the bpf_redirect() helper
    Redirect = 7,
    /// For hw path, this means "trap to cpu" and don't further process the
    /// frame in hardware. For sw path, this is equivalent of `Stolen` - drop
    /// the skb and act like everything is alright.
    Trap = 8,
}

/// Result type for tc action programs.
pub type TcActionResult = Result<TcAction, SocketError>;
pub mod maps;

pub mod prelude {
    pub use super::maps::*;
    pub use super::*;
    pub use crate::bindings::*;
    pub use crate::helpers::*;
    pub use crate::maps::*;
    pub use crate::socket::*;
    pub use redbpf_macros::{program, tc_action};
}
