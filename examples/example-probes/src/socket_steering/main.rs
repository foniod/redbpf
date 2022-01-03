#![no_std]
#![no_main]

use redbpf_probes::sk_lookup::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[map]
static mut steered_ports: HashMap<u16, u8> = HashMap::with_max_entries(1024);

#[map]
static mut destination_socket: SockMap = SockMap::with_max_entries(1);

#[sk_lookup]
pub fn steer_to_socket(ctx: SkLookupContext) -> SkAction {
    unsafe {
        if steered_ports.get(&ctx.local_port()).is_some()
            && destination_socket.assign(ctx.inner(), 0).is_err()
        {
            SkAction::Drop
        } else {
            SkAction::Pass
        }
    }
}
