#![no_std]
#![no_main]
/// This example program shows how to redirect packet using sockmap.
use core::mem;
use core::ptr;
use memoffset::offset_of;
use redbpf_probes::sockmap::prelude::*;

use example_probes::echo::IdxMapKey;

program!(0xFFFFFFFE, "GPL");

#[map(link_section = "maps/echo_sockmap")]
static mut ECHO_SOCKMAP: SockMap = SockMap::with_max_entries(10240);

#[map(link_section = "maps/idx_map")]
static mut IDX_MAP: HashMap<IdxMapKey, u32> = HashMap::with_max_entries(1024);

#[stream_parser]
unsafe fn parse_message_boundary(skb: SkBuff) -> StreamParserResult {
    let len = (*skb.skb).len;
    printk!("message length: %u", len);
    Ok(StreamParserAction::MessageLength(len))
}

#[stream_verdict]
unsafe fn verdict(skb: SkBuff) -> SkAction {
    let ip = (*skb.skb).remote_ip4;
    let port = (*skb.skb).remote_port;

    printk!("ip: %x", u32::from_be(ip));
    printk!("port: %u", u32::from_be(port));

    let idx = if let Some(index) = IDX_MAP.get(&IdxMapKey { addr: ip, port }) {
        *index
    } else {
        printk!("drop packet since addr not found in idx map");
        return SkAction::Drop;
    };

    match ECHO_SOCKMAP.redirect(skb.skb as *mut _, idx) {
        Ok(_) => {
            printk!("redirect success");
            SkAction::Pass
        }
        Err(_) => {
            printk!("drop packet since redirect failed");
            SkAction::Drop
        }
    }
}
