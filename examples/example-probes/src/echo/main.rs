#![no_std]
#![no_main]
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
fn parse_message_boundary(skb: SkBuff) -> StreamParserResult {
    let len: u32 = unsafe {
        let addr = (skb.skb as usize + offset_of!(__sk_buff, len)) as *const u32;
        ptr::read(addr)
    };
    printk!("length: %u", len);
    Ok(StreamParserAction::MessageLength(len))
}

#[stream_verdict]
fn verdict(skb: SkBuff) -> SkAction {
    let (ip, port) = unsafe {
        let ip_addr = (skb.skb as usize + offset_of!(__sk_buff, remote_ip4)) as *const u32;
        let port_addr = (skb.skb as usize + offset_of!(__sk_buff, remote_port)) as *const u32;
        (ptr::read(ip_addr), ptr::read(port_addr))
    };

    printk!("ip: %x", u32::from_be(ip));
    printk!("port: %u", u32::from_be(port));

    let mut idx = 0;
    match unsafe {
        let key = IdxMapKey { addr: ip, port };
        IDX_MAP.get(&key)
    } {
        None => return SkAction::Drop,
        Some(index) => idx = *index,
    }

    match unsafe { ECHO_SOCKMAP.redirect(skb.skb as *mut _, idx) } {
        Ok(_) => SkAction::Pass,
        Err(_) => SkAction::Drop,
    }
}
