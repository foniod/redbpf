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
    trace_print(b"length: ", len);
    Ok(StreamParserAction::MessageLength(len))
}

#[stream_verdict]
fn verdict(skb: SkBuff) -> SkAction {
    let (ip, port) = unsafe {
        let ip_addr = (skb.skb as usize + offset_of!(__sk_buff, remote_ip4)) as *const u32;
        let port_addr = (skb.skb as usize + offset_of!(__sk_buff, remote_port)) as *const u32;
        (ptr::read(ip_addr), ptr::read(port_addr))
    };

    trace_print(b"ip as BE: ", ip);
    trace_print(b"port as BE: ", port);

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

fn hex_u8(v: u8, buf: &mut [u8]) {
    let w = v / 0x10;
    buf[0] = if w < 0xa { w + b'0' } else { w - 0xa + b'a' };
    let u = v % 0x10;
    buf[1] = if u < 0xa { u + b'0' } else { u - 0xa + b'a' };
}

fn hex_bytes(arr: &[u8], buf: &mut [u8]) -> usize {
    let mut pos = 0;
    for (i, b) in arr.iter().enumerate() {
        if i != 0 {
            buf[pos] = b' ';
            pos += 1;
        }
        hex_u8(*b, &mut buf[pos..pos + 2]);
        pos += 2;
    }
    pos
}

fn trace_print<T>(msg: &[u8], x: T) {
    let mut buf = [0u8; 128];
    let mut pos = 0;
    for c in msg {
        buf[pos] = *c;
        pos += 1;
    }

    let ptr = &x as *const T as *const usize as usize;
    let sz = mem::size_of::<T>();
    let mut arr = [0u8; 64];
    for i in 0..sz {
        arr[i] = unsafe { ptr::read((ptr + i) as *const usize as *const u8) };
    }

    pos += hex_bytes(&arr[..sz], &mut buf[pos..]);
    buf[pos] = b'\n';
    pos += 2;

    bpf_trace_printk(&buf[..pos]);
}
