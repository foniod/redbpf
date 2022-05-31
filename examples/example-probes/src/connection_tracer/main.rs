//! This example demonstrates how to use a tracepoint to trace the connect() system call
//!
//! See also the definition of the structs in `mod.rs`
#![no_std]
#![no_main]

use core::mem::size_of;
use example_probes::connection_tracer::SysEnterConnectArgs;
use redbpf_probes::tracepoint::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[tracepoint]
unsafe fn sys_enter_connect(args: *const SysEnterConnectArgs) {
    let args = bpf_probe_read(args).expect("Failed to read arguments");
    let addrlen = args.addrlen;
    if addrlen < size_of::<sockaddr_in>() as u64 {
        return;
    }

    let addr = args.useraddr;
    let family = bpf_probe_read(addr as *const sa_family_t).unwrap_or(u16::MAX) as u32;
    match family {
        AF_INET => {
            let sockaddr_struct = bpf_probe_read(addr as *const sockaddr_in).unwrap();
            let ipv4 = &(sockaddr_struct.sin_addr.s_addr as u64) as *const u64;
            bpf_trace_printk_raw(b"Connected to IPv4 address %pI4\0", ipv4 as u64, 0, 0)
                .expect("printk failed");
        }
        _ => {}
    };
}
