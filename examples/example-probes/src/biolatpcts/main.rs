// This is a remake of examples/tracing/biolatpcts.py of bcc using RedBPF. The
// purpose of this code is to show how to use percpu array and how to write
// kprobe program. This source code implements a half part, a BPF
// program running inside kernel. The other part of userspace is implemented at
// `example-userspace/examples/biolatpcts.rs`

#![no_std]
#![no_main]
use core::cmp;

use redbpf_probes::kprobe::prelude::*;

// You can use types and variables defined in Linux kernel headers. In order to
// use kernel data types, you may include specific header into
// `example-probes/include/bindings.h` and add some stuff to
// `example-probes/build.rs` first. Please take a look at those files.
use example_probes::bindings::{request, NSEC_PER_MSEC, NSEC_PER_USEC};

program!(0xFFFFFFFE, "GPL");

#[map(link_section = "maps/lat_100ms")]
static mut LAT_100MS: PerCpuArray<u64> = PerCpuArray::with_max_entries(100);

#[map(link_section = "maps/lat_1ms")]
static mut LAT_1MS: PerCpuArray<u64> = PerCpuArray::with_max_entries(100);

#[map(link_section = "maps/lat_10us")]
static mut LAT_10US: PerCpuArray<u64> = PerCpuArray::with_max_entries(100);

#[kprobe("blk_account_io_done")]
fn blk_account_io_done(regs: Registers) {
    let rq: &request = unsafe { (regs.parm1() as *const request).as_ref().unwrap() };

    let stime = rq.io_start_time_ns().unwrap();
    if stime == 0 {
        return;
    }
    let now = regs.parm2();
    let dur = now - stime;
    let slot = cmp::min(dur / (100 * NSEC_PER_MSEC) as u64, 99);
    unsafe {
        match LAT_100MS.get_mut(slot as u32) {
            Some(val) => *val += 1,
            _ => (),
        }
    }
    if slot > 0 {
        return;
    }

    let slot = cmp::min(dur / NSEC_PER_MSEC as u64, 99);
    unsafe {
        match LAT_1MS.get_mut(slot as u32) {
            Some(val) => *val += 1,
            _ => (),
        }
    }
    if slot > 0 {
        return;
    }

    let slot = cmp::min(dur / (10 * NSEC_PER_USEC) as u64, 99);
    unsafe {
        match LAT_10US.get_mut(slot as u32) {
            Some(val) => *val += 1,
            _ => (),
        }
    }
}
