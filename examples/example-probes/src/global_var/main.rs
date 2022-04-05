#![no_std]
#![no_main]
use core::sync::atomic::Ordering;

use redbpf_probes::kprobe::prelude::*;

use example_probes::global_var::{GLOBAL_VAR, GLOBAL_VAR_INCORRECT};

program!(0xFFFFFFFE, "GPL");

#[map]
static mut PERCPU_MAP: PerCpuArray<u64> = PerCpuArray::with_max_entries(1);

#[kprobe]
fn incr_write_count(_regs: Registers) {
    unsafe {
        GLOBAL_VAR.fetch_add(1, Ordering::Relaxed);
    }

    unsafe {
        GLOBAL_VAR_INCORRECT += 1;
    }

    unsafe {
        let val = PERCPU_MAP.get_mut(0).unwrap();
        *val += 1;
    }
}
