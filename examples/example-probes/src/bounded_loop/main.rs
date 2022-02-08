#![no_std]
#![no_main]
use redbpf_probes::kprobe::prelude::*;
program!(0xFFFFFFFE, "GPL");

#[map]
static mut ARRAY: Array<u64> = Array::with_max_entries(1000);

#[kprobe]
pub fn prog(_: Registers) {
    unsafe {
        let sum = ARRAY.get_mut(0).unwrap();
        // This is bounded loop. If `cargo bpf build` command is executed
        // without --force-loop-unroll flag, this loop is intact.
        for idx in 1..1000 {
            let val = ARRAY.get(idx).unwrap();
            *sum += val;
        }
    }
}
