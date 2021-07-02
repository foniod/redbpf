#![no_std]
#![no_main]
use redbpf_probes::kprobe::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[map(link_section = "maps/sharedmap")]
static mut CLONE_COUNT: Array<u64> = Array::with_max_entries(1);

#[kprobe]
fn sys_clone(_: Registers) {
    unsafe {
        *CLONE_COUNT.get_mut(0).unwrap() += 1;
    }
}
