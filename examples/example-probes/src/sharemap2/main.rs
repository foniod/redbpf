#![no_std]
#![no_main]
use redbpf_probes::kprobe::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[map(link_section = "maps/sharedmap")]
static mut SOME_COUNT: Array<u64> = Array::with_max_entries(1);

#[kprobe]
fn sys_exit(_: Registers) {
    unsafe {
        let cnt = SOME_COUNT.get_mut(0).unwrap();
        if cnt > &mut 1000 {
            *cnt = 0;
        }
    }
}
