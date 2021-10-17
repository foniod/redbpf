#![no_std]
#![no_main]
use core::mem;
use redbpf_probes::bpf_iter::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[task_iter]
unsafe fn dump_tgid(ctx: TaskIterContext) -> BPFIterAction {
    let ctx_ptr = ctx.ctx;
    let meta_ptr = (*ctx_ptr).__bindgen_anon_1.meta;
    let seq_ptr = (*meta_ptr).__bindgen_anon_1.seq;
    let task_ptr = (*ctx_ptr).__bindgen_anon_2.task;
    if task_ptr.is_null() {
        return BPFIterAction::Ok;
    }
    let tgid = (*task_ptr).tgid;
    bpf_seq_write(
        seq_ptr,
        &tgid as *const _ as *const _,
        mem::size_of_val(&tgid) as u32,
    );

    BPFIterAction::Ok
}
