#![no_std]
#![no_main]
use example_probes::mallocstacks::MallocEvent;
use redbpf_probes::uprobe::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[map]
static mut stack_trace: StackTrace = StackTrace::with_max_entries(10240);

#[map]
static mut malloc_event: PerfMap<MallocEvent> = PerfMap::with_max_entries(1024);

#[uprobe]
fn malloc(regs: Registers) {
    let mut mev = MallocEvent {
        stackid: 0,
        size: regs.parm1(),
    };

    unsafe {
        if let Ok(stackid) = stack_trace.stack_id(regs.ctx, BPF_F_USER_STACK as _) {
            mev.stackid = stackid;
            malloc_event.insert(regs.ctx, &mev);
        }
    }
}
