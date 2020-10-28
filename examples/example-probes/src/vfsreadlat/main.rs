#![no_std]
#![no_main]
use example_probes::vfsreadlat::VFSEvent;
use redbpf_probes::kprobe::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[map("timestamp")]
static mut timestamp: HashMap<u64, VFSEvent> = HashMap::with_max_entries(10240);

#[map("pid")]
static mut pid: PerfMap<VFSEvent> = PerfMap::with_max_entries(10240);

#[kprobe("vfs_read")]
fn vfs_read_enter(_regs: Registers) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let p = pid_tgid >> 32;
    let t = pid_tgid & 0xFFFFFFFF;

    let event = VFSEvent {
        pid: p,
        tgid: t,
        timestamp: bpf_ktime_get_ns(),
        latency: 0,
    };
    unsafe {
        timestamp.set(&t, &event);
    };
}

#[kretprobe("vfs_read")]
fn vfs_read_exit(regs: Registers) {
    let t = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    unsafe {
        match timestamp.get_mut(&t) {
            Some(event) => {
                timestamp.delete(&t);
                event.latency = bpf_ktime_get_ns() - event.timestamp;
                pid.insert(regs.ctx, &event);
            }
            None => {}
        }
    };
}
