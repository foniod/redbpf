#![no_std]
#![no_main]
use example_probes::vfsreadlat::VFSEvent;
use redbpf_probes::kprobe::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[map(link_section = "maps/timestamp")]
static mut TIMESTAMP: HashMap<u64, VFSEvent> = HashMap::with_max_entries(10240);

#[map(link_section = "maps/pid")]
static mut PID: PerfMap<VFSEvent> = PerfMap::with_max_entries(10240);

#[kprobe("vfs_read")]
fn vfs_read_enter(_regs: Registers) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid & 0xFFFFFFFF; // task->pid
    let tgid = pid_tgid >> 32; // task->tgid

    let event = VFSEvent {
        pid,
        tgid,
        timestamp: bpf_ktime_get_ns(),
        latency: 0,
    };
    unsafe {
        TIMESTAMP.set(&tgid, &event);
    };
}

#[kretprobe("vfs_read")]
fn vfs_read_exit(regs: Registers) {
    let tgid = bpf_get_current_pid_tgid() >> 32;
    unsafe {
        match TIMESTAMP.get_mut(&tgid) {
            Some(event) => {
                TIMESTAMP.delete(&tgid);
                event.latency = bpf_ktime_get_ns() - event.timestamp;
                PID.insert(regs.ctx, &event);
            }
            None => {}
        }
    };
}
