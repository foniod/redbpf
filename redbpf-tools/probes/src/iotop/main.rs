#![no_std]
#![no_main]
use probes::bindings::request;
use probes::iotop::{Counter, CounterKey, Process};
use redbpf_probes::kprobe::prelude::*;

const REQ_OP_WRITE: u32 = 1;

program!(0xFFFFFFFE, "GPL");

#[map]
static mut start: HashMap<*const request, u64> = HashMap::with_max_entries(10240);

#[map]
static mut processes: HashMap<*const request, Process> = HashMap::with_max_entries(10240);

#[map]
static mut counts: HashMap<CounterKey, Counter> = HashMap::with_max_entries(10240);

#[kprobe]
fn blk_account_io_start(regs: Registers) {
    let comm = bpf_get_current_comm();
    let pid = bpf_get_current_pid_tgid() >> 32;
    let req = regs.parm1() as *const request;
    unsafe { processes.set(&req, &Process { pid, comm }) }
}

fn start_request(regs: Registers) {
    let ts = bpf_ktime_get_ns();
    let req = regs.parm1() as *const request;
    unsafe { start.set(&req, &ts) }
}

#[kprobe]
fn blk_mq_start_request(regs: Registers) {
    start_request(regs)
}

#[kprobe]
fn blk_account_io_done(regs: Registers) {
    let _ = do_complete(regs);
}

#[inline]
fn do_complete(regs: Registers) -> Option<()> {
    let req = regs.parm1() as *const request;

    let start_ts = unsafe { start.get(&req)? };
    let delta_us = (bpf_ktime_get_ns() - start_ts) / 1000u64;

    let request = unsafe { &*req };
    let rq_disk = unsafe { &*request.rq_disk()? };
    let major = rq_disk.major()?;
    let minor = rq_disk.first_minor()?;
    let write = (request.cmd_flags()? & REQ_OP_WRITE != 0) as u64;

    let unknown_process = Process {
        pid: 0,
        comm: [0; 16],
    };
    let process = match unsafe { processes.get(&req) } {
        Some(p) => p,
        None => &unknown_process,
    };
    let key = CounterKey {
        process: process.clone(),
        major,
        minor,
        write,
    };

    let mut counter = unsafe {
        match counts.get_mut(&key) {
            Some(c) => c,
            None => {
                let zero = Counter {
                    bytes: 0,
                    us: 0,
                    io: 0,
                };
                counts.set(&key, &zero);
                counts.get_mut(&key)?
            }
        }
    };

    counter.bytes += request.__data_len()? as u64;
    counter.us += delta_us;
    counter.io += 1;

    unsafe {
        start.delete(&req);
        processes.delete(&req);
    }

    None
}
