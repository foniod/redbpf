// This example is a remake of examples/tracing/biolatpcts.py of bcc using
// RedBPF. The purpose of this program is to show how to use kprobe and percpu
// array in userspace. This source code deals with userspace part only. You can
// find another half, a BPF program, at example-probes/biolatpcts/main.rs
use std::cmp;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, Level};
use tracing_subscriber::FmtSubscriber;

use redbpf::load::Loader;
use redbpf::PerCpuArray;

fn find_pct(req: f32, total: u64, slots: &[u64], mut idx: usize, mut counted: u64) -> (usize, u64) {
    while idx > 0 {
        idx -= 1;
        if slots[idx] > 0 {
            counted += slots[idx];
            if counted as f32 / total as f32 * 100.0 >= 100.0 - req {
                break;
            }
        }
    }
    (idx, counted)
}

fn calc_lat_pct(
    req_pcts: &[u64],
    total: u64,
    lat_100ms: &[u64],
    lat_1ms: &[u64],
    lat_10us: &[u64],
) -> Box<[u64]> {
    let mut pcts = vec![0u64; req_pcts.len()].into_boxed_slice();

    if total == 0 {
        return pcts;
    }

    let data = [(100_000, lat_100ms), (1000, lat_1ms), (10, lat_10us)];
    let mut data_sel = 0;
    let mut idx = 100;
    let mut counted = 0;

    for pct_idx in (0..req_pcts.len()).rev() {
        let req = req_pcts[pct_idx] as f32;
        let mut gran;
        loop {
            let last_counted = counted;
            gran = data[data_sel].0;
            let slots = data[data_sel].1;
            let pct = find_pct(req, total, &slots, idx, counted);
            idx = pct.0;
            counted = pct.1;
            if idx > 0 || data_sel == data.len() - 1 {
                break;
            }
            counted = last_counted;
            data_sel += 1;
            idx = 100;
        }

        pcts[pct_idx] = gran * idx as u64 + gran / 2;
    }

    return pcts;
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ! {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    if unsafe { libc::geteuid() != 0 } {
        error!("You must be root to use eBPF!");
        std::process::exit(1);
    }

    let mut loaded = Loader::load(include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/biolatpcts/biolatpcts.elf"
    )))
    .expect("error loading BPF program");

    for kp in loaded.kprobes_mut() {
        kp.attach_kprobe(&kp.name(), 0).expect(&format!(
            "error attaching kprobe BPF program to kernel function {}",
            kp.name()
        ));
    }
    let cur_lat_100ms =
        PerCpuArray::<u64>::new(loaded.map("lat_100ms").expect("array lat_100ms not found"))
            .expect("error creating PerCpuArray in userspace");
    let cur_lat_1ms =
        PerCpuArray::<u64>::new(loaded.map("lat_1ms").expect("array lat_1ms not found"))
            .expect("error creating PerCpuArray in userspace");
    let cur_lat_10us =
        PerCpuArray::<u64>::new(loaded.map("lat_10us").expect("array lat_10us not found"))
            .expect("error creating PerCpuArray in userspace");

    let mut last_lat_100ms = [0; 100];
    let mut last_lat_1ms = [0; 100];
    let mut last_lat_10us = [0; 100];

    let mut lat_100ms = [0; 100];
    let mut lat_1ms = [0; 100];
    let mut lat_10us = [0; 100];

    loop {
        sleep(Duration::from_secs(3)).await;

        let mut lat_total = 0;

        for i in 0usize..100 {
            let v: u64 = cur_lat_100ms.get(i as u32).unwrap().iter().sum();
            lat_100ms[i] = cmp::max(v - last_lat_100ms[i], 0);
            last_lat_100ms[i] = v;

            let v: u64 = cur_lat_1ms.get(i as u32).unwrap().iter().sum();
            lat_1ms[i] = cmp::max(v - last_lat_1ms[i], 0);
            last_lat_1ms[i] = v;

            let v: u64 = cur_lat_10us.get(i as u32).unwrap().iter().sum();
            lat_10us[i] = cmp::max(v - last_lat_10us[i], 0);
            last_lat_10us[i] = v;

            lat_total += lat_100ms[i];
        }

        let target_pcts = [50, 75, 90, 99];
        let pcts = calc_lat_pct(&target_pcts, lat_total, &lat_100ms, &lat_1ms, &lat_10us);

        for i in 0..target_pcts.len() {
            print!("p{}={}us ", target_pcts[i], pcts[i]);
        }
        println!();
    }
}
