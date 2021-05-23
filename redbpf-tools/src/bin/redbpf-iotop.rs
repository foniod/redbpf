// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use redbpf::{load::Loader, HashMap as BPFHashMap};
use std::collections::HashMap;
use std::ffi::CStr;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::os::raw::c_char;
use std::process;
use std::time::Duration;
use tokio;
use tokio::runtime;
use tokio::signal;
use tokio::time::sleep;

use probes::iotop::{Counter, CounterKey};

fn main() {
    if unsafe { libc::geteuid() } != 0 {
        println!("redbpf-iotop: You must be root to use eBPF!");
        process::exit(-1);
    }

    let rt = runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _ = rt.block_on(async {
        // load the BPF programs and maps
        let mut loader = Loader::load(probe_code()).expect("error loading probe");

        // attach the kprobes
        for kprobe in loader.kprobes_mut() {
            kprobe
                .attach_kprobe(&kprobe.name(), 0)
                .expect(&format!("error attaching program {}", kprobe.name()));
        }

        tokio::spawn(async move {
            let counts =
                BPFHashMap::<CounterKey, Counter>::new(loader.map("counts").unwrap()).unwrap();
            let disks = parse_diskstats().unwrap();

            loop {
                sleep(Duration::from_millis(1000)).await;

                println!(
                    "{:6} {:16} {:1} {:3} {:3} {:8} {:>5} {:>7} {:>6}",
                    "PID", "COMM", "D", "MAJ", "MIN", "DISK", "I/O", "Kbytes", "AVGms"
                );

                let mut items: Vec<(CounterKey, Counter)> = counts.iter().collect();
                items.sort_unstable_by(|(_, av), (_, bv)| av.bytes.cmp(&bv.bytes));

                for (k, v) in items.iter().rev() {
                    let comm = unsafe { CStr::from_ptr(k.process.comm.as_ptr() as *const c_char) }
                        .to_string_lossy()
                        .into_owned();

                    let unknown = String::from("?");
                    let disk_name = disks.get(&(k.major, k.minor)).unwrap_or(&unknown);
                    let avg_ms = v.us as f64 / 1000f64 / v.io as f64;

                    println!(
                        "{:<6} {:16} {:1} {:3} {:3} {:8} {:5} {:7} {:6.2}",
                        k.process.pid,
                        comm,
                        if k.write != 0 { "W" } else { "R" },
                        k.major,
                        k.minor,
                        disk_name,
                        v.io,
                        v.bytes / 1024,
                        avg_ms
                    );
                }

                println!("");
            }
        });

        signal::ctrl_c().await
    });
}

fn parse_diskstats() -> io::Result<HashMap<(i32, i32), String>> {
    let file = File::open("/proc/diskstats")?;
    let reader = BufReader::new(file);
    let mut disks = HashMap::new();
    for line in reader.lines() {
        let line = line.unwrap();
        let parts: Vec<_> = line.split_ascii_whitespace().collect();
        disks.insert(
            (parts[0].parse().unwrap(), parts[1].parse().unwrap()),
            parts[2].to_string(),
        );
    }
    Ok(disks)
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/iotop/iotop.elf"
    ))
}
