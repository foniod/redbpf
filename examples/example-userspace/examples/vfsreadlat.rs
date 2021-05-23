use futures::stream::StreamExt;
use probes::vfsreadlat::VFSEvent;
use redbpf::load::{Loaded, Loader};
use std::collections::HashMap;
use std::env;
use std::process;
use std::ptr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio;
use tokio::runtime;
use tokio::signal;
use tokio::time::sleep;
use tracing::{error, Level};
use tracing_subscriber::FmtSubscriber;

const UNDER_ONE: &str = "~ 0";
const ONE_TO_TEN: &str = "1 ~ 10";
const TEN_TO_HUNDRED: &str = "10 ~ 100";
const OVER_HUNDRED: &str = "100 ~";

type Counts = Arc<Mutex<HashMap<&'static str, u64>>>;

fn start_reporter(counts: Counts) {
    let counts = counts.clone();
    tokio::spawn(async move {
        loop {
            println!("{:>11}\t{}", "latency", "count");
            for range in &[UNDER_ONE, ONE_TO_TEN, TEN_TO_HUNDRED, OVER_HUNDRED] {
                let counts = counts.clone();
                let mut counts = counts.lock().unwrap();
                let cnt = counts.get_mut(range).unwrap();
                println!("{:>8} ms\t{}", range, cnt);
                *cnt = 0;
            }
            sleep(Duration::from_secs(1)).await
        }
    });
}

fn start_perf_event_handler(mut loaded: Loaded, counts: Counts) {
    let counts = counts.clone();
    tokio::spawn(async move {
        while let Some((name, events)) = loaded.events.next().await {
            for event in events {
                match name.as_str() {
                    "pid" => {
                        let vev = unsafe { ptr::read(event.as_ptr() as *const VFSEvent) };
                        let latency = vev.latency / 1_000_000;
                        let range = if latency < 1 {
                            UNDER_ONE
                        } else if 1 <= latency && latency < 10 {
                            ONE_TO_TEN
                        } else if 10 <= latency && latency < 100 {
                            TEN_TO_HUNDRED
                        } else {
                            OVER_HUNDRED
                        };
                        let mut counts = counts.lock().unwrap();
                        *counts.get_mut(range).unwrap() += 1;
                    }
                    _ => panic!("unexpected event"),
                }
            }
        }
    });
}

fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    if unsafe { libc::geteuid() } != 0 {
        error!("You must be root to use eBPF!");
        process::exit(1);
    }
    let counts: Counts = Arc::new(Mutex::new(
        [
            (UNDER_ONE, 0),
            (ONE_TO_TEN, 0),
            (TEN_TO_HUNDRED, 0),
            (OVER_HUNDRED, 0),
        ]
        .iter()
        .cloned()
        .collect(),
    ));
    let rt = runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _ = rt.block_on(async {
        let mut loaded = Loader::load(probe_code()).expect("error loading BPF program");
        for kp in loaded.kprobes_mut() {
            kp.attach_kprobe(&kp.name(), 0)
                .expect(&format!("error attaching kprobe program {}", kp.name()));
        }

        start_perf_event_handler(loaded, counts.clone());
        start_reporter(counts.clone());

        signal::ctrl_c().await
    });
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/vfsreadlat/vfsreadlat.elf"
    ))
}
