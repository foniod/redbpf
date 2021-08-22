use futures::stream::StreamExt;
use libc::pid_t;
use std::boxed::Box;
use std::collections::HashMap;
use std::env;
use std::process;
use std::ptr;
use std::sync::{Arc, Mutex};
use tokio;
use tokio::runtime;
use tokio::signal;
use tracing::{error, Level};
use tracing_subscriber::FmtSubscriber;

use redbpf::load::{Loaded, Loader};
use redbpf::{BpfStackFrames, StackTrace};

use probes::mallocstacks::MallocEvent;

struct AllocSize {
    size: u64,
    count: u64,
    frames: BpfStackFrames,
}

type Acc = Arc<Mutex<HashMap<i64, AllocSize>>>;

fn handle_malloc_event(acc: Acc, loaded: &Loaded, event: Box<[u8]>) {
    let mut acc = acc.lock().unwrap();
    let mev = unsafe { ptr::read(event.as_ptr() as *const MallocEvent) };
    if let Some(alloc_size) = acc.get_mut(&mev.stackid) {
        (*alloc_size).size += mev.size;
        (*alloc_size).count += 1;
    } else {
        let mut stack_trace = StackTrace::new(loaded.map("stack_trace").unwrap());
        if let Some(frames) = stack_trace.get(mev.stackid) {
            acc.insert(
                mev.stackid,
                AllocSize {
                    size: mev.size,
                    count: 1,
                    frames,
                },
            );
        }
    }
}

fn start_perf_event_handler(mut loaded: Loaded, acc: Acc) {
    tokio::spawn(async move {
        while let Some((name, events)) = loaded.events.next().await {
            match name.as_str() {
                "malloc_event" => {
                    for event in events {
                        handle_malloc_event(acc.clone(), &loaded, event);
                    }
                }
                _ => {}
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

    let args: Vec<String> = env::args().collect();
    let pid = args.get(1).unwrap_or_else(|| {
        error!("PID must be specified");
        process::exit(1);
    });
    let pid = pid.parse::<pid_t>().unwrap_or_else(|err| {
        error!("Invalid PID: {}", err);
        process::exit(1);
    });

    let acc: Acc = Arc::new(Mutex::new(HashMap::new()));
    let rt = runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _ = rt.block_on(async {
        let mut loaded = Loader::load(probe_code()).expect("error loading BPF program");

        for prb in loaded.uprobes_mut() {
            prb.attach_uprobe(Some(&prb.name()), 0, "libc", Some(pid))
                .expect(&format!("error attaching uprobe program {}", prb.name()));
        }
        start_perf_event_handler(loaded, acc.clone());

        println!("Attaching to malloc in PID {}, Hit Ctrl-C to quit", pid);
        signal::ctrl_c().await
    });
    println!("");

    let acc = acc.lock().unwrap();
    for alloc_size in acc.values() {
        println!(
            "{} bytes allocated, malloc called {} times at:",
            alloc_size.size, alloc_size.count
        );
        for ip in alloc_size.frames.ip.iter() {
            if *ip == 0x0 {
                break;
            }
            println!("{:#x}", ip);
        }
    }
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/mallocstacks/mallocstacks.elf"
    ))
}
