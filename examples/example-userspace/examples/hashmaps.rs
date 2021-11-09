//! This example shows usage of HashMap, PerCpuHashMap and LruHashMap.  And
//! also it confirms you that hashmap has race condition problems. You should
//! consider PerCpuHashMap if your program needs to store accurate map data.

use libc;
use std::process;
use std::time::Duration;
use tokio::{signal::ctrl_c, time::sleep};
use tracing::{error, subscriber, Level};
use tracing_subscriber::FmtSubscriber;

use probes::hashmaps::BigStructure;
use redbpf::{load::Loader, HashMap, LruHashMap, PerCpuHashMap};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    subscriber::set_global_default(subscriber).unwrap();
    if unsafe { libc::geteuid() != 0 } {
        error!("You must be root to use eBPF!");
        process::exit(1);
    }

    let mut loaded = Loader::load(probe_code()).expect("error loading probe");
    for kp in loaded.kprobes_mut() {
        kp.attach_kprobe(kp.name().as_str(), 0)
            .expect(format!("error on attach_kprobe to {}", kp.name()).as_str());
    }

    let big_struct =
        LruHashMap::<i8, BigStructure>::new(loaded.map("BIG_STRUCT").expect("map not found"))
            .expect("error on LruHashMap::new");
    let pcpu_mem_alloc =
        PerCpuHashMap::<usize, usize>::new(loaded.map("PCPU_MEM_ALLOC").expect("map not found"))
            .expect("error on PerCpuHashMap::new");
    let mem_alloc = HashMap::<usize, usize>::new(loaded.map("MEM_ALLOC").expect("map not found"))
        .expect("error on HashMap::new");
    println!("Hit Ctrl-C to quit");
    loop {
        tokio::select! {
            _ = sleep(Duration::from_secs(1)) => {}
            _ = ctrl_c() => break
        }

        let mut alloc_stats = mem_alloc.iter().collect::<Vec<(usize, usize)>>();
        alloc_stats.sort();
        println!("[allocation size upto XXX bytes] => [number of __kmalloc call]");

        for (size, total_cnt) in alloc_stats {
            let pcpu_vals = pcpu_mem_alloc.get(size).unwrap();
            let exact_cnt: usize = pcpu_vals.iter().sum();
            if total_cnt != exact_cnt {
                println!(
                    "{} => {} != {} (hashmap != pcpu hashmap)",
                    size, total_cnt, exact_cnt
                );
            } else {
                println!("{} => {}", size, total_cnt);
            }
        }
    }

    println!("");
    println!("iterate over big structures!");
    for (_, bigstruct) in big_struct.iter() {
        println!("{:?}", bigstruct);
    }
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/hashmaps/hashmaps.elf"
    ))
}
