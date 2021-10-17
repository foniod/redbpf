/// This example shows how to use a BPF iterator of task_struct
use libc;
use std::process;
use std::time::Duration;
use tokio;
use tracing::{error, Level};
use tracing_subscriber::FmtSubscriber;

use redbpf::load::Loader;

const PROG_NAME: &str = "dump_tgid";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    if unsafe { libc::getuid() != 0 } {
        error!("You must be root to use eBPF!");
        process::exit(1);
    }

    let mut loaded = Loader::load(probe_code()).unwrap();
    let tasks = loaded
        .task_iter_mut(PROG_NAME)
        .expect(&format!("{} not found", PROG_NAME));

    println!("==== TGID list ====");
    for tgid in tasks
        .bpf_iter::<libc::pid_t>()
        .expect("error on TaskIter::bpf_iter")
    {
        println!("{}", tgid);
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    println!("==== TGID list ====");
    for tgid in tasks
        .bpf_iter::<libc::pid_t>()
        .expect("error on TaskIter::bpf_iter")
    {
        println!("{}", tgid);
    }
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/tasks/tasks.elf"
    ))
}
