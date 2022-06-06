use libc;
use std::process;
use tokio::signal::ctrl_c;
use tracing::{error, subscriber, Level};
use tracing_subscriber::FmtSubscriber;
use redbpf::load::Loader;

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
    for tracepoint in loaded.tracepoints_mut() {
        tracepoint.attach_trace_point("syscalls", "sys_enter_connect")
            .expect(format!("error on attach_trace_point to {}", tracepoint.name()).as_str());
    }

    println!("Hit Ctrl-C to quit");
    ctrl_c().await.expect("Error awaiting CTRL-C");
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
    env!("OUT_DIR"),
    "/target/bpf/programs/connection_tracer/connection_tracer.elf"
    ))
}
