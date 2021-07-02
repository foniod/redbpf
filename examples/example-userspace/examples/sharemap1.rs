/// This example is paired with sharemap2 example. The purpose of sharemap1
/// and sharemap2 is to show how to share maps between independent BPF
/// programs. First, sharemap1 creates a map and pins it to file. And then
/// sharemap2 loads the map from the pin file.
///
/// 4 programs will share one map. 4 programs consists of the following:
/// 1. a BPF program in kernel space of sharemap1
/// 2. a userspace program of sharemap1
/// 3. a BPF program in kernel space of sharemap2
/// 4. a userspace program of sharemap2
use redbpf::load::Loader;
use redbpf::Array;
use std::process;
use std::time::Duration;
use tokio::signal::ctrl_c;
use tokio::time::sleep;
use tracing::{debug, error, Level};
use tracing_subscriber::FmtSubscriber;

const PIN_FILE: &str = "/sys/fs/bpf/sharedmap";
const MAP_NAME: &str = "sharedmap";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    if unsafe { libc::geteuid() != 0 } {
        error!("You must be root to use eBPF!");
        process::exit(1);
    }

    let mut loaded = Loader::load(probe_code()).unwrap();
    loaded
        .map_mut(MAP_NAME)
        .expect("map not found")
        .pin(PIN_FILE)
        .expect("error on pinning");
    debug!("attach_kprobe on sys_clone");
    loaded
        .kprobe_mut("sys_clone")
        .expect("sys_clone kprobe not found")
        .attach_kprobe("__x64_sys_clone", 0)
        .expect("error on attach_kprobe");
    let arr = Array::<u64>::new(loaded.map_mut(MAP_NAME).unwrap()).expect("error on Array::new");
    loop {
        println!("sharemap1 counter: {}", arr.get(0).unwrap());
        tokio::select! {
            _ = sleep(Duration::from_secs(1)) => {}
            _ = ctrl_c() => {
                break;
            }
        }
    }
    loaded
        .map_mut(MAP_NAME)
        .unwrap()
        .unpin()
        .expect("error on unpin");
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/sharemap1/sharemap1.elf"
    ))
}
