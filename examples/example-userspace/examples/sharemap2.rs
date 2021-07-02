/// This example is paired with sharemap1 example. The purpose of sharemap1
/// and sharemap2 is to show how to share maps between independent BPF
/// programs. First, sharemap1 creates a map and pins it to file. And then
/// sharemap2 loads the map from the pin file.
///
/// 4 programs will share one map. 4 programs consists of the following:
/// 1. a BPF program in kernel space of sharemap1
/// 2. a userspace program of sharemap1
/// 3. a BPF program in kernel space of sharemap2
/// 4. a userspace program of sharemap2
///
/// The instruction that the sharemap2 loads a map from the pin file which was
/// created by sharemap1 is defined at example-probes/src/sharemap2/main.rs. It
/// utilizes `redbpf::Map::from_pin_file` and
/// `redbpf::ModuleBuilder::replace_map`.
use redbpf::{Array, Map, ModuleBuilder};
use std::process;
use std::time::Duration;
use tokio::signal::ctrl_c;
use tokio::time::sleep;
use tracing::{error, Level};
use tracing_subscriber::FmtSubscriber;

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

    let mut builder = ModuleBuilder::parse(probe_code()).expect("error on ModuleBuilder::parse");
    builder
        .replace_map(
            MAP_NAME,
            Map::from_pin_file("/sys/fs/bpf/sharedmap").expect("error on Map::from_pin_file"),
        )
        .expect("error on replace_map");
    let mut module = builder
        .to_module()
        .expect("error on ModuleBuilder::to_module");

    for prog in module.programs.iter_mut() {
        prog.load(module.version, module.license.clone())
            .expect("error on Program::load");
    }
    module
        .kprobe_mut("sys_exit")
        .expect("sys_exit kprobe not found")
        .attach_kprobe("__x64_sys_exit", 0)
        .expect("error on attach_kprobe");
    let arr = Array::<u64>::new(module.map(MAP_NAME).expect("map not found"))
        .expect("error on Array::new");
    loop {
        println!("sharemap2 counter: {}", arr.get(0).unwrap());
        tokio::select! {
            _ = sleep(Duration::from_secs(1)) => {}
            _ = ctrl_c() => {
                break;
            }
        }
    }
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/sharemap2/sharemap2.elf"
    ))
}
