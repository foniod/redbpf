use std::env;
use std::path::{Path, PathBuf};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use cargo_bpf_lib as cargo_bpf;

fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let cargo = PathBuf::from(env::var("CARGO").unwrap());
    let target = PathBuf::from(env::var("OUT_DIR").unwrap());
    let probes = Path::new("../example-probes");

    let mut features = vec![String::from("probes")];
    if env::var("CARGO_FEATURE_KERNEL5_8").is_ok() {
        features.push(String::from("kernel5_8"));
    }
    if env::var("CARGO_FEATURE_KERNEL5_9").is_ok() {
        features.push(String::from("kernel5_8"));
        features.push(String::from("kernel5_9"));
    }
    cargo_bpf::build_with_features(
        &cargo,
        &probes,
        &target.join("target"),
        &mut Vec::new(),
        &features,
    )
    .expect("couldn't compile probes");

    cargo_bpf::probe_files(&probes)
        .expect("couldn't list probe files")
        .iter()
        .for_each(|file| {
            println!("cargo:rerun-if-changed={}", file);
        });
    println!("cargo:rerun-if-changed=../example-probes/Cargo.toml");
}
