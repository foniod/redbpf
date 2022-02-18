use std::env;
use std::path::{Path, PathBuf};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use cargo_bpf::BuildOptions;
use cargo_bpf_lib as cargo_bpf;

fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let cargo = PathBuf::from(env::var("CARGO").unwrap());
    let target = PathBuf::from(env::var("OUT_DIR").unwrap());
    let package = Path::new("../example-probes");

    let mut features = vec![String::from("probes")];
    if env::var("CARGO_FEATURE_KERNEL5_8").is_ok() {
        features.push(String::from("kernel5_8"));
    }

    let mut buildopt = BuildOptions::default();
    buildopt.target_dir = target.join("target");
    if env::var("CARGO_FEATURE_FORCE_LOOP_UNROLL").is_ok() {
        buildopt.force_loop_unroll = true;
    }
    if let Err(e) =
        cargo_bpf::build_with_features(&cargo, &package, &mut Vec::new(), &buildopt, &features)
    {
        eprintln!("{}", e);
        panic!("probes build failed");
    }

    println!("cargo:rerun-if-changed=../../redbpf-probes");
    println!("cargo:rerun-if-changed=../../redbpf-macros");
    cargo_bpf::probe_files(&package)
        .expect("couldn't list probe files")
        .iter()
        .for_each(|file| {
            println!("cargo:rerun-if-changed={}", file);
        });
    println!("cargo:rerun-if-changed=../example-probes/Cargo.toml");
}
