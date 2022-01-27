use std::env;
use std::path::{Path, PathBuf};

use cargo_bpf::BuildOptions;
use cargo_bpf_lib as cargo_bpf;

fn main() {
    let cargo = PathBuf::from(env::var("CARGO").unwrap());
    let target = PathBuf::from(env::var("OUT_DIR").unwrap());
    let package = Path::new("probes");

    let mut buildopt = BuildOptions::default();
    buildopt.target_dir = target.join("target");

    cargo_bpf::build(&cargo, &package, &mut Vec::new(), &buildopt)
        .expect("couldn't compile probes");

    cargo_bpf::probe_files(&package)
        .expect("couldn't list probe files")
        .iter()
        .for_each(|file| {
            println!("cargo:rerun-if-changed={}", file);
        });
}
