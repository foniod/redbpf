use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;
use tracing::{debug, warn, Level};
use tracing_subscriber::FmtSubscriber;

use bpf_sys::{
    headers::{get_custom_header_path, get_custom_header_version},
    type_gen::get_custom_vmlinux_path,
};
use cargo_bpf_lib::bindgen as bpf_bindgen;

fn create_module(path: PathBuf, name: &str, bindings: &str) -> io::Result<()> {
    let mut file = File::create(path)?;
    writeln!(
        &mut file,
        r"
mod {name} {{
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(unused_unsafe)]
#![allow(clippy::all)]
{bindings}
}}
pub use {name}::*;
",
        name = name,
        bindings = bindings
    )
}

fn rerun_if_changed_dir(dir: &str) {
    println!("cargo:rerun-if-changed={}/", dir);
    glob::glob(&format!("./{}/**/*.h", dir))
        .expect("Failed to glob for source files from build.rs")
        .filter_map(|e| e.ok())
        .for_each(|path| println!("cargo:rerun-if-changed={}", path.to_string_lossy()));
}

fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    rerun_if_changed_dir("include");

    if env::var("CARGO_FEATURE_PROBES").is_err() {
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let mut builder = if get_custom_vmlinux_path().is_some() {
        debug!("Generating custom bindings with BTF of vmlinux");
        bpf_bindgen::get_builder_vmlinux(out_dir.join("vmlinux.h")).unwrap()
    } else if get_custom_header_path().is_some() || get_custom_header_version().is_some() {
        debug!("Generating custom bindings with pre-installed kernel headers");
        bpf_bindgen::get_builder_kernel_headers().unwrap()
    } else {
        debug!("Try generating custom bindings with pre-installed kernel headers");
        bpf_bindgen::get_builder_kernel_headers()
            .or_else(|e| {
                warn!("error on bpf_bindgen::get_builder_kernel_headers: {:?}", e);
                debug!("try bpf_bindgen::get_builder_vmlinux");
                bpf_bindgen::get_builder_vmlinux(out_dir.join("vmlinux.h"))
            })
            .unwrap()
    };
    builder = builder.header("include/bindings.h");
    let types = ["request", "req_opf"];

    for ty in types.iter() {
        builder = builder.allowlist_type(ty);
    }

    let mut bindings = builder
        .generate()
        .expect("failed to generate bindings")
        .to_string();
    let accessors = bpf_bindgen::generate_read_accessors(&bindings, &["request", "gendisk"]);
    bindings.push_str("use redbpf_probes::helpers::bpf_probe_read;");
    bindings.push_str(&accessors);
    create_module(out_dir.join("gen_bindings.rs"), "gen_bindings", &bindings).unwrap();
}
