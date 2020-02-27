
use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;

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

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let mut builder = bpf_bindgen::builder().header("include/bindings.h");
    let types = ["request", "req_opf"];

    for ty in types.iter() {
        builder = builder.whitelist_type(ty);
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
