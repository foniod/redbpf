use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;

use redbpf::build::headers::kernel_headers;

fn create_module(path: PathBuf, name: &str, bindings: &str) -> io::Result<()> {
    let mut file = File::create(path)?;
    writeln!(
        &mut file,
        r"
mod {name} {{
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(clippy::all)]
{bindings}
}}
pub use {name}::*;
",
        name=name,
        bindings=bindings
    )
}

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let kernel_headers = kernel_headers().expect("couldn't find kernel headers");
    let mut flags: Vec<String> = kernel_headers
        .iter()
        .map(|dir| format!("-I{}", dir))
        .collect();
    flags.extend(redbpf::build::BUILD_FLAGS.iter().map(|f| f.to_string()));
    flags.push("-Wno-unused-function".to_string());
    flags.push("-Wno-unused-variable".to_string());
    flags.push("-Wno-address-of-packed-member".to_string());
    flags.push("-Wno-gnu-variable-sized-type-not-at-end".to_string());

    let bindings = bindgen::builder()
        .clang_args(&flags)
        .header("./include/redbpf_helpers.h")
        .use_core()
        .ctypes_prefix("::cty")
        // bpf_helpers
        .whitelist_type("pt_regs")
        .whitelist_type("s32")
        .whitelist_type("bpf_.*")
        .whitelist_var("BPF_.*")
        // XDP
        .whitelist_type("xdp_md")
        .whitelist_type("ethhdr")
        .whitelist_type("iphdr")
        .whitelist_type("tcphdr")
        .whitelist_type("udphdr")
        .whitelist_type("xdp_action")
        .whitelist_type("__sk_.*")
        .whitelist_type("sk_.*")
        .whitelist_var("ETH_.*")
        .whitelist_var("IPPROTO_.*")
        .opaque_type("xregs_state")
        .generate()
        .expect("Unable to generate bindings!");
    create_module(
        out_dir.join("gen_helpers.rs"),
        "gen_helpers",
        &bindings.to_string(),
    )
    .unwrap();
}
