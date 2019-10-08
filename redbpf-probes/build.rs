use std::env;
use std::io::Write;
use std::fs::File;
use std::path::PathBuf;

use redbpf::build::headers::kernel_headers;

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
        .header("../include/bpf_helpers.h")
        .ctypes_prefix("::cty")
        .whitelist_type("pt_regs")
        .whitelist_type("bpf_map_def")
        .whitelist_type("bpf_map_type")
        .whitelist_type("bpf_func_id")
        .generate()
        .expect("Unable to generate bindings!");
    let mut file = File::create(out_dir.join("gen_helpers.rs")).unwrap();
    writeln!(&mut file, r"
mod gen_helpers {{
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(clippy::all)]
{}
}}
pub use gen_helpers::*;
", bindings.to_string()).unwrap();
    
    let bindings = bindgen::builder()
        .clang_args(&flags)
        .header("../include/xdp_bindings.h")
        .ctypes_prefix("::cty")
        .whitelist_type("ip.*hdr")
        .generate()
        .expect("Unable to generate bindings!");
    let mut file = File::create(out_dir.join("gen_xdp_bindings.rs")).unwrap();
    writeln!(&mut file, r"
mod gen_xdp_bindings {{
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(clippy::all)]
{}
}}
pub use gen_xdp_bindings::*;
", bindings.to_string()).unwrap();
}