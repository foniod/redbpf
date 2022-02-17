// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use bindgen;
use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = PathBuf::from(out_dir);

    let bindings = bindgen::Builder::default()
        .header("bindings.h")
        .clang_arg("-Ilibbpf/src")
        .clang_arg("-Ilibbpf/include/uapi")
        .clang_arg("-Ilibbpf/include")
        .allowlist_function("btf_dump__new")
        .allowlist_function("vdprintf")
        .generate()
        .expect("Unable to generate bindings");
    bindings
        .write_to_file(out_path.join("libbpf_bindings.rs"))
        .expect("Couldn't write bindings!");
}
