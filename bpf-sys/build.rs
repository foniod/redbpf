// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![deny(clippy::all)]
use std::env;
use std::path::PathBuf;

const KERNEL_HEADERS: [&str; 6] = [
    "arch/x86/include/generated/uapi",
    "arch/x86/include/uapi",
    "arch/x86/include/",
    "include/generated/uapi",
    "include/uapi",
    "include",
];

pub mod uname {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/uname.rs"));
}

pub mod headers {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/headers.rs"));
}

fn rerun_if_changed_dir(dir: &str) {
    println!("cargo:rerun-if-changed={}/", dir);
    for ext in &["c", "h", "bash", "map", "md", "rst", "sh", "template"] {
        glob::glob(&format!("./{}/**/*.{}", dir, ext))
            .expect("Failed to glob for source files from build.rs")
            .filter_map(|e| e.ok())
            .for_each(|path| println!("cargo:rerun-if-changed={}", path.to_string_lossy()));
    }
}

fn main() {
    println!("cargo:rustc-link-lib=static=bpf");
    for dir in &["bcc", "libbpf", "libelf"] {
        rerun_if_changed_dir(dir);
    }
    println!("cargo:rerun-if-changed=bpfsys-musl.h");
    println!("cargo:rerun-if-changed=libbpf_xdp.h");

    let target = env::var("TARGET").unwrap();
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = PathBuf::from(out_dir);

    let mut libbpf = cc::Build::new();
    libbpf
        .flag("-Wno-sign-compare")
        .flag("-Wno-int-conversion")
        .flag("-Wno-unused-parameter")
        .flag("-Wno-unused-result")
        .flag("-Wno-format-truncation")
        .flag("-Wno-missing-field-initializers")
        .include("libbpf/include/uapi")
        .include("libbpf/include")
        .include("bcc")
        .include("libelf")
        .include(".");
    if target.contains("musl") {
        for include in
            headers::prefix_kernel_headers(&KERNEL_HEADERS).expect("couldn't find kernel headers")
        {
            libbpf.include(include);
        }
        libbpf
            .define("COMPAT_NEED_REALLOCARRAY", "1")
            .flag("-include")
            .flag("bpfsys-musl.h");
    }
    libbpf
        .flag("-include")
        .flag("linux/stddef.h")
        .file("libbpf/src/bpf.c")
        .file("libbpf/src/bpf_prog_linfo.c")
        .file("libbpf/src/btf.c")
        .file("libbpf/src/libbpf.c")
        .file("libbpf/src/libbpf_errno.c")
        .file("libbpf/src/libbpf_probes.c")
        .file("libbpf/src/netlink.c")
        .file("libbpf/src/nlattr.c")
        .file("libbpf/src/str_error.c")
        .file("libbpf/src/xsk.c")
        .file("bcc/libbpf.c")
        .file("bcc/perf_reader.c")
        .compile("libbpf.a");

    let bindings = bindgen::Builder::default()
        .header("libbpf_xdp.h")
        .header("libbpf/src/bpf.h")
        .clang_arg("-Ilibbpf/src")
        .clang_arg("-Ilibbpf/include/uapi")
        .clang_arg("-Ilibbpf/include")
        .clang_arg("-Ibcc")
        .generate()
        .expect("Unable to generate bindings");
    bindings
        .write_to_file(out_path.join("libbpf_bindings.rs"))
        .expect("Couldn't write bindings!");
    let bindings = bindgen::Builder::default()
        .header("libbpf/src/libbpf.h")
        .clang_arg("-Ilibbpf/include/uapi")
        .clang_arg("-Ilibbpf/include")
        .clang_arg("-Ibcc")
        .whitelist_type("bpf_map_def")
        .generate()
        .expect("Unable to generate bindings");
    bindings
        .write_to_file(out_path.join("libbpf_map_def.rs"))
        .expect("Couldn't write bindings!");
    let bindings = bindgen::Builder::default()
        .header("bcc/perf_reader.h")
        .header("libbpf/src/bpf.h")
        .clang_arg("-Ilibbpf/src")
        .clang_arg("-Ilibbpf/include/uapi")
        .clang_arg("-Ilibbpf/include")
        .clang_arg("-Ibcc")
        .generate()
        .expect("Unable to generate bindings");
    bindings
        .write_to_file(out_path.join("perf_reader_bindings.rs"))
        .expect("Couldn't write bindings!");
}
