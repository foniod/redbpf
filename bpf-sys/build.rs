// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![deny(clippy::all)]
use std::env;
use std::path::PathBuf;
use std::process::Command;

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
    println!(
        "cargo:rustc-link-search=native={}",
        env::var("OUT_DIR").unwrap()
    );
    println!("cargo:rustc-link-lib=static=bpf");
    println!("cargo:rustc-link-lib=elf");
    println!("cargo:rustc-link-lib=z");
    for dir in &["libbpf", "libelf"] {
        rerun_if_changed_dir(dir);
    }
    println!("cargo:rerun-if-changed=bpfsys-musl.h");
    println!("cargo:rerun-if-changed=libbpf_xdp.h");

    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = PathBuf::from(out_dir);

    // -fPIE is passed because Fedora 35 requires it. Other distros like Ubuntu
    // 21.04, Alpine 3.14 also works find with it
    Command::new("make").args(format!("-C libbpf/src BUILD_STATIC_ONLY=1 OBJDIR={}/libbpf DESTDIR={out_dir} INCLUDEDIR= LIBDIR= UAPIDIR=", out_dir=env::var("OUT_DIR").unwrap()).split(" ")).arg("CFLAGS=-g -O2 -Werror -Wall -fPIE").arg("install").status().unwrap();
    let bindings = bindgen::Builder::default()
        .header("libbpf_xdp.h")
        .header("libbpf/src/bpf.h")
        .header("libbpf/src/libbpf.h")
        .header("libbpf/include/uapi/linux/btf.h")
        .header("libbpf/src/btf.h")
        .clang_arg("-Ilibbpf/src")
        .clang_arg("-Ilibbpf/include/uapi")
        .clang_arg("-Ilibbpf/include")
        // blacklist `bpf_map_def` to avoid conflict with libbpf_map_def.rs
        .blocklist_type("bpf_map_def")
        .generate()
        .expect("Unable to generate bindings");
    bindings
        .write_to_file(out_path.join("libbpf_bindings.rs"))
        .expect("Couldn't write bindings!");
    let bindings = bindgen::Builder::default()
        .header("libbpf/src/libbpf.h")
        .clang_arg("-Ilibbpf/include/uapi")
        .clang_arg("-Ilibbpf/include")
        .whitelist_type("bpf_map_def")
        .generate()
        .expect("Unable to generate bindings");
    bindings
        .write_to_file(out_path.join("libbpf_map_def.rs"))
        .expect("Couldn't write bindings!");
    let bindings = bindgen::Builder::default()
        .header("libbpf/src/bpf.h")
        .clang_arg("-Ilibbpf/src")
        .clang_arg("-Ilibbpf/include/uapi")
        .clang_arg("-Ilibbpf/include")
        .generate()
        .expect("Unable to generate bindings");
    bindings
        .write_to_file(out_path.join("perf_reader_bindings.rs"))
        .expect("Couldn't write bindings!");
}
