use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-lib=static=bpf");

    cc::Build::new()
        .include("libbpf/include/uapi") // these are the libbpf includes
        .include("libbpf/include")
        .include(".") // bcc/libbpf.c includes "libbpf/src/bpf.h"
        .include("bcc") //  this is needed for  setns.h
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
        .file("bcc/libbpf.c") // this is the bcc libbpf wrapper
        .file("bcc/perf_reader.c")
        .compile("libbpf.a");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bindings = bindgen::Builder::default()
        .header("bcc/libbpf.h")
        .generate()
        .expect("Unable to generate bindings");
    bindings
        .write_to_file(out_path.join("libbpf_bindings.rs"))
        .expect("Couldn't write bindings!");
    let bindings = bindgen::Builder::default()
        .header("bcc/perf_reader.h")
        .generate()
        .expect("Unable to generate bindings");
    bindings
        .write_to_file(out_path.join("perf_reader_bindings.rs"))
        .expect("Couldn't write bindings!");
}
