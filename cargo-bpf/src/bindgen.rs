// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

pub use bindgen::Builder;
use bindgen::{self, callbacks::ParseCallbacks};
use std::io::{self, Write};
use std::path::Path;
use std::process::Command;
use std::str;

pub use crate::accessors::generate_read_accessors;
use crate::build_constants::{kernel_headers, BUILD_FLAGS};
use crate::CommandError;
use bpf_sys::type_gen::vmlinux_btf_dump;

/// Get `bindgen::Builder` that generates bindings using pre-installed kernel
/// headers
///
/// Necessary include-directories for kernel headers are set to
/// `bindgen::Builder`. So that users of this function can include kernel
/// headers.
pub fn get_builder_kernel_headers() -> Result<Builder, String> {
    let kernel_headers =
        kernel_headers().or_else(|_| Err("kernel headers not found".to_string()))?;
    let mut flags: Vec<String> = kernel_headers
        .iter()
        .map(|dir| format!("-I{}", dir))
        .collect();
    flags.extend(BUILD_FLAGS.iter().map(|f| f.to_string()));

    Ok(bindgen::builder()
        .clang_args(&flags)
        .use_core()
        .ctypes_prefix("::cty")
        .opaque_type("xregs_state")
        .parse_callbacks(Box::new(Callbacks)))
}

/// Get `bindgen::Builder` that generates bindings using BTF of vmlinux
///
/// `c_dump_file` is a path of C header file where structs and enums will be
/// written by
/// [`VmlinuxBtfDump`](../../bpf-sys/type-gen/struct.VmlinuxBtfDump.html). It
/// is just a temporary file that will be read by `bindgen` to generate rust
/// bindings in the end. The file name of `c_dump_file` is used as an
/// include-guard. e.g., if `c_dump_file` is "vmlinux.h" then the guard macro
/// is `__VMLINUX_H__`
pub fn get_builder_vmlinux(c_dump_file: impl AsRef<Path>) -> Result<Builder, String> {
    vmlinux_btf_dump()
        .or_else(|e| Err(format!("error on vmlinux_btf_dump: {:?}", e)))?
        .generate(c_dump_file.as_ref())
        .or_else(|e| Err(format!("error on VmlinuxBtfDump::generate: {:?}", e)))?;

    Ok(bindgen::builder()
        .use_core()
        .ctypes_prefix("::cty")
        .parse_callbacks(Box::new(Callbacks))
        .header(c_dump_file.as_ref().to_str().unwrap()))
}

pub fn builder() -> Builder {
    get_builder_kernel_headers().unwrap()
}

pub fn generate(builder: &Builder, extra_args: &[&str]) -> Result<String, String> {
    let mut bindgen_flags = builder.command_line_flags();
    let p = bindgen_flags
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(bindgen_flags.len() - 1);
    for (i, flag) in extra_args.iter().enumerate() {
        bindgen_flags.insert(p + i, String::from(*flag));
    }
    let output = Command::new("bindgen")
        .args(bindgen_flags)
        .output()
        .expect("error running bindgen");
    if !output.status.success() {
        return Err(String::from_utf8(output.stderr).unwrap());
    }
    io::stderr().write_all(&output.stderr).unwrap();
    let bindings = String::from_utf8(output.stdout).unwrap();
    Ok(bindings)
}

pub fn cmd_bindgen(header: &Path, extra_args: &[&str]) -> Result<(), CommandError> {
    let (_temp, header) = if !header.exists() {
        // try to find find the file in the kernel include path
        let path = header.to_str().unwrap();
        let mut file = tempfile::Builder::new().suffix(".h").tempfile().unwrap();
        write!(
            &mut file,
            r#"
#define KBUILD_MODNAME "cargo_bpf_bindings"
#include <linux/kconfig.h>
#include <{}>
        "#,
            path
        )
        .unwrap();
        let header = file.path().to_owned();
        (Some(file), header)
    } else {
        (None, header.to_owned())
    };

    let builder = builder().header(header.to_str().unwrap());
    let bindings = generate(&builder, extra_args).map_err(CommandError)?;
    let mut out = io::stdout();
    writeln!(
        &mut out,
        r"
mod generated_bindings {{
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(clippy::all)]
{}
}}
pub use generated_bindings::*;
",
        bindings
    )
    .unwrap();

    Ok(())
}

#[derive(Debug)]
struct Callbacks;

impl ParseCallbacks for Callbacks {
    fn item_name(&self, name: &str) -> Option<String> {
        match name {
            "u8" | "u16" | "u32" | "u64" => Some(format!("_cargo_bpf_{}", name)),
            _ => None,
        }
    }
}
