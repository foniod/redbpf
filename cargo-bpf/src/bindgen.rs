// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use bindgen;
pub use bindgen::Builder;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;
use std::str;

use crate::CommandError;
pub use crate::accessors::generate_read_accessors;

use redbpf::{self, build::headers::kernel_headers};

pub fn builder() -> Builder {
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

    bindgen::builder()
        .clang_args(&flags)
        .use_core()
        .ctypes_prefix("::cty")
}

pub fn generate(builder: &Builder, extra_args: &[&str]) -> String {
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
    io::stderr().write_all(&output.stderr).unwrap();
    let bindings = str::from_utf8(&output.stdout).unwrap();
    bindings.to_string()
}

pub fn cmd_bindgen(header: &PathBuf, extra_args: &[&str]) -> Result<(), CommandError> {
    let builder = builder().header(header.to_str().unwrap());
    let bindings = generate(&builder, extra_args);
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
