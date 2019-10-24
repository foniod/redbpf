use std::io::{self, Write};
use std::path::PathBuf;
use std::str;
use std::process::Command;
use bindgen;

use crate::CommandError;

use redbpf::{self, build::headers::kernel_headers};

pub fn cmd_bindgen(header: &PathBuf, extra_args: &[&str]) -> Result<(), CommandError> {
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

    let mut bindgen_flags = bindgen::builder()
        .clang_args(&flags)
        .header(header.to_str().unwrap())
        .use_core()
        .ctypes_prefix("::cty")
        .command_line_flags();
    let p = bindgen_flags
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(bindgen_flags.len() - 1);
    for (i, flag) in extra_args.iter().enumerate() {
        bindgen_flags.insert(p + i, String::from(*flag));
    }
    let output = Command::new("bindgen").args(bindgen_flags).output()?;
    io::stderr().write_all(&output.stderr)?;
    let bindings = output.stdout;
    let bindings = str::from_utf8(&bindings).unwrap();
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