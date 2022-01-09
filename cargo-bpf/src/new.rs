// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

use crate::CommandError;

pub fn new(path: &PathBuf, name: Option<&str>) -> Result<(), CommandError> {
    if path.exists() {
        return Err(CommandError(format!(
            "destination `{}' already exists",
            path.to_str().unwrap()
        )));
    }

    fs::create_dir_all(path.join("src"))?;
    let name = name.or_else(|| path.file_name()?.to_str()).unwrap();
    let mut file = File::create(path.join("Cargo.toml"))?;
    write!(
        &mut file,
        r#"[package]
name = "{}"
version = "0.1.0"
edition = '2018'

[dependencies]
cty = "0.2"
redbpf-macros = "2.3.0"
redbpf-probes = "2.3.0"

[build-dependencies]
cargo-bpf = {{ version = "2.3.0", default-features = false }}

[features]
default = []
probes = []

[lib]
path = "src/lib.rs"
"#,
        name
    )?;

    let mut file = File::create(path.join("src").join("lib.rs"))?;
    write!(
        &mut file,
        r#"
#![no_std]
"#
    )?;
    Ok(())
}
