use std::io::Write;
use std::fs::{self, File};
use std::path::PathBuf;

use crate::commands::CommandError;

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
redbpf-macros = {{ path = "../../ingraind/redbpf-macros" }}
redbpf-probes = {{ path = "../../ingraind/redbpf-probes" }}

[build-dependencies]
bindgen = "0.51.1"
redbpf = {{ version = "0.3.3", features = ["build"] }}

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
#![feature(const_fn, const_transmute)]
#![no_std]
"#)?;
    Ok(())
}
