// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use crate::CommandError;

impl From<toml_edit::Value> for CommandError {
    fn from(error: toml_edit::Value) -> CommandError {
        CommandError(error.to_string())
    }
}

pub fn new_program(name: &str) -> Result<(), CommandError> {
    use toml_edit::{value, Array, ArrayOfTables, Document, Item, Table};

    let ident = name_to_ident(name);
    let current_dir = std::env::current_dir().unwrap();
    let path = Path::new("Cargo.toml");
    if !path.exists() {
        return Err(CommandError(format!(
            "Could not find `Cargo.toml' in {:?}",
            current_dir
        )));
    }
    let data = fs::read_to_string(path).unwrap();
    let mut config = data.parse::<Document>().unwrap();

    let crate_name = config["lib"]["name"]
        .as_str()
        .or_else(|| config["package"]["name"].as_str())
        .ok_or_else(|| CommandError("invalid manifest syntax".to_string()))
        .map(String::from)?;

    let mut targets = match &config["bin"] {
        Item::None => ArrayOfTables::new(),
        Item::ArrayOfTables(array) => array.clone(),
        _ => return Err(CommandError("invalid manifest syntax".to_string())),
    };
    if targets
        .iter()
        .any(|target| target["name"].as_str().map(|s| s == name).unwrap_or(false))
    {
        return Err(CommandError(format!(
            "a program named `{}' already exists",
            name
        )));
    }

    let mut target = Table::new();
    target.entry("name").or_insert(value(name));
    target
        .entry("path")
        .or_insert(value(format!("src/{}/main.rs", name)));
    let mut features = Array::default();
    features.push("probes")?;
    target.entry("required-features").or_insert(value(features));

    targets.append(target);
    config["bin"] = Item::ArrayOfTables(targets);

    fs::write(path, config.to_string())?;

    let src = Path::new("src");
    let lib_rs = src.join("lib.rs");
    let mut file = OpenOptions::new().write(true).open(lib_rs)?;
    file.seek(SeekFrom::End(0))?;
    writeln!(&mut file, "pub mod {};", ident)?;

    let probe_dir = src.join(name);
    fs::create_dir_all(probe_dir.clone())?;

    let mod_rs = probe_dir.join("mod.rs");
    fs::write(
        mod_rs,
        r#"
use cty::*;

// This is where you should define the types shared by the kernel and user
// space, eg:
//
// #[repr(C)]
// #[derive(Debug)]
// pub struct SomeEvent {
//     pub pid: u64,
//     ...
// }
"#,
    )?;
    let main_rs = probe_dir.join("main.rs");
    let mut main_rs = File::create(main_rs)?;
    write!(
        &mut main_rs,
        r#"#![no_std]
#![no_main]
use cty::*;

// use one of the preludes
// use redbpf_probes::kprobe::prelude::*;
// use redbpf_probes::xdp::prelude::*;
// use redbpf_probes::socket_filter::prelude::*;
// use redbpf_probes::tc::prelude::*;
// use redbpf_probes::uprobe::prelude::*;
// use redbpf_probes::sockmap::prelude::*;
// use redbpf_probes::bpf_iter::prelude::*;

// Use the types you're going to share with userspace, eg:
// use {lib}::{name}::SomeEvent;

program!(0xFFFFFFFE, "GPL");

// The maps and probe functions go here, eg:
//
// #[map]
// static mut syscall_events: PerfMap<SomeEvent> = PerfMap::with_max_entries(1024);
//
// #[kprobe("__x64_sys_open")]
// fn syscall_enter(regs: Registers) {{
//   let pid_tgid = bpf_get_current_pid_tgid();
//   ...
//
//   let event = SomeEvent {{
//     pid: pid_tgid >> 32,
//     ...
//   }};
//   unsafe {{ syscall_events.insert(regs.ctx, &event) }};
// }}
"#,
        lib = name_to_ident(crate_name.as_str()),
        name = name_to_ident(name),
    )?;

    Ok(())
}

fn name_to_ident(name: &str) -> String {
    name.replace("-", "_")
}
