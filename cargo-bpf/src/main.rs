// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/*!
Cargo subcommand for working with Rust eBPF programs.

# Overview

`cargo-bpf` is part of the [`redbpf`](https://github.com/foniod/redbpf)
project. In addition to `cargo-bpf`, the `redbpf` project includes
[`redbpf-probes`](../../redbpf_probes/) and
[`redbpf-macros`](../../redbpf_macros/), which provide an idiomatic Rust API to
write programs that can be compiled to eBPF bytecode and executed by the linux
in-kernel eBPF virtual machine.

# Installation

To install `cargo bpf` simply run:

```
cargo install cargo-bpf
```

# Creating a new project

After installng `cargo bpf`, you can create a new project with `cargo bpf new`:
```ìgnore
$ cargo bpf new hello-bpf
$ ls -R hello-bpf/
hello-bpf/:
Cargo.toml  src

hello-bpf/src:
lib.rs

$ cat hello-bpf/Cargo.toml
[package]
name = "hello-bpf"
version = "0.1.0"
edition = '2018'

[dependencies]
cty = "0.2"
redbpf-macros = "1.0"
redbpf-probes = "1.0"

[features]
default = []
probes = []

[lib]
path = "src/lib.rs"

$ cat hello-bpf/src/lib.rs
#![no_std]
```

As you can see `cargo bpf new` created a new crate `hello-bpf` and
automatically added `redbpf-probes` and `redbpf-macros` as dependencies. It
also created `src/lib.rs` and declared the crate as `no_std`, as eBPF
programs are run in a restricted virtual machine where `std` features are not
available.

# Adding a new eBPF program

Adding a new program is easy:

```
$ cd hello-bpf
$ cargo bpf add block_http
$ tail Cargo.toml
...
[[bin]]
name = "block_http"
path = "src/block_http/main.rs"
required-features = ["probes"]
```

As you can see, running `cargo bpf add` added a new `[bin]` target to the
crate. This new target will contain the eBPF program code.

# Building

Say that you're building an XDP program to block all traffic directed to port 80, and have therefore modified
`src/block_http/main.rs` to include the following code:

```no_run
#![no_std]
#![no_main]
use redbpf_probes::xdp::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[xdp]
pub fn block_port_80(ctx: XdpContext) -> XdpResult {
    if let Ok(transport) = ctx.transport() {
        if transport.dest() == 80 {
            return Ok(XdpAction::Drop);
        }
    }

    Ok(XdpAction::Pass)
}
```

In order to build the program, you can run:

```
$ cargo bpf build block_http
```

`cargo bpf build` will produce eBPF code compatibile with the format expected
by `redbpf::Module` and will place it in
`target/bpf/programs/block_http.elf`.

# Loading a program during development

`cargo bpf` includes a simple `load` subcommand that can be used during
development to test that your eBPF program is loading and producing the
expected output.

Loading eBPF programs requires admin priviledges, so you'll have to run
`load` as root or with sudo:

```
$ sudo cargo bpf load -i eth0 target/bpf/programs/block_http.elf
```

*/
use clap::{self, crate_authors, crate_version, App, AppSettings, Arg, SubCommand};
use std::path::PathBuf;

use cargo_bpf::BuildOptions;
use cargo_bpf_lib as cargo_bpf;

fn main() {
    let matches =
        App::new("cargo")
            .bin_name("cargo")
            .settings(&[
                AppSettings::ColoredHelp,
                AppSettings::ArgRequiredElseHelp,
                AppSettings::GlobalVersion,
                AppSettings::SubcommandRequiredElseHelp,
            ])
            .subcommand(
                SubCommand::with_name("bpf")
                    .version(format!("{} (with LLVM {})", crate_version!(), env!("CARGO_BPF_LLVM_VERSION")).as_str())
                    .author(crate_authors!("\n"))
                    .about("A cargo subcommand for developing eBPF programs")
                    .settings(&[
                        AppSettings::SubcommandRequiredElseHelp
                    ])
                    .subcommand(
                        SubCommand::with_name("new")
                            .about("Creates a new eBPF package at <PATH>")
                            .arg(Arg::with_name("name").long("name").value_name("NAME").help(
                                "Set the resulting package name, defaults to the directory name",
                            ))
                            .arg(Arg::with_name("PATH").required(true)),
                    )
                    .subcommand(
                        SubCommand::with_name("add")
                            .about("Adds a new eBPF program at src/<NAME>")
                            .arg(Arg::with_name("NAME").required(true).help(
                                "The name of the eBPF program. The code will be created under src/<NAME>",
                            ))
                    )
                    .subcommand(
                        SubCommand::with_name("bindgen")
                            .about("Generates rust bindings from C headers")
                            .arg(Arg::with_name("HEADER").required(true).help(
                                "The C header file to generate bindings for",
                            ))
                            .arg(Arg::with_name("BINDGEN_ARGS").required(false).multiple(true).help(
                                "Extra arguments passed to bindgen",
                            ))
                    )
                    .subcommand(
                        SubCommand::with_name("build")
                            .about("Compiles the eBPF programs in the package")
                            .arg(Arg::with_name("TARGET_DIR").value_name("DIRECTORY").long("target-dir").help(
                                "Directory for all generated artifacts"
                            ))
                            .arg(Arg::with_name("FORCE_LOOP_UNROLL").long("force-loop-unroll").help(
                                "Ensure every loop is unrolled"
                            ))
                            .arg(Arg::with_name("NAME").required(false).multiple(true).help(
                                "The names of the programs to compile. When no names are specified, all the programs are built",
                            ))
                            .arg(Arg::with_name("FEATURES").value_name("FEATURES").short("f").long("features").required(false).multiple(true).help(
                                "The features of the programs to compile. `probes` features are added by default.",
                            ))
                    )
                    .subcommand(
                        SubCommand::with_name("load")
                            .about("Loads the specified eBPF program")
                            .arg(Arg::with_name("INTERFACE").value_name("INTERFACE").short("i").long("interface").help(
                                "Binds XDP programs to the given interface"
                            ))
                            .arg(Arg::with_name("UPROBE_PATH").value_name("PATH").short("u").long("uprobe-path").help(
                                "Attach uprobes to the given library/binary"
                            ))
                            .arg(Arg::with_name("PID").value_name("PID").short("p").long("pid").help(
                                "Attach uprobes to the given PID"
                            ))
                            .arg(Arg::with_name("PROGRAM").required(true).help(
                                "Loads the specified eBPF program and outputs all the events generated",
                            ))
                    ),
            )
            .get_matches();
    let matches = matches.subcommand_matches("bpf").unwrap();
    if let Some(m) = matches.subcommand_matches("new") {
        let path = m.value_of("PATH").map(PathBuf::from).unwrap();

        if let Err(e) = cargo_bpf::new(&path, m.value_of("NAME")) {
            clap::Error::with_description(&e.0, clap::ErrorKind::InvalidValue).exit()
        }
    }
    if let Some(m) = matches.subcommand_matches("add") {
        if let Err(e) = cargo_bpf::new_program(m.value_of("NAME").unwrap()) {
            clap::Error::with_description(&e.0, clap::ErrorKind::InvalidValue).exit()
        }
    }
    if let Some(m) = matches.subcommand_matches("bindgen") {
        let header = m.value_of("HEADER").map(PathBuf::from).unwrap();
        let extra_args = m
            .values_of("BINDGEN_ARGS")
            .map(|i| i.collect())
            .unwrap_or_else(Vec::new);
        if let Err(e) = cargo_bpf::bindgen::cmd_bindgen(&header, &extra_args[..]) {
            clap::Error::with_description(&e.0, clap::ErrorKind::InvalidValue).exit()
        }
    }
    if let Some(m) = matches.subcommand_matches("build") {
        let mut buildopt = BuildOptions::default();
        if let Some(v) = m.value_of("TARGET_DIR") {
            buildopt.target_dir = PathBuf::from(v);
        }
        buildopt.force_loop_unroll = m.is_present("FORCE_LOOP_UNROLL");
        let programs = m
            .values_of("NAME")
            .map(|i| i.map(String::from).collect())
            .unwrap_or_else(Vec::new);
        let mut features = m
            .values_of("FEATURES")
            .map(|i| i.map(String::from).collect())
            .unwrap_or_else(Vec::new);
        let probes_feature = "probes".to_owned();
        if !features.contains(&probes_feature) {
            features.push(probes_feature)
        }
        if let Err(e) = cargo_bpf::cmd_build(programs, &buildopt, &features) {
            clap::Error::with_description(&e.0, clap::ErrorKind::InvalidValue).exit()
        }
    }
    if let Some(m) = matches.subcommand_matches("load") {
        let program = m.value_of("PROGRAM").map(PathBuf::from).unwrap();
        let interface = m.value_of("INTERFACE");
        let uprobe_path = m.value_of("UPROBE_PATH");
        let uprobe_pid = m.value_of("PID").map(|p| p.parse::<i32>().unwrap());
        if let Err(e) = cargo_bpf::load(&program, interface, uprobe_path, uprobe_pid) {
            clap::Error::with_description(&e.0, clap::ErrorKind::InvalidValue).exit()
        }
    }
}
