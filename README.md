RedBPF
======

![LICENSE](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)
[![CircleCI](https://circleci.com/gh/redsift/redbpf.svg?style=shield)](https://circleci.com/gh/redsift/redbpf)

A Rust eBPF toolchain.

# Overview

The RedBPF project is a collection of Rust libraries to work with eBPF
programs. It includes:

- `redbpf-probes` - an idiomatic Rust API to write programs that can be
compiled to eBPF bytecode and executed by the linux in-kernel eBPF virtual
machine.
    
    [![Documentation](https://img.shields.io/badge/docs-latest-red.svg)](https://ingraind.org/api/redbpf_probes/)

- `redbpf-macros` - companion crate to `redbpf-probes` which provides
procedural macros to reduce the amount of boilerplate needed to produce eBPF
programs.

    [![Documentation](https://img.shields.io/badge/docs-latest-red.svg)](https://ingraind.org/api/redbpf_macros/)

- `redbpf` - a user space library that can be used to parse and load eBPF
programs written using `redbpf-probes` and `redbpf-macros`.

    [![Documentation](https://img.shields.io/badge/docs-latest-red.svg)](https://ingraind.org/api/redbpf/)

- `cargo-bpf` - a cargo subcommand for creating, developing and building eBPF
programs in Rust using the RedBPF APIs.
    
    [![Documentation](https://img.shields.io/badge/docs-latest-red.svg)](https://ingraind.org/api/cargo_bpf/)

# Usage

The easiest way to get started is to install `cargo-bpf`, see the
[cargo bpf
documentation](https://ingraind.org/api/cargo_bpf/)
for more info.

The
[`rust-tools`](https://github.com/redsift/redbpf/tree/master/redbpf-tools)
directory also contains examples of using redbpf in real life.

To see how and what RedBPF can be used for, check out the [ingraind
project](https://github.com/redsift/ingraind/tree/v1.0).

# Requirements

In order to build some of the code here, you will need the following:

 * Linux 4.19+, with a build tree. The build tree is picked up from standard locations, or the `KERNEL_SOURCE` environment variable.
 * LLVM 9, or an LLVM version compatible with the Rust release you're using to build
 * The latest stable Rust compiler. We only promise to build with the latest stable and nightly compilers.

# Getting started

It's easiest to get started by installing `cargo-bpf` using cargo.

	cargo install cargo-bpf
	cargo bpf --help

If you would like to go the git way, clone this repository then make
sure you sync the git submodules necessary to build redbpf:

    git submodule sync
    git submodule update --init

Then install the dependencies for your distro before running the usual ritual.

	cargo build --release
    cargo install --path cargo-bpf

## Ubuntu

Install the following dependencies:

	apt-get install -y curl \
		wget \
		gnupg2 \
		software-properties-common \
		build-essential \
		clang-9 \
		llvm-9 \
		libelf-dev \
		linux-headers \
		ca-certificates{,-java}

## Fedora

	yum install -y clang-9.0.0 \
		llvm-9.0.0 \
		llvm-libs-9.0.0 \
		llvm-devel-9.0.0 \
		llvm-static-9.0.0 \
		kernel \
		kernel-devel \
		elfutils-libelf-devel \
		ca-certificates

# License

This repository contains code from other software in the following
directories, licensed under their own particular licenses:

 * `bpf-sys/libelf/*`: GPL2 + LGPL3 
 * `bpf-sys/bcc/*`: Apache2, public domain
 * `include/bpf_helpers.h` LGPL2 + BSD-2
 * `include/bpf_helper_defs.h`: LGPL2 + BSD-2
 * `bpf-sys/libbpf`: LGPL2 + BSD-2
 
Where '+' means they are dual licensed.

RedBPF and its components, unless otherwise stated, are licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

# Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
