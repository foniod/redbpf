RedBPF
======

![LICENSE](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)
[![CircleCI](https://circleci.com/gh/redsift/redbpf.svg?style=shield)](https://circleci.com/gh/redsift/redbpf)
[![element](https://img.shields.io/matrix/redbpf:rustch.at?server_fqdn=rustch.at)](https://app.element.io/#/room/!vCJcBZDeGUXaqSvPpL:rustch.at?via=rustch.at)

A Rust eBPF toolchain.

# Overview

The redbpf project is a collection of tools and libraries to build eBPF
programs using Rust. It includes:

- [redbpf](https://ingraind.org/api/redbpf/) - a user space library that can be
  used to load eBPF programs

- [redbpf-probes](https://ingraind.org/api/redbpf_probes/) - an idiomatic Rust
  API to write eBPF programs that can be loaded by the linux kernel

- [redbpf-macros](https://ingraind.org/api/redbpf_macros/) - companion crate to
  `redbpf-probes` which provides convenient procedural macros useful when
  writing eBPF programs

- [cargo-bpf](https://ingraind.org/api/cargo_bpf/) - a cargo subcommand for
  creating, building and debugging eBPF programs

# Requirements

In order to use redbpf you need LLVM 11 and the headers for the kernel you want
to target.

## Linux kernel

The **minimum kernel version supported is 4.19**. Kernel headers are discovered
automatically, or you can use the `KERNEL_SOURCE` environment variable to point
to a specific location. Building against a linux source tree is supported as
long as you run `make prepare` first.

## Installing dependencies on Debian based distributions

On Debian, Ubuntu and derivatives you can install the dependencies running:

	sudo apt-get -y install build-essential zlib1g-dev \
			llvm-11-dev libclang-11-dev linux-headers-$(uname -r)

If your distribution doesn't have LLVM 11, you can add the [official LLVM
APT repository](apt.llvm.org) to your `sources.list`.

## Installing dependencies on RPM based distributions

First ensure that your distro includes LLVM 11:

	yum info llvm-devel | grep Version
	Version      : 11.0.0

If you don't have vesion 11, you can get it from the Fedora 33 repository.

Then install the dependencies running:

	yum install clang llvm-devel zlib-devel kernel-devel

# Getting started

The easiest way to get started is using `cargo-bpf`, see the
[documentation](https://ingraind.org/api/cargo_bpf/) for more info.

[redbpf-tools](https://github.com/redsift/redbpf/tree/master/redbpf-tools) is a
`cargo-bpf` generated crate that includes simple examples you can use to
understand how to structure your programs.

Finally the [ingraind project](https://github.com/redsift/ingraind)
includes more concrete examples of redbpf programs.

# Building from source

After cloning the repository run:

    git submodule sync
    git submodule update --init

Install the dependencies as documented above, then run `cargo build` as usual.

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

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
	http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

# Contribution

This project is for everyone. We ask that our users and contributors
take a few minutes to review our [code of conduct](https://github.com/ingraind/project/blob/main/CODE_OF_CONDUCT.md).

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
