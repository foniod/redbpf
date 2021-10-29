RedBPF
======

![LICENSE](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)
[![element](https://img.shields.io/matrix/redbpf:rustch.at?server_fqdn=rustch.at)](https://app.element.io/#/room/!vCJcBZDeGUXaqSvPpL:rustch.at?via=rustch.at)

A Rust eBPF toolchain.

# Overview

The redbpf project is a collection of tools and libraries to build eBPF
programs using Rust. It includes:

- [redbpf](https://foniod.org/api/redbpf/) - a user space library that can be
  used to load eBPF programs or access eBPF maps.

- [redbpf-probes](https://foniod.org/api/redbpf_probes/) - an idiomatic Rust
  API to write eBPF programs that can be loaded by the linux kernel

- [redbpf-macros](https://foniod.org/api/redbpf_macros/) - companion crate to
  `redbpf-probes` which provides convenient procedural macros useful when
  writing eBPF programs. For example, `#[map]` for defining a map, `#[kprobe]`
  for defining a BPF program that can be attached to kernel functions.

- [cargo-bpf](https://foniod.org/api/cargo_bpf/) - a cargo subcommand for
  creating, building and debugging eBPF programs

# Requirements

In order to use redBPF, you need
- one of LLVM 13, LLVM 12 or LLVM 11 installed in the system
- either the Linux kernel headers or `vmlinux`, you want to target

Currently LLVM 12 is used as a default version when compiling BPF programs, but
you can specify other LLVM versions as follows:
- `cargo build --no-default-features --features llvm13`
- `cargo build --no-default-features --features llvm11`

## Valid combinations of rust and LLVM versions

`rustc` uses its own version of LLVM. But RedBPF also requires LLVM installed
in the system. In order to compile BPF programs, RedBPF makes use of `rustc` to
emit bitcode first and then parses and optimizes the bitcode by calling LLVM
API directly. Thus, two versions of LLVM are used while compiling BPF programs.

- the version of LLVM that `rustc` depends on
- the version of LLVM which is installed in system

Two versions should match.

First RedBPF executes `rustc` to emit bitcode and second it calls LLVM API to
handle the resulting bitcode. Normally LLVM is likely to support backward
compatibility for intermediate representation. Thus, it is okay to use `rustc`
that depends on the LLVM version that is equal to or less than system LLVM.


| Rust version | LLVM version of the Rust | Valid system LLVM version |
|:-------------|:------------------------:|:--------------------------|
| 1.56 ~       | LLVM 13                  | LLVM 13                   |
| 1.52 ~ 1.55  | LLVM 12                  | LLVM 13, LLVM 12          |
| 1.48 ~ 1.51  | LLVM 11                  | LLVM 13, LLVM 12, LLVM 11 |

* The minimum rust version for compiling `redbpf` is Rust 1.48

## Linux kernel

The **minimum kernel version supported is 4.19**. Kernel headers are discovered
automatically, or you can use the `KERNEL_SOURCE` environment variable to point
to a specific location. Building against a linux source tree is supported as
long as you run `make prepare` first.

**NOTE** for compiling BPF programs **inside containers**.  
You need to specify `KERNEL_SOURCE` or `KERNEL_VERSION` environment variables
that indicate kernel headers. The headers should be found inside the
container. For example, inside the Ubuntu 21.04 container that contains the
Linux `5.11.0-25-generic` kernel headers, you should specify `KERNEL_VERSION`
environment variable as follows:

```console
# KERNEL_VERSION=5.11.0-25-generic cargo build --examples
```

If your container has `vmlinux`, you can specify it instead of the Linux kernel
headers.

```console
# REDBPF_VMLINUX=/boot/vmlinux cargo build --examples
```

See, [build-test.sh](./scripts/build-test.sh) for more information.

## Installing dependencies on Debian based distributions

On Debian, Ubuntu and derivatives you can install the dependencies running:

	sudo apt-get -y install build-essential zlib1g-dev \
			llvm-12-dev libclang-12-dev linux-headers-$(uname -r) \
			libelf-dev

If your distribution doesn't have LLVM 12, you can add the [official LLVM
APT repository](https://apt.llvm.org) to your `sources.list`.

## Installing dependencies on RPM based distributions

First ensure that your distro includes LLVM 12:

	yum info llvm-devel | grep Version
	Version      : 12.0.0

If you don't have vesion 12, you can get it from the Fedora 34 repository.

Then install the dependencies running:

	yum install clang llvm-devel zlib-devel kernel-devel

## Build images

You can refer to `Dockerfile`s that are ready for building redBPF and foniod:
[build-images](https://github.com/foniod/build-images)

# Getting started

The easiest way to get started is reading a [basic tutorial](TUTORIAL.md).

You can find several examples in this [directory](examples/). All example
programs are splitted into two parts: `example-probes` and
`example-userspace`. `example-probes` contains BPF programs that execute in
kernel context. `example-userspace` includes userspace programs that load BPF
programs into kernel space and communicate with BPF programs through BPF maps.

Also see [documentation](https://foniod.org/api/cargo_bpf/) of `cargo-bpf`. It
provides a CLI tool for compiling BPF programs easily.

[redbpf-tools](https://github.com/foniod/redbpf/tree/master/redbpf-tools) is a
`cargo-bpf` generated crate that includes simple examples you can use to
understand how to structure your programs.

Finally, check the [foniod project](https://github.com/foniod/foniod) that
includes more advanced, concrete production ready examples of redbpf programs.

# Building from source

After cloning the repository run:

    git submodule sync
    git submodule update --init

Install the dependencies as documented above, then run `cargo build` as usual.

# License

This repository contains code from other software in the following
directories, licensed under their own particular licenses:

 * `bpf-sys/libbpf`: LGPL2 + BSD-2

Where '+' means they are dual licensed.

RedBPF and its components, unless otherwise stated, are licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
	http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

# Contribution

This project is for everyone. We ask that our users and contributors
take a few minutes to review our [code of conduct](https://github.com/foniod/project/blob/main/CODE_OF_CONDUCT.md).

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

For further advice on getting started, please consult the [Contributor's
Guide](https://github.com/foniod/project/blob/main/CONTRIBUTING.md). Please
note that all contributions MUST contain a [Developer Certificate of
Origin](https://github.com/foniod/project/blob/developer-certificate-of-origin/CONTRIBUTING.md#developer-certificate-of-origin)
sign-off line.
