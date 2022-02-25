RedBPF
======

![LICENSE](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)
[![element](https://img.shields.io/matrix/redbpf:rustch.at?server_fqdn=rustch.at)](https://app.element.io/#/room/!vCJcBZDeGUXaqSvPpL:rustch.at?via=rustch.at)

A Rust eBPF toolchain.

# Overview

The redbpf project is a collection of tools and libraries to build eBPF
programs using Rust. It includes:

- [redbpf](https://docs.rs/redbpf/latest/redbpf/) - a user space library that can be
  used to load eBPF programs or access eBPF maps.

- [redbpf-probes](https://docs.rs/redbpf-probes/latest/redbpf_probes/) - an idiomatic Rust
  API to write eBPF programs that can be loaded by the linux kernel

- [redbpf-macros](https://docs.rs/redbpf-macros/latest/redbpf_macros/) - companion crate to
  `redbpf-probes` which provides convenient procedural macros useful when
  writing eBPF programs. For example, `#[map]` for defining a map, `#[kprobe]`
  for defining a BPF program that can be attached to kernel functions.

- [cargo-bpf](./cargo-bpf/src/main.rs) - a cargo subcommand for creating,
  building and debugging eBPF programs

# Features

- Allows users to write both BPF programs and userspace programs in Rust
- Offers many BPF map types
  1. `HashMap`, `PerCpuHashMap`, `LruHashMap`, `LruPerCpuHashMap`, `Array`,
     `PerCpuArray`, `PerfMap`, `TcHashMap`, `StackTrace`, `ProgramArray`,
     `SockMap`, `DevMap`
- Offers several BPF program types
  1. `KProbe`, `KRetProbe`, `UProbe`, `URetProbe`, `SocketFilter`, `XDP`,
     `StreamParser`, `StreamVerdict`, `TaskIter`, `SkLookup`
- Provides attribute macros that define various kind of BPF programs and BPF
  maps in a declarative way.
  1. `#[kprobe]`, `#[kretprobe]`, `#[uprobe]`, `#[uretprobe]`, `#[xdp]`,
     `#[tc_action]`, `#[socket_filter]`, `#[stream_parser]`,
     `#[stream_verdict]`, `#[task_iter]`
  2. `#[map]`
- Can generate Rust bindings from the Linux kernel headers or from the BTF of
  `vmlinux`
- Provides API for both BPF programs and userspace programs to help users write
  Rust idiomatic code
- Supports BTF for maps
- Supports pinning maps and loading maps from pins
- Supports BPF iterator for `task`
- Enables users to write BPF programs for `tc` action and RedBPF compiles the
  programs into the ELF object file that is compatible with `tc` command
- Provides wrappers of BPF helper functions
- Offers asynchronous stream of `perf events` for userspace programs
- Supports multiple versions of LLVM
- Shows BPF verifier logs when loading BPF programs, BPF maps or BTF fails
- Has several example programs that are separated into two parts: BPF programs
  and userspace programs

# Install

## Requirements

`LLVM` is required in your build system to compile BPF bytecode using RedBPF.

- **LLVM 13**  
  It is needed to compile BPF bytecode.

- One of the followings:
  1. The Linux kernel headers
  2. `vmlinux`, the Linux kernel image that contains `.BTF` section
  3. Raw BTF data i.e. `/sys/kernel/btf/vmlinux`  
  These are needed to generate Rust bindings of the data structures of the Linux kernel.

### On Ubuntu 20.04 LTS

Install LLVM 13 and the Linux kernel headers
```console
# apt-get update \
  && apt-get -y install \
       wget \
       build-essential \
       software-properties-common \
       lsb-release \
       libelf-dev \
       linux-headers-generic \
       pkg-config \
  && wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 13 && rm -f ./llvm.sh
# llvm-config-13 --version | grep 13
```

### On Fedora 35

Install LLVM 13 and the Linux kernel headers
```console
# dnf install -y \
    clang-13.0.0 \
	llvm-13.0.0 \
	llvm-libs-13.0.0 \
	llvm-devel-13.0.0 \
	llvm-static-13.0.0 \
	kernel \
	kernel-devel \
	elfutils-libelf-devel \
	make \
    pkg-config \
    zstd
# llvm-config --version | grep 13
```

### On Arch Linux

Install LLVM 13 and the Linux kernel headers

```console
# pacman --noconfirm -Syu \
  && pacman -S --noconfirm \
       llvm \
       llvm-libs \
       libffi \
       clang \
       make \
       pkg-config \
       linux-headers \
       linux
# llvm-config --version | grep -q '^13'
```

### Building LLVM from source

If your Linux distro does not support the latest LLVM as pre-built packages
yet, you may build LLVM from the LLVM source code.

```console
$ tar -xaf llvm-13.0.0.src.tar.xz
$ mkdir -p llvm-13.0.0.src/build
$ cd llvm-13.0.0.src/build
$ cmake .. -DCMAKE_INSTALL_PREFIX=$HOME/llvm-13-release -DCMAKE_BUILD_TYPE=Release
$ cmake --build . --target install
```

Then you can use your LLVM by specifying the custom installation path when
installing `cargo-bpf` or building RedBPF like this:

```console
$ LLVM_SYS_130_PREFIX=$HOME/llvm-13-release/ cargo install cargo-bpf
$ LLVM_SYS_130_PREFIX=$HOME/llvm-13-release/ cargo build
```

Make sure correct `-DCMAKE_BUILD_TYPE` is specified. Typically `Debug` type is
not recommended if you are not going to debug LLVM itself.


## Installing `cargo-bpf`

`cargo-bpf` is a command line tool for compiling BPF program written in Rust
into BPF bytecode.

```console
$ cargo install cargo-bpf
$ cargo bpf --version
```

You can learn how to use this from [tutorial](TUTORIAL.md).

## Building RedBPF from source

If you want to build RedBPF from source to fix something, you can do as follows:

```console
$ git clone https://github.com/foniod/redbpf.git
$ cd redbpf
$ git submodule sync
$ git submodule update --init
$ cargo build
$ cargo build --examples
```

# Getting started

The easiest way to get started is reading a [basic tutorial](TUTORIAL.md).

You can find several examples in this [directory](examples/). All example
programs are splitted into two parts: `example-probes` and
`example-userspace`. `example-probes` contains BPF programs that execute in
kernel context. `example-userspace` includes userspace programs that load BPF
programs into kernel space and communicate with BPF programs through BPF maps.

See also [documentation](./cargo-bpf/src/main.rs) of `cargo-bpf`. It provides a
CLI tool for compiling BPF programs easily.

[redbpf-tools](https://github.com/foniod/redbpf/tree/master/redbpf-tools) is a
`cargo-bpf` generated crate that includes simple examples you can use to
understand how to structure your programs.

Finally, check the [foniod project](https://github.com/foniod/foniod) that
includes more advanced, concrete production ready examples of redbpf programs.

## Valid combinations of Rust and LLVM versions

`rustc` is linked to its own bundled version of LLVM. And `cargo-bpf` also uses
its own version of LLVM that is statically linked into `cargo-bpf` itself. But
note that users can control the LLVM version of `cargo-bpf` by providing other
versions of LLVM in their system when building `cargo-bpf`.

Why do we care about two LLVM versions?  
Because both two versions of LLVMs are all participating in the process of
compiling BPF programs.

1. RedBPF executes `rustc` to compile BPF programs. And `rustc` calls LLVM
   functions to emit LLVM bitcode.
2. And then RedBPF parses the emitted LLVM bitcode to convert it into BPF
   bytecode. To do so, it calls LLVM functions that are statically linked into
   `cargo-bpf`.

What happens if LLVM of `rustc` is newer than the LLVM of `cargo-bpf`? You
already feel it. BAM!  Typically older version of LLVM can not properly handle
the bitcode that is generated by newer version of LLVM. i.e., `cargo-bpf` with
older LLVM can not properly handle what `rustc` with newer LLVM emits.

What happens if LLVM of `rustc` is older than the LLVM of `cargo-bpf`? Normally
LLVM is likely to support backward compatibility for intermediate
representation.

Let's put things together.

There are two LLVM versions involved in compiling BPF programs:

1. the version of LLVM**(1)** that `cargo-bpf` is statically linked to when
   `cargo-bpf` is built.
2. the version of LLVM**(2)** that `rustc` is linked to.

*And*, **(1)** should be greater than or equal to **(2)**.  
*It is the best case if `(1) == (2)` but `(1) > (2)` is also okay.*

| Rust version | LLVM version of the rustc | Valid LLVM version of system |
|:-------------|:-------------------------:|:-----------------------------|
| 1.56 ~       | LLVM 13                   | LLVM 13 and newer            |

## Docker images for RedBPF build test

You can refer to various `Dockerfile`s that contain minimal necessary packages
to build `RedBPF` properly: [Dockerfiles for
RedBPF](https://github.com/foniod/build-images/redbpf)

These docker images are pushed to ghcr.io:

x86_64
- `ghcr.io/foniod/redbpf-build:latest-x86_64-ubuntu21.04`
- `ghcr.io/foniod/redbpf-build:latest-x86_64-fedora35`
- `ghcr.io/foniod/redbpf-build:latest-x86_64-alpine3.15`
- `ghcr.io/foniod/redbpf-build:latest-x86_64-debian11`
- `ghcr.io/foniod/redbpf-build:latest-x86_64-archlinux`

ARM64
- `ghcr.io/foniod/redbpf-build:latest-aarch64-ubuntu21.04`
- `ghcr.io/foniod/redbpf-build:latest-aarch64-fedora35`
- `ghcr.io/foniod/redbpf-build:latest-aarch64-alpine3.15`
- `ghcr.io/foniod/redbpf-build:latest-aarch64-debian11`

See [build-test.yml](.github/workflows/build-test.yml) for more information.
It describes build tests of RedBPF that run inside docker containers.

If you want docker images that are prepared to build `foniod` then refer to
this: [Dockerfiles for foniod](https://github.com/foniod/build-images)

## Note for building RedBPF inside docker containers

You need to specify `KERNEL_SOURCE` or `KERNEL_VERSION` environment variables
that indicate kernel headers. The headers should be found inside the
container. For example, inside the Ubuntu 21.04 container that contains the
Linux `5.11.0-25-generic` kernel headers, you should specify `KERNEL_VERSION`
environment variable as follows:

```console
# KERNEL_VERSION=5.11.0-25-generic cargo build --examples
```

If your container has `vmlinux`, the Linux kernel image that contains `.BTF`
section in it, you can specify it instead of the Linux kernel headers.

```console
# REDBPF_VMLINUX=/boot/vmlinux cargo build --examples
```

See [build-test.yml](.github/workflows/build-test.yml) for more information.
It describes build tests of RedBPF that run inside docker containers.

## Supported Architectures

Currently, `x86-64` and `aarch64` architectures are supported.


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
