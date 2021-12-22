// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/*!
Rust API to write eBPF programs.

# Overview

`redbpf-probes` is part of the [redbpf](https://github.com/foniod/redbpf)
project. It provides an idiomatic Rust API to write programs that can be
compiled to eBPF bytecode and executed by the linux in-kernel eBPF virtual
machine.

This crate is expected to be used with the companion
[`redbpf-macros`](../../redbpf_macros/) crate - a collection of procedural
macros used to reduce the amount of boilerplate needed to produce eBPF
programs.

To streamline the process of working with eBPF programs even further, `redbpf`
also provides [`cargo-bpf`](../../cargo_bpf/) - a cargo subcommand to simplify
creating and building eBPF programs.

# Example

This is what `redbpf_probes` and `redbpf_macros` look like in action:

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

# Methods of generating rust bindings

Rust bindings for structs and enums of the Linux kernel are used by BPF
programs. redBPF provides two methods for generating the rust bindings.

1. Generate rust bindings from the Linux kernel headers that are pre-installed
in the system. The Linux kernel headers are located by
[`bpf_sys::headers`](../../bpf_sys/headers/index.html).

2. Generate rust bindings from `vmlinux.h`. It is generated on the spot by
[`bpf_sys::type_gen`](../../bpf_sys/type_gen/index.html). The vmlinux is an
image of the Linux kernel so all data types including internal structs and
enums can be dumped into C source code from the vmlinux image.

Users of redBPF can select a preferred method for generating rust bindings by
setting environment variables explained as below.

# Rules about method selection

In order to select a method between two methods, three environment variables
are involved: `KERNEL_SOURCE`, `KERNEL_VERSION` and `REDBPF_VMLINUX`.

Case 1. No setting

If none of the three environment variables are set, both two methods of
generating rust bindings will be tried. First, the method with the Linux kernel
headers is tried. If it fails, then the method with vmlinux is tried as
fallback.

Case 2. When `REDBPF_VMLINUX` is set

`REDBPF_VMLINUX` takes precedence over `KERNEL_SOURCE` and `KERNEL_VERSION`
environment variables. So the method of generating rust bindings of the Linux
kernel data structures for BPF programs is to vmlinux.h that is generated from
vmlinux image. No pre-installed kernel headers are required in this case.

Case 3. `REDBPF_VMLINUX` is not set, but any of `KERNEL_SOURCE` or
`KERNEL_VERSION` environment variables are set

The method of generating rust bindings of the Linux kernel data structures for
BPF programs is to use the kernel headers in the specified path. In this case
vmlinux is not required at all.

# Possible `REDBPF_VMLINUX` values

1. A path to the custom vmlinux file or raw BTF data file
- For example, `REDBPF_VMLINUX=/boot/my-vmlinux-5.11.0` specifies a path to vmlinux image.
- For example, `REDBPF_VMLINUX=/sys/kernel/btf/vmlinux` sets a path to raw BTF data file.

2. Special treatment for `REDBPF_VMLINUX=system`. If `system` is given, redBPF
tries to probe vmlinux from the well-known system paths and uses it

3. `REDBPF_VMLINUX` not set. The behavior of redBPF depends on whether
`KERNEL_SOURCE` and `KERNEL_VERSION` environment variables are given or not.
*/
#![deny(clippy::all)]
#![no_std]
pub mod bindings;
pub mod bpf_iter;
pub mod helpers;
pub mod kprobe;
pub mod maps;
pub mod net;
pub mod registers;
pub mod socket;
pub mod socket_filter;
pub mod sockmap;
pub mod tc;
pub mod uprobe;
pub mod xdp;
