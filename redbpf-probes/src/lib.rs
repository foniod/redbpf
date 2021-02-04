// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/*!
Rust API to write eBPF programs.

# Overview

`redbpf-probes` is part of the [redbpf](https://github.com/redsift/redbpf)
project. It provides an idiomatic Rust API to write programs that can be
compiled to eBPF bytecode and executed by the linux in-kernel eBPF virtual
machine.

This crate is expected to be used with the companion
[`redbpf-macros`](https://ingraind.org/api/redbpf_macros/) crate - a
collection of procedural macros used to reduce the amount of boilerplate
needed to produce eBPF programs.

To streamline the process of working with eBPF programs even further,
`redbpf` also provides [`cargo-bpf`](https://ingraind.org/api/cargo_bpf/) -
a cargo subcommand to simplify creating and building eBPF programs.

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

*/
#![deny(clippy::all)]
#![no_std]
pub mod bindings;
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
