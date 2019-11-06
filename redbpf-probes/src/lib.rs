/*!
Rust API to write eBPF programs.

# Overview

`redbpf-probes` is part of the [redbpf](https://github.com/redsift/redbpf)
project. It provides an idiomatic Rust API to write programs that can be
compiled to eBPF bytecode and executed by the linux in-kernel eBPF virtual
machine.

This crate is expected to be used with the companion
[`redbpf-macros`](https://docs.rs/redbpf_macros\/\*\/redbpf_macros/) crate - a
collection of procedural macros used to reduce the amount of boilerplate
needed to produce eBPF programs.

To streamline the process of working with eBPF programs even further,
`redbpf` also provides [`cargo-bpf`](https://docs.rs/cargo_bpf\/\*\/cargo_bpf/) -
a cargo subcommand to simplify creating and building eBPF programs.

# Example

This is what `redbpf_probes` and `redbpf_macros` look like in action:

```
#![no_std]
#![no_main]
use redbpf_probes::bindings::*;
use redbpf_probes::xdp::{XdpAction, XdpContext};
use redbpf_macros::{program, xdp};

program!(0xFFFFFFFE, "GPL");

#[xdp]
pub extern "C" fn block_port_80(ctx: XdpContext) -> XdpAction {
    if let Some(transport) = ctx.transport() {
        if transport.dest() == 80 {
            return XdpAction::Drop;
        }
    }

    XdpAction::Pass
}
```

*/
#![no_std]
pub mod bindings;
pub mod maps;
pub mod xdp;
