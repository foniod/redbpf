RedBPF
======

[![LICENSE](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)
[![CircleCI](https://circleci.com/gh/redsift/redbpf.svg?style=shield)](https://circleci.com/gh/redsift/redbpf)

A Rust eBPF toolchain.

# Overview

The RedBPF project is a collection of Rust libraries to work with eBPF
programs. It includes:

- `redbpf-probes` - an idiomatic Rust API to write programs that can be
compiled to eBPF bytecode and executed by the linux in-kernel eBPF virtual
machine.
    
    [![Documentation](https://img.shields.io/badge/docs-latest-red.svg)](https://redsift.github.io/rust/redbpf/doc/redbpf_probes/)

- `redbpf-macros` - companion crate to `redbpf-probes` which provides
procedural macros to reduce the amount of boilerplate needed to produce eBPF
programs.

    [![Documentation](https://img.shields.io/badge/docs-latest-red.svg)](https://redsift.github.io/rust/redbpf/doc/redbpf_macros/)

- `redbpf`, a user space library that can be used to parse and load eBPF
programs written using `redbpf-probes` and `redbpf-macros`.

    [![Documentation](https://img.shields.io/badge/docs-latest-red.svg)](https://redsift.github.io/rust/redbpf/doc/redbpf/)

- `cargo-bpf`, a cargo subcommand for creating, developing and building eBPF
programs in Rust using the RedBPF APIs.
    
    [![Documentation](https://img.shields.io/badge/docs-latest-red.svg)](https://redsift.github.io/rust/redbpf/doc/cargo_bpf/)

# Usage

The easiest way to get started is to install `cargo-bpf`, see the [cargo bpf documentation](https://redsift.github.io/rust/redbpf/doc/cargo_bpf/) for more info. 

To see how and what RedBPF can be used for, check out the [ingraind project](https://github.com/redsift/ingraind/tree/v1.0).

## License

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

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
