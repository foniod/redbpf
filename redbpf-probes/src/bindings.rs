// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/*!
Generated, low level bindings to bpf types and constants.

This module contains `bindgen` generated bindings to the types defined and
used by [`bpf
helpers`](https://github.com/redsift/libbpf/blob/master/src/bpf_helper_defs.h)
and other types that are commonly used when writing eBPF programs such as
`kprobes` and `XDP` programs.

Whenever possible, you should prefer higher level types provided by the
`maps` and `xdp` modules.

If your probe needs types not exposed by this module, you can [generate your
custom bindings with `cargo bpf bindgen`](https://ingraind.org/api/cargo_bpf/).
*/
include!(concat!(env!("OUT_DIR"), "/gen_bindings.rs"));
