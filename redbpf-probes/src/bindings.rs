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
custom bindings with `cargo bpf bindgen`](https://docs.rs/cargo_bpf/\*\/cargo_bpf).
*/
include!(concat!(env!("OUT_DIR"), "/gen_helpers.rs"));
