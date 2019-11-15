// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(clippy::all)]

extern crate zero;
pub mod headers;
pub mod perf_reader;
pub mod uname;

include!(concat!(env!("OUT_DIR"), "/libbpf_bindings.rs"));
include!(concat!(env!("OUT_DIR"), "/libbpf_map_def.rs"));
unsafe impl ::zero::Pod for bpf_map_def {}
unsafe impl ::zero::Pod for bpf_insn {}
