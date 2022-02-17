// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

pub mod headers;
pub mod uname;

pub mod type_gen;

// FIXME: Remove libbpf_bindings in favor of libbpf-sys
mod libbpf_bindings {
    #![allow(non_camel_case_types)]
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/libbpf_bindings.rs"));
}
