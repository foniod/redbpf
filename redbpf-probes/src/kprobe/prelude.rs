// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! The Kprobe Prelude
//!
//! The purpose of this module is to alleviate imports of the common kprobe types
//! by adding a glob import to the top of kprobe programs:
//!
//! ```
//! use redbpf_probes::kprobe::prelude::*;
//! ```
pub use crate::bindings::*;
pub use crate::helpers::*;
pub use crate::maps::*;
pub use crate::registers::*;
pub use cty::*;
pub use redbpf_macros::{kprobe, kretprobe, map, printk, program};
