// Copyright 2021 Junyeong Jeong <rhdxmr@gmail.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
/*!
BPF iterators
*/

/// Possible types that a BPF program of BPF iterators can return
pub enum BPFIterAction {
    /// Okay
    Ok,
    /// Retry the same object
    Retry,
}

pub mod context;

pub mod prelude {
    pub use super::context::*;
    pub use super::*;
    pub use crate::bindings::*;
    pub use crate::helpers::*;
    pub use crate::maps::*;
    pub use redbpf_macros::{map, printk, program, task_iter};
}
