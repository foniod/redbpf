// Copyright 2021 Junyeong Jeong <rhdxmr@gmail.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
/*!
Contexts passed to BPF iterators
 */

use crate::bindings::*;

/// A structure that wraps `bpf_iter__task`
///
/// Currently `bpf_iter__task` is not provided to userspace by the Linux kernel
/// headers. So it is likely to change its definition in the future. Thus we'd
/// rather not add methods that rely on the `bpf_iter__task` to
/// `TaskIterContext` for now.
pub struct TaskIterContext {
    pub ctx: *mut bpf_iter__task,
}
