// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/*!
Tracepoint probes.

# Example

Do something when a syscall is started.

```no_run
#![no_std]
#![no_main]
use redbpf_probes::tracepoint::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[tracepoint("raw_syscalls:syscall_enter")]
pub fn syscall_enter(args: *const core::ffi::c_void) {
    // do something here
    // ...
}
```
 */
pub mod prelude;
