// Copyright 2022 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/*!
Tracepoint probes.

[Tracepoints](https://www.kernel.org/doc/Documentation/trace/tracepoints.txt) are similar to [kprobes](super::kprobe), but without the ability
to read CPU registers. Instead a tracepoint receives a fixed set of input arguments
depending on the tracepoint. This makes tracepoints more stable across kernel versions
and is less architecture-specific. However tracepoint probes can only be attached
to a predetermined set of kernel functions (unlike kprobes that can be attached almost anywhere).

There is no explicit return type for tracepoints (i.e. no kretprobe equivalent), but many kernel functions
have tracepoints defined at function entry and exit.

# Example
Do something when ioctl system call is triggered. See the examples directory for a more
complete scenario.

```no_run
#![no_std]
#![no_main]
use redbpf_probes::tracepoint::prelude::*;
program!(0xFFFFFFFE, "GPL");
#[tracepoint("syscalls:sys_enter_ioctl")]
pub fn sys_enter_ioctl(args: *const c_void) {
    // do something here
    // ...
}
```
 */
pub mod prelude;
