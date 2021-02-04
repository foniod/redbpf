// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/*!
User-space probes.

UProbes are hooks on the entry (uprobe) or exit (uretprobe) of user-space functions.
For an overview of UProbes and how they work, see
<https://www.kernel.org/doc/Documentation/trace/uprobetracer.txt>.

# Example

Do something when the OpenSSL `SSL_write` function is called:

```no_run
use redbpf_probes::uprobe::prelude::*;

#[uprobe]
fn SSL_write(regs: Registers) {
    let buf = regs.parm2() as *const c_void;
    let num = regs.parm3() as i32;
    // do something with the buffer
    // ...
}

```

*/

pub mod prelude;
