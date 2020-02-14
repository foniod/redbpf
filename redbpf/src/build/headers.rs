// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::build::Error;
use bpf_sys::headers::prefix_kernel_headers;

#[cfg(target_arch = "x86_64")]
pub const KERNEL_HEADERS: [&str; 7] = [
    "arch/x86/include",
    "arch/x86/include/generated",
    "include",
    "include/generated",
    "arch/include/generated/uapi",
    "arch/x86/include/uapi",
    "include/uapi",
];

#[cfg(target_arch = "aarch64")]
pub const KERNEL_HEADERS: [&str; 8] = [
    "arch/arm64/include",
    "arch/arm64/include/generated",
    "include",
    "include/generated",
    "arch/include/generated/uapi",
    "arch/arm64/include/uapi",
    "arch/arm64/include/generated/uapi",
    "include/uapi",
];

pub fn kernel_headers() -> Result<Vec<String>, Error> {
    prefix_kernel_headers(&KERNEL_HEADERS).ok_or(Error::KernelHeadersNotFound)
}
