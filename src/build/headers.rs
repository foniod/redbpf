use std::path::PathBuf;

use crate::build::Error;
use bpf_sys::headers::kernel_headers_path;

pub const KERNEL_HEADERS: [&'static str; 6] = [
    "arch/x86/include",
    "arch/x86/include/generated",
    "include",
    "arch/include/generated/uapi",
    "arch/x86/include/uapi",
    "include/uapi",
];

pub fn kernel_headers() -> Result<Vec<String>, Error> {
    let path = PathBuf::from(kernel_headers_path().ok_or(Error::KernelHeadersNotFound)?);
    Ok(KERNEL_HEADERS
        .iter()
        .map(|dir| String::from(path.join(dir).to_str().unwrap()))
        .collect())
}