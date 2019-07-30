use lazy_static::*;
use regex::Regex;
use std::env;
use std::ffi::OsString;
use std::process::Command;
use std::path::Path;

use crate::build::Error;
use crate::uname;

pub const KERNEL_HEADERS: [&'static str; 6] = [
    "arch/x86/include",
    "arch/x86/include/generated",
    "include",
    "arch/include/generated/uapi",
    "arch/x86/include/uapi",
    "include/uapi",
];

pub fn headers() -> Result<Vec<OsString>, Error> {
    let mut headers_base_path = env_kernel_path().or_else(|_| lib_modules_kernel_path())?;
    if !headers_base_path.ends_with("/") {
        headers_base_path.push('/');
    }

    Ok(KERNEL_HEADERS
        .iter()
        .map(|h| OsString::from(format!("-I{}{}", headers_base_path, h)))
        .collect())
}

pub fn env_kernel_path() -> Result<String, Error> {
    env::var("KERNEL_SOURCE").map_err(|_| Error::KernelHeadersNotFound)
}

pub fn lib_modules_kernel_path() -> Result<String, Error> {
    if let Ok(u) = uname::uname() {
        let release = uname::to_str(&u.release);
        let path = format!("/lib/modules/{}/build/", release);
        if Path::new(&format!("{}Kconfig", path)).is_file() {
            return Ok(path);
        }

    }

    Err(Error::KernelHeadersNotFound)
}
