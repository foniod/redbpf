use std::env;
use std::path::Path;

use crate::uname;

pub fn kernel_headers_path() -> Option<String> {
    env::var("KERNEL_SOURCE").ok().or_else(lib_modules_kernel_path)
}

fn lib_modules_kernel_path() -> Option<String> {
    if let Some(version) = kernel_version() {
        let path = format!("/lib/modules/{}/build/", version);
        if Path::new(&format!("{}Kconfig", path)).is_file() {
            return Some(path);
        }
    }

    None
}

fn kernel_version() -> Option<String> {
    env::var("KERNEL_VERSION").ok().or_else(|| {
        uname::uname().ok().map(|u| {
            uname::to_str(&u.release).to_string()
        })
    })
}