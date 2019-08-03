use std::env;
use std::path::Path;

use crate::uname;

pub fn kernel_headers_path() -> Option<String> {
    env::var("KERNEL_SOURCE").ok().or_else(lib_modules_kernel_path)
}

fn lib_modules_kernel_path() -> Option<String> {
    if let Ok(u) = uname::uname() {
        let release = uname::to_str(&u.release);
        let path = format!("/lib/modules/{}/build/", release);
        if Path::new(&format!("{}Kconfig", path)).is_file() {
            return Some(path);
        }

    }

    None
}