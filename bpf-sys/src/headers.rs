// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::env;
use std::path::{Path, PathBuf};

use crate::uname;

struct KernelHeaders {
    source: PathBuf,
    build: PathBuf
}

pub fn prefix_kernel_headers(headers: &[&str]) -> Option<Vec<String>> {
    let KernelHeaders { source, build } = kernel_headers_path()?;
    let mut ret: Vec<String> = Vec::new();
    for header in headers {
        if header.contains("generated") {
            let path = build.join(header);
            ret.push(path.to_string_lossy().into());
            if header.ends_with("generated") {
                ret.push(path.parent().unwrap().to_string_lossy().into());
            }
        } else {
            ret.push(source.join(header).to_string_lossy().into());
        }
    }
    Some(ret)
}

fn kernel_headers_path() -> Option<KernelHeaders> {
    env::var("KERNEL_SOURCE")
    .ok()
    .map(|s| {
        let path = PathBuf::from(s);
        KernelHeaders {
            source: path.clone(),
            build: path
        }
    })
    .or_else(lib_modules_kernel_headers)
}

fn lib_modules_kernel_headers() -> Option<KernelHeaders> {
    if let Some(version) = kernel_version() {
        let path = Path::new("/lib/modules").join(version);
        let mut build = path.join("build");
        let source = path.join("source");
        let kconfig = "include/linux/kconfig.h";
        let source = match (source.join(kconfig).is_file(), build.join(kconfig).is_file()) {
            (true, _) => source,
            (false, true) => build.clone(),
            _ => return None
        };
        if !build.join("include/generated/uapi/linux/version.h").is_file() {
            build = source.clone()
        };

        return Some(KernelHeaders {
            source,
            build
        });
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