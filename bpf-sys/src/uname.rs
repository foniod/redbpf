// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::ffi::CStr;
use std::fs;
use std::mem;
use std::os::raw::c_char;
use std::str::from_utf8_unchecked;
use std::str::FromStr;

#[allow(clippy::result_unit_err)]
pub fn uname() -> Result<::libc::utsname, ()> {
    let mut uname = unsafe { mem::zeroed() };
    let res = unsafe { ::libc::uname(&mut uname) };
    if res < 0 {
        Err(())
    } else {
        Ok(uname)
    }
}

#[inline]
pub fn get_kernel_internal_version() -> Option<u32> {
    let version = if let Ok(version) = fs::read_to_string("/proc/version_signature") {
        parse_version_signature(&version.trim())?
    } else {
        to_str(&uname().ok()?.release).into()
    };

    parse_version(&version).map(|(major, minor, patch)| major << 16 | minor << 8 | patch)
}

#[allow(clippy::result_unit_err)]
#[inline]
pub fn get_fqdn() -> Result<String, ()> {
    let uname = uname()?;
    let mut hostname = to_str(&uname.nodename).to_string();
    let domainname = to_str(&uname.domainname);
    if domainname != "(none)" {
        hostname.push('.');
        hostname.push_str(domainname);
    }

    Ok(hostname)
}

#[inline]
pub fn to_str(bytes: &[c_char]) -> &str {
    unsafe { from_utf8_unchecked(CStr::from_ptr(bytes.as_ptr()).to_bytes()) }
}

fn parse_version_signature(signature: &str) -> Option<String> {
    let parts: Vec<_> = signature.split(' ').collect();
    if parts.len() != 3 {
        return None;
    }

    parts.last().map(|v| <&str>::clone(v).into())
}

fn parse_version(version: &str) -> Option<(u32, u32, u32)> {
    if let Some(version) = version.splitn(2, '-').next() {
        if let Some(version) = version.splitn(2, '+').next() {
            let parts: Vec<_> = version
                .splitn(4, '.')
                .filter_map(|v| u32::from_str(v).ok())
                .collect();
            if parts.len() < 3 {
                return None;
            }
            return Some((parts[0], parts[1], parts[2]));
        }
    }

    None
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_version() {
        assert_eq!(parse_version("5.10.93.2-microsoft-standard-WSL2"), Some((5, 10, 93)));
        assert_eq!(parse_version("4.15.18"), Some((4, 15, 18)));
        assert_eq!(parse_version("4.15.1-generic"), Some((4, 15, 1)));
        assert_eq!(parse_version("4.15.1-generic-foo"), Some((4, 15, 1)));
        assert_eq!(parse_version("4.14.138+"), Some((4, 14, 138)));
        assert_eq!(parse_version("4.3.2.1"), None);
        assert_eq!(parse_version("4.2.foo"), None);
        assert_eq!(parse_version("4.2."), None);
        assert_eq!(parse_version("4.2"), None);
        assert_eq!(parse_version("foo"), None);
        assert_eq!(parse_version(""), None);
    }

    #[test]
    fn test_parse_version_signature() {
        assert_eq!(
            parse_version_signature("Ubuntu 4.15.0-55.60-generic 4.15.18"),
            Some("4.15.18".into())
        );
        assert_eq!(
            parse_version_signature("Ubuntu 4.15.0-55.60-generic 4.15.18 foo"),
            None
        );
        assert_eq!(parse_version_signature("Ubuntu 4.15.0-55.60-generic"), None);
    }
}
