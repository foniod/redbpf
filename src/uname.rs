use crate::error::{LoadError, Result};
use std::ffi::CStr;
use std::mem;
use std::str::from_utf8_unchecked;
use std::str::FromStr;

pub fn uname() -> Result<::libc::utsname> {
    let mut uname = unsafe { mem::zeroed() };
    let res = unsafe { ::libc::uname(&mut uname) };
    if res < 0 {
        Err(LoadError::Uname)
    } else {
        Ok(uname)
    }
}

#[inline]
pub fn get_kernel_internal_version() -> Result<u32> {
    let uname = uname()?;

    let urelease = to_str(&uname.release);
    let err = || LoadError::KernelRelease(urelease.to_string());
    let err_ = |_| LoadError::KernelRelease(urelease.to_string());

    let mut release_package = urelease.splitn(2, '-');
    let mut release = release_package.next().ok_or(err())?.splitn(3, '.');

    let major = u32::from_str(release.next().ok_or(err())?).map_err(err_)?;
    let minor = u32::from_str(release.next().ok_or(err())?).map_err(err_)?;
    let patch = u32::from_str(release.next().ok_or(err())?).map_err(err_)?;

    Ok(major << 16 | minor << 8 | patch)
}

#[inline]
pub fn get_fqdn() -> Result<String> {
    let uname = uname()?;
    let mut hostname = to_str(&uname.nodename).to_string();
    let domainname = to_str(&uname.domainname);
    if domainname != "(none)" {
        hostname.push_str(".");
        hostname.push_str(domainname);
    }

    Ok(hostname)
}

#[inline]
pub fn to_str(bytes: &[i8]) -> &str {
    unsafe { from_utf8_unchecked(CStr::from_ptr(bytes.as_ptr()).to_bytes()) }
}
