// Copyright 2021 Junyeong Jeong <rhdxmr@gmail.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
/*!
A module for generating C source code (i.e. vmlinux.h) that defines all structs
and enums of the Linux kernel.

This module is responsible for generating C source code using BTF of
vmlinux. All data structures even not exported to the Linux kernel headers can
be found in `vmlinux.h`.

*NOTE* BTF does not record macro constants that are defined by `#define`
syntax. So macro constants can not be generated from vmlinux image. But
`type_gen` provides common macro constants by including some C header files in
system.
*/

use super::libbpf_bindings;
use libbpf_sys::{
    btf, btf__free, btf__get_nr_types, btf__name_by_offset, btf__parse_elf, btf__parse_raw,
    btf__type_by_id, btf_dump, btf_dump__dump_type, btf_dump__free, libbpf_find_kernel_btf,
};
use libc::{c_char, c_void};
use regex::RegexSet;
use std::env;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Write};
use std::mem;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::path::Path;
use std::path::PathBuf;
use std::ptr;
pub const ENV_VMLINUX_PATH: &'static str = "REDBPF_VMLINUX";

// only used for RAII
struct RawFdWrapper(RawFd);
impl Drop for RawFdWrapper {
    fn drop(&mut self) {
        unsafe {
            File::from_raw_fd(self.0);
        }
    }
}

impl From<File> for RawFdWrapper {
    fn from(fobj: File) -> RawFdWrapper {
        RawFdWrapper(fobj.into_raw_fd())
    }
}

impl From<RawFdWrapper> for File {
    fn from(rawfd: RawFdWrapper) -> File {
        let fobj = unsafe { File::from_raw_fd(rawfd.0) };
        mem::forget(rawfd);
        fobj
    }
}

// only used for RAII
struct BtfDumpWrapper(*mut btf_dump);
impl Drop for BtfDumpWrapper {
    fn drop(&mut self) {
        unsafe {
            btf_dump__free(self.0);
        }
    }
}

/// An error that occurred during parsing vmlinux and generating C source code
/// from BTF.
#[derive(Debug)]
pub enum TypeGenError {
    /// error on parsing vmlinux
    VmlinuxParsingError,
    /// vmlinux not found
    VmlinuxNotFound,
    /// path contains invalid utf-8
    InvalidPath,
    /// IO error
    IO(io::Error),
    /// invalid regex
    RegexError,
    DumpError,
}

type Result<T> = std::result::Result<T, TypeGenError>;

/// Load vmlinux from file and generate `vmlinux.h`
pub struct VmlinuxBtfDump {
    allowlist: Option<Vec<String>>,
    btfptr: *mut btf,
}

impl VmlinuxBtfDump {
    /// Probe few well-known locations for vmlinux kernel image and try to load
    /// BTF data out of it
    pub fn with_system_default() -> Result<Self> {
        let btfptr = unsafe { libbpf_find_kernel_btf() };
        if (btfptr as isize) < 0 {
            return Err(TypeGenError::VmlinuxNotFound);
        }

        Ok(VmlinuxBtfDump {
            allowlist: None,
            btfptr,
        })
    }

    /// Read the ELF file and parse BTF data out of the given ELF file
    pub fn with_elf_file(elf_file: impl AsRef<Path>) -> Result<Self> {
        if !elf_file.as_ref().exists() {
            return Err(TypeGenError::VmlinuxNotFound);
        }

        let elf_str = elf_file
            .as_ref()
            .to_str()
            .ok_or(TypeGenError::InvalidPath)?;

        let cvmlinux_path = CString::new(elf_str).unwrap();
        let btfptr = unsafe { btf__parse_elf(cvmlinux_path.as_ptr(), ptr::null_mut()) };
        if (btfptr as isize) < 0 {
            return Err(TypeGenError::VmlinuxParsingError);
        }

        Ok(VmlinuxBtfDump {
            allowlist: None,
            btfptr,
        })
    }

    /// Parse BTF data from a file containing raw BTF data
    pub fn with_raw_file(raw: impl AsRef<Path>) -> Result<Self> {
        if !raw.as_ref().exists() {
            return Err(TypeGenError::VmlinuxNotFound);
        }

        let raw_str = raw.as_ref().to_str().ok_or(TypeGenError::InvalidPath)?;

        let cpath = CString::new(raw_str).unwrap();
        let btfptr = unsafe { btf__parse_raw(cpath.as_ptr()) };
        if (btfptr as isize) < 0 {
            return Err(TypeGenError::VmlinuxParsingError);
        }

        Ok(VmlinuxBtfDump {
            allowlist: None,
            btfptr,
        })
    }

    /// Add regex `pattern` into allowlist of BTF types
    pub fn allowlist(mut self, pattern: &str) -> Self {
        let allowlist: &mut Vec<String> = if let Some(allowlist) = &mut self.allowlist {
            allowlist
        } else {
            self.allowlist = Some(vec![]);
            self.allowlist.as_mut().unwrap()
        };
        allowlist.push(pattern.to_string());
        self
    }

    /// Dump BTF types as C source code into `outfile` including all the
    /// necessary dependent types.
    pub fn generate(self, outfile: impl AsRef<Path>) -> Result<()> {
        let mut fobj = File::create(&outfile).or_else(|e| Err(TypeGenError::IO(e)))?;
        let header_name = outfile.as_ref().file_name().unwrap();
        let guard_name = header_name
            .to_str()
            .unwrap()
            .to_uppercase()
            .chars()
            .map(|c| match c {
                'A'..='Z' => c,
                _ => '_',
            })
            .collect::<String>();
        let guardstr = format!(
            "#ifndef __{guard_name}__\n#define __{guard_name}__\n\n",
            guard_name = guard_name
        );
        fobj.write_all(guardstr.as_bytes())
            .or_else(|e| Err(TypeGenError::IO(e)))?;
        fobj.flush().or_else(|e| Err(TypeGenError::IO(e)))?;
        let mut rawfd: RawFdWrapper = fobj.into();
        let white_re = if let Some(ref allowlist) = self.allowlist {
            Some(RegexSet::new(allowlist).or(Err(TypeGenError::RegexError))?)
        } else {
            None
        };
        unsafe {
            let dumpptr = libbpf_bindings::btf_dump__new(
                self.btfptr as _,
                Some(vdprintf_wrapper),
                &mut rawfd as *mut _ as *mut _,
                ptr::null(),
            );
            if (dumpptr as isize) < 0 {
                return Err(TypeGenError::DumpError);
            }
            let dumpptr = BtfDumpWrapper(dumpptr as _);
            for type_id in 1..=btf__get_nr_types(self.btfptr) {
                let btftypeptr = btf__type_by_id(self.btfptr, type_id);
                let nameptr = btf__name_by_offset(self.btfptr, (*btftypeptr).name_off);
                if nameptr.is_null() {
                    continue;
                }

                let cname = CStr::from_ptr(nameptr);
                let namestr = cname.to_str().or(Err(TypeGenError::DumpError))?;
                if let Some(wre) = &white_re {
                    if !wre.is_match(namestr) {
                        continue;
                    }
                }
                if btf_dump__dump_type(dumpptr.0, type_id) < 0 {
                    return Err(TypeGenError::DumpError);
                }
            }
        }

        let mut fobj: File = rawfd.into();
        fobj.write_all(b"#endif\n")
            .or_else(|e| Err(TypeGenError::IO(e)))?;

        Ok(())
    }
}

impl Drop for VmlinuxBtfDump {
    fn drop(&mut self) {
        unsafe {
            btf__free(self.btfptr);
        }
    }
}

// FIXME: remove libbpf_bindings in favor of libbpf-sys
// wrapping vdprintf to get rid of return type
unsafe extern "C" fn vdprintf_wrapper(
    ctx: *mut c_void,
    format: *const c_char,
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    #[cfg(target_env = "musl")]
    va_list: libbpf_bindings::__isoc_va_list,
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    #[cfg(not(target_env = "musl"))]
    va_list: libbpf_bindings::__gnuc_va_list,
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    va_list: *mut libbpf_bindings::__va_list_tag,
) {
    let rawfd_wrapper = &*(ctx as *mut RawFdWrapper);
    libbpf_bindings::vdprintf(rawfd_wrapper.0, format, va_list);
}

pub fn get_custom_vmlinux_path() -> Option<PathBuf> {
    Some(PathBuf::from(env::var(ENV_VMLINUX_PATH).ok()?))
}

/// Find a source of vmlinux BTF and parse it
///
/// Using the returned `VmlinuxBtfDump`, BTF of the Linux kernel can be dumped
/// into `vmlinux.h`.
pub fn vmlinux_btf_dump() -> Result<VmlinuxBtfDump> {
    if let Some(path) = get_custom_vmlinux_path() {
        if path.to_str().unwrap() == "system" {
            VmlinuxBtfDump::with_system_default()
        } else {
            VmlinuxBtfDump::with_raw_file(&path).or_else(|_| VmlinuxBtfDump::with_elf_file(&path))
        }
    } else {
        VmlinuxBtfDump::with_system_default()
    }
}
