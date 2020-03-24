// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! # RedBPF
//!
//! This crate provides a build-load-run workflow for eBPF modules. If the
//! `build` cargo feature is enabled, build-specific functionality is available.
//! You may want to use the `redbpf` crate like so:
//!
//! ```toml
//! [build-dependencies]
//! redbpf = { version = "0.9", features = ["build"] }
//!
//! [dependencies]
//! redbpf = "0.9"
//! ````
//!
//! For more information about build-specific examples, look at the
//! documentation for the `build` module.
//!
//! ## ELF object expectations
//!
//! The ELF sections loaded by RedBPF should follow the following naming convention:
//!  * `maps/name` for maps
//!  * `kprobe/function_name` for entry probes for `function_name`
//!  * `kretprobe/function_name` for return probes for `function_name`
//!  * `xdp/name` for XDP probes. Names can be anything.
//!  * `socketfilter/name` for socket filters. Names can be anything.
//!
//! Additionally, as per convention, the following sections should be present in
//! the ELF object:
//!
//! ```c
//! __u32 _version SEC("version") = 0xFFFFFFFE;
//! char _license[] SEC("license") = "GPL";
//! ```
//!
//! If the license is not GPL, some in-kernel functionality is not available for eBPF modules.
//!
//! The magic version number is compatible with GoBPF's convention: during
//! loading it is replaced with the currently running kernel's internal version,
//! as returned by `uname()`.
#![deny(clippy::all)]
#![allow(non_upper_case_globals)]

#[macro_use]
extern crate lazy_static;

#[cfg(feature = "build")]
pub mod build;
pub mod cpus;
mod error;
#[cfg(feature = "load")]
pub mod load;
mod perf;
mod symbols;
pub mod sys;
pub mod xdp;

pub use bpf_sys::uname;
use bpf_sys::{
    bpf_insn, bpf_map_def, bpf_probe_attach_type, bpf_probe_attach_type_BPF_PROBE_ENTRY,
    bpf_probe_attach_type_BPF_PROBE_RETURN, bpf_prog_type,
};
use goblin::elf::{reloc::RelocSection, section_header as hdr, Elf, SectionHeader, Sym};

use std::collections::HashMap as RSHashMap;
use std::ffi::CString;
use std::fs;
use std::io;
use std::marker::PhantomData;
use std::mem;
use std::mem::MaybeUninit;
use std::os::unix::io::RawFd;
use libc::pid_t;

pub use crate::error::{Error, Result};
pub use crate::perf::*;
use crate::symbols::*;
use crate::uname::get_kernel_internal_version;

#[cfg(target_arch = "aarch64")]
pub type DataPtr = *const u8;
#[cfg(target_arch = "aarch64")]
pub type MutDataPtr = *mut u8;

#[cfg(target_arch = "x86_64")]
pub type DataPtr = *const i8;
#[cfg(target_arch = "x86_64")]
pub type MutDataPtr = *mut i8;

pub struct Module {
    pub programs: Vec<Program>,
    pub maps: Vec<Map>,
    pub license: String,
    pub version: u32,
}
/// A BPF program defined in a [Module](struct.Module.html).
pub enum Program {
    KProbe(KProbe),
    KRetProbe(KProbe),
    UProbe(UProbe),
    URetProbe(UProbe),
    SocketFilter(SocketFilter),
    TracePoint(TracePoint),
    XDP(XDP),
}

struct ProgramData {
    pub name: String,
    code: Vec<bpf_insn>,
    fd: Option<RawFd>,
}

/// Type to work with `kprobes` or `kretprobes`.
pub struct KProbe {
    common: ProgramData,
    attach_type: bpf_probe_attach_type,
}

/// Type to work with `uprobes` or `uretprobes`.
pub struct UProbe {
    common: ProgramData,
    attach_type: bpf_probe_attach_type,
}

/// Type to work with `socket filters`.
pub struct SocketFilter {
    common: ProgramData,
}

pub struct TracePoint {
    common: ProgramData,
}
/// Type to work with `XDP` programs.
pub struct XDP {
    common: ProgramData,
    interface: Option<String>,
}

pub struct Map {
    pub name: String,
    pub kind: u32,
    fd: RawFd,
    config: bpf_map_def,
}

pub struct HashMap<'a, K: Clone, V: Clone> {
    base: &'a Map,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

#[allow(dead_code)]
pub struct Rel {
    shndx: usize,
    target: usize,
    offset: u64,
    sym: usize,
}

impl Program {
    fn new(kind: &str, name: &str, code: &[u8]) -> Result<Program> {
        let code = zero::read_array(code).to_vec();
        let name = name.to_string();

        let common = ProgramData {
            name,
            code,
            fd: None,
        };

        Ok(match kind {
            "kprobe" => Program::KProbe(KProbe {
                common,
                attach_type: bpf_probe_attach_type_BPF_PROBE_ENTRY,
            }),
            "kretprobe" => Program::KProbe(KProbe {
                common,
                attach_type: bpf_probe_attach_type_BPF_PROBE_RETURN,
            }),
            "uprobe" => Program::UProbe(UProbe {
                common,
                attach_type: bpf_probe_attach_type_BPF_PROBE_ENTRY,
            }),
            "uretprobe" => Program::UProbe(UProbe {
                common,
                attach_type: bpf_probe_attach_type_BPF_PROBE_RETURN,
            }),
            "tracepoint" => Program::TracePoint(TracePoint { common }),
            "socketfilter" => Program::SocketFilter(SocketFilter { common }),
            "xdp" => Program::XDP(XDP {
                common,
                interface: None,
            }),
            _ => return Err(Error::Section(kind.to_string())),
        })
    }

    fn to_prog_type(&self) -> bpf_prog_type {
        use Program::*;

        match self {
            KProbe(_) | KRetProbe(_) | UProbe(_) | URetProbe(_) => {
                bpf_sys::bpf_prog_type_BPF_PROG_TYPE_KPROBE
            }
            XDP(_) => bpf_sys::bpf_prog_type_BPF_PROG_TYPE_XDP,
            SocketFilter(_) => bpf_sys::bpf_prog_type_BPF_PROG_TYPE_SOCKET_FILTER,
            TracePoint(_) => bpf_sys::bpf_prog_type_BPF_PROG_TYPE_TRACEPOINT,
        }
    }

    fn data(&self) -> &ProgramData {
        use Program::*;

        match self {
            KProbe(p) | KRetProbe(p) => &p.common,
            UProbe(p) | URetProbe(p) => &p.common,
            XDP(p) => &p.common,
            SocketFilter(p) => &p.common,
            TracePoint(p) => &p.common,
        }
    }

    fn data_mut(&mut self) -> &mut ProgramData {
        use Program::*;

        match self {
            KProbe(p) | KRetProbe(p) => &mut p.common,
            UProbe(p) | URetProbe(p) => &mut p.common,
            XDP(p) => &mut p.common,
            SocketFilter(p) => &mut p.common,
            TracePoint(p) => &mut p.common,
        }
    }

    pub fn name(&self) -> &str {
        &self.data().name
    }

    /// Load the BPF program.
    ///
    /// BPF programs need to be loaded before they can be attached. Loading will fail if the BPF verifier rejects the code.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use redbpf::Module;
    /// let mut module = Module::parse(&std::fs::read("file.elf").unwrap()).unwrap();
    /// for program in module.programs.iter_mut() {
    ///     program
    ///         .load(module.version, module.license.clone()).unwrap()
    /// }
    /// ```
    pub fn load(&mut self, kernel_version: u32, license: String) -> Result<()> {
        if let Some(_) = self.data().fd {
            return Err(Error::ProgramAlreadyLoaded);
        }
        let clicense = CString::new(license)?;
        let cname = CString::new(self.data_mut().name.clone())?;
        let log_buffer: MutDataPtr =
            unsafe { libc::malloc(mem::size_of::<i8>() * 16 * 65535) as MutDataPtr };
        let buf_size = 64 * 65535 as u32;

        let fd = unsafe {
            bpf_sys::bcc_prog_load(
                self.to_prog_type(),
                cname.as_ptr() as DataPtr,
                self.data_mut().code.as_ptr(),
                (self.data_mut().code.len() * mem::size_of::<bpf_insn>()) as i32,
                clicense.as_ptr() as DataPtr,
                kernel_version as u32,
                0 as i32,
                log_buffer,
                buf_size,
            )
        };

        if fd < 0 {
            Err(Error::BPF)
        } else {
            self.data_mut().fd = Some(fd);
            Ok(())
        }
    }
}

impl KProbe {
    /// Attach the `kprobe` or `kretprobe`.
    ///
    /// Attach the probe to the function `fn_name` inside the kernel. If `offset`
    /// is given, the probe will be attached at that byte offset inside the
    /// function.
    ///
    /// # Example
    /// ```no_run
    /// use redbpf::Module;
    /// let mut module = Module::parse(&std::fs::read("file.elf").unwrap()).unwrap();
    /// for kprobe in module.kprobes_mut() {
    ///     kprobe.attach_kprobe(&kprobe.name(), 0).unwrap();
    /// }
    /// ```
    pub fn attach_kprobe(&mut self, fn_name: &str, offset: u64) -> Result<()> {
        let fd = self.common.fd.ok_or(Error::ProgramNotLoaded)?;
        let ev_name = CString::new(format!("{}{}", fn_name, self.attach_type)).unwrap();
        let cname = CString::new(fn_name).unwrap();
        let pfd = unsafe {
            bpf_sys::bpf_attach_kprobe(
                fd,
                self.attach_type,
                ev_name.as_ptr(),
                cname.as_ptr(),
                offset,
                0,
            )
        };

        if pfd < 0 {
            Err(Error::BPF)
        } else {
            Ok(())
        }
    }

    pub fn name(&self) -> String {
        self.common.name.to_string()
    }

    pub fn attach_type_str(&self) -> &'static str {
        match self.attach_type {
            bpf_probe_attach_type_BPF_PROBE_ENTRY => "Kprobe",
            bpf_probe_attach_type_BPF_PROBE_RETURN => "Kretprobe",
            _ => unreachable!(),
        }
    }
}

impl UProbe {
    /// Attach the `uprobe` or `uretprobe`.
    ///
    /// Attach the probe to the function `fn_name` defined in the library or
    /// binary at `path`. If `offset` is given, the probe will be attached at
    /// that byte offset inside the function. If a `pid` is passed, only the
    /// corresponding process is traced.
    ///
    /// # Example
    /// ```no_run
    /// use redbpf::Module;
    /// let mut module = Module::parse(&std::fs::read("file.elf").unwrap()).unwrap();
    /// for uprobe in module.uprobes_mut() {
    ///     uprobe.attach_uprobe(&uprobe.name(), 0, "/lib/x86_64-linux-gnu/libc-2.30.so", None).unwrap();
    /// }
    /// ```
    pub fn attach_uprobe(
        &mut self,
        fn_name: &str,
        offset: u64,
        target: &str,
        pid: Option<pid_t>,
    ) -> Result<()> {
        let fd = self.common.fd.ok_or(Error::ProgramNotLoaded)?;

        let pid = pid.unwrap_or(-1);
        let path = match (target.starts_with("/"), LD_SO_CACHE.as_ref()) {
            (false, Ok(cache)) => cache.resolve(target).unwrap_or(target).to_string(),
            _ => target.to_owned(),
        };
        let data = fs::read(&path)?;
        let parser = ElfSymbols::parse(&data)?;
        let sym_offset = parser
            .resolve(fn_name)
            .ok_or_else(|| Error::SymbolNotFound(fn_name.to_string()))?
            .st_value;

        let ev_name =
            CString::new(format!("{}{}{}{}", &path, fn_name, self.attach_type, pid)).unwrap();
        let path = CString::new(path).unwrap();
        let pfd = unsafe {
            bpf_sys::bpf_attach_uprobe(
                fd,
                self.attach_type,
                ev_name.as_ptr(),
                path.as_ptr(),
                sym_offset + offset,
                pid,
            )
        };

        if pfd < 0 {
            Err(Error::BPF)
        } else {
            Ok(())
        }
    }

    pub fn name(&self) -> String {
        self.common.name.to_string()
    }
}

impl TracePoint {
    pub fn attach_trace_point(&mut self, category: &str, name: &str) -> Result<()> {
        let fd = self.common.fd.ok_or(Error::ProgramNotLoaded)?;
        let category = CString::new(category)?;
        let name = CString::new(name)?;
        let res = unsafe {
            bpf_sys::bpf_attach_tracepoint(
                fd,
                category.as_c_str().as_ptr(),
                name.as_c_str().as_ptr(),
            )
        };

        if res < 0 {
            Err(Error::BPF)
        } else {
            Ok(())
        }
    }

    pub fn name(&self) -> String {
        self.common.name.to_string()
    }
}

impl XDP {
    /// Attach the XDP program.
    ///
    /// Attach the XDP program to the given network interface.
    ///
    /// # Example
    /// ```no_run
    /// # use redbpf::{Module, xdp};
    /// # let mut module = Module::parse(&std::fs::read("file.elf").unwrap()).unwrap();
    /// # for uprobe in module.xdps_mut() {
    /// uprobe.attach_xdp("eth0", xdp::Flags::default()).unwrap();
    /// # }
    /// ```
    pub fn attach_xdp(&mut self, interface: &str, flags: xdp::Flags) -> Result<()> {
        let fd = self.common.fd.ok_or(Error::ProgramNotLoaded)?;
        self.interface = Some(interface.to_string());
        let ciface = CString::new(interface).unwrap();
        let res = unsafe { bpf_sys::bpf_attach_xdp(ciface.as_ptr(), fd, flags as u32) };

        if res < 0 {
            Err(Error::BPF)
        } else {
            Ok(())
        }
    }

    pub fn name(&self) -> String {
        self.common.name.to_string()
    }
}

impl Drop for XDP {
    fn drop(&mut self) {
        if let Some(interface) = &self.interface {
            let ciface = CString::new(interface.as_bytes()).unwrap();
            let _ = unsafe { bpf_sys::bpf_attach_xdp(ciface.as_ptr(), -1, 0) };
        }
    }
}

impl SocketFilter {
    /// Attach the socket filter program.
    ///
    /// Attach the socket filter program to the given network interface.
    ///
    /// # Example
    /// ```no_run
    /// use redbpf::Module;
    /// let mut module = Module::parse(&std::fs::read("file.elf").unwrap()).unwrap();
    /// for sf in module.socket_filters_mut() {
    ///     sf.attach_socket_filter("eth0").unwrap();
    /// }
    /// ```
    pub fn attach_socket_filter(&mut self, interface: &str) -> Result<RawFd> {
        let fd = self.common.fd.ok_or(Error::ProgramNotLoaded)?;
        let ciface = CString::new(interface).unwrap();
        let sfd = unsafe { bpf_sys::bpf_open_raw_sock(ciface.as_ptr()) };

        if sfd < 0 {
            return Err(Error::IO(io::Error::last_os_error()));
        }

        match unsafe { bpf_sys::bpf_attach_socket(sfd, fd) } {
            0 => Ok(sfd),
            _ => Err(Error::IO(io::Error::last_os_error())),
        }
    }

    pub fn name(&self) -> String {
        self.common.name.to_string()
    }
}

impl Module {
    pub fn parse(bytes: &[u8]) -> Result<Module> {
        let object = Elf::parse(&bytes[..])?;
        let symtab = object.syms.to_vec();
        let shdr_relocs = &object.shdr_relocs;

        let mut rels = vec![];
        let mut programs = RSHashMap::new();
        let mut maps = RSHashMap::new();

        let mut license = String::new();
        let mut version = 0u32;

        for (shndx, shdr) in object.section_headers.iter().enumerate() {
            let (kind, name) = get_split_section_name(&object, &shdr, shndx)?;

            let section_type = shdr.sh_type;
            let content = data(&bytes, &shdr);

            match (section_type, kind, name) {
                (hdr::SHT_REL, _, _) => add_rel(&mut rels, shndx, &shdr, shdr_relocs),
                (hdr::SHT_PROGBITS, Some("version"), _) => version = get_version(&content),
                (hdr::SHT_PROGBITS, Some("license"), _) => {
                    license = zero::read_str(content).to_string()
                }
                (hdr::SHT_PROGBITS, Some("maps"), Some(name)) => {
                    // Maps are immediately bcc_create_map'd
                    maps.insert(shndx, Map::load(name, &content)?);
                }
                (hdr::SHT_PROGBITS, Some(kind @ "kprobe"), Some(name))
                | (hdr::SHT_PROGBITS, Some(kind @ "kretprobe"), Some(name))
                | (hdr::SHT_PROGBITS, Some(kind @ "uprobe"), Some(name))
                | (hdr::SHT_PROGBITS, Some(kind @ "uretprobe"), Some(name))
                | (hdr::SHT_PROGBITS, Some(kind @ "xdp"), Some(name))
                | (hdr::SHT_PROGBITS, Some(kind @ "socketfilter"), Some(name)) => {
                    programs.insert(shndx, Program::new(kind, name, &content)?);
                }
                _ => {}
            }
        }

        // Rewrite programs with relocation data
        for rel in rels.iter() {
            if programs.contains_key(&rel.target) {
                rel.apply(&mut programs, &maps, &symtab)?;
            }
        }

        let programs = programs.drain().map(|(_, v)| v).collect();
        let maps = maps.drain().map(|(_, v)| v).collect();
        Ok(Module {
            programs,
            maps,
            license,
            version,
        })
    }

    pub fn kprobes(&self) -> impl Iterator<Item = &KProbe> {
        use Program::*;
        self.programs.iter().filter_map(|prog| match prog {
            KProbe(p) | KRetProbe(p) => Some(p),
            _ => None,
        })
    }

    pub fn kprobes_mut(&mut self) -> impl Iterator<Item = &mut KProbe> {
        use Program::*;
        self.programs.iter_mut().filter_map(|prog| match prog {
            KProbe(p) | KRetProbe(p) => Some(p),
            _ => None,
        })
    }

    pub fn uprobes(&self) -> impl Iterator<Item = &UProbe> {
        use Program::*;
        self.programs.iter().filter_map(|prog| match prog {
            UProbe(p) | URetProbe(p) => Some(p),
            _ => None,
        })
    }

    pub fn uprobes_mut(&mut self) -> impl Iterator<Item = &mut UProbe> {
        use Program::*;
        self.programs.iter_mut().filter_map(|prog| match prog {
            UProbe(p) | URetProbe(p) => Some(p),
            _ => None,
        })
    }

    pub fn xdps(&self) -> impl Iterator<Item = &XDP> {
        use Program::*;
        self.programs.iter().filter_map(|prog| match prog {
            XDP(p) => Some(p),
            _ => None,
        })
    }

    pub fn xdps_mut(&mut self) -> impl Iterator<Item = &mut XDP> {
        use Program::*;
        self.programs.iter_mut().filter_map(|prog| match prog {
            XDP(p) => Some(p),
            _ => None,
        })
    }

    pub fn socket_filters(&self) -> impl Iterator<Item = &SocketFilter> {
        use Program::*;
        self.programs.iter().filter_map(|prog| match prog {
            SocketFilter(p) => Some(p),
            _ => None,
        })
    }

    pub fn socket_filters_mut(&mut self) -> impl Iterator<Item = &mut SocketFilter> {
        use Program::*;
        self.programs.iter_mut().filter_map(|prog| match prog {
            SocketFilter(p) => Some(p),
            _ => None,
        })
    }

    pub fn trace_points(&self) -> impl Iterator<Item = &TracePoint> {
        use Program::*;
        self.programs.iter().filter_map(|prog| match prog {
            TracePoint(p) => Some(p),
            _ => None,
        })
    }

    pub fn trace_points_mut(&mut self) -> impl Iterator<Item = &mut TracePoint> {
        use Program::*;
        self.programs.iter_mut().filter_map(|prog| match prog {
            TracePoint(p) => Some(p),
            _ => None,
        })
    }
}

#[inline]
fn get_split_section_name<'o>(
    object: &'o Elf<'_>,
    shdr: &'o SectionHeader,
    shndx: usize,
) -> Result<(Option<&'o str>, Option<&'o str>)> {
    let name = object
        .shdr_strtab
        .get_unsafe(shdr.sh_name)
        .ok_or_else(|| Error::Section(format!("Section name not found: {}", shndx)))?;

    let mut names = name.splitn(2, '/');

    let kind = names.next();
    let name = names.next();

    Ok((kind, name))
}

impl Rel {
    #[inline]
    pub fn apply(
        &self,
        programs: &mut RSHashMap<usize, Program>,
        maps: &RSHashMap<usize, Map>,
        symtab: &[Sym],
    ) -> Result<()> {
        let prog = programs.get_mut(&self.target).ok_or(Error::Reloc)?;
        let map = maps.get(&symtab[self.sym].st_shndx).ok_or(Error::Reloc)?;
        let insn_idx = (self.offset / std::mem::size_of::<bpf_insn>() as u64) as usize;

        let code = &mut prog.data_mut().code;
        code[insn_idx].set_src_reg(bpf_sys::BPF_PSEUDO_MAP_FD as u8);
        code[insn_idx].imm = map.fd;

        Ok(())
    }
}

impl Map {
    pub fn load(name: &str, code: &[u8]) -> Result<Map> {
        let config: bpf_map_def = *zero::read(code);
        let cname = CString::new(name.to_owned())?;
        let fd = unsafe {
            bpf_sys::bcc_create_map(
                config.type_,
                cname.as_ptr(),
                config.key_size as i32,
                config.value_size as i32,
                config.max_entries as i32,
                config.map_flags as i32,
            )
        };
        if fd < 0 {
            return Err(Error::Map);
        }

        Ok(Map {
            name: name.to_string(),
            kind: config.type_,
            fd,
            config,
        })
    }
}

impl<'base, K: Clone, V: Clone> HashMap<'base, K, V> {
    pub fn new<'a>(base: &'a Map) -> Result<HashMap<'a, K, V>> {
        if mem::size_of::<K>() != base.config.key_size as usize
            || mem::size_of::<V>() != base.config.value_size as usize
        {
            return Err(Error::Map);
        }

        Ok(HashMap {
            base,
            _k: PhantomData,
            _v: PhantomData,
        })
    }

    pub fn set(&self, mut key: K, mut value: V) {
        unsafe {
            bpf_sys::bpf_update_elem(
                self.base.fd,
                &mut key as *mut _ as *mut _,
                &mut value as *mut _ as *mut _,
                0,
            );
        }
    }

    pub fn get(&self, mut key: K) -> Option<V> {
        let mut value = MaybeUninit::zeroed();
        if unsafe {
            bpf_sys::bpf_lookup_elem(
                self.base.fd,
                &mut key as *mut _ as *mut _,
                &mut value as *mut _ as *mut _,
            )
        } < 0
        {
            return None;
        }
        Some(unsafe { value.assume_init() })
    }

    pub fn delete(&self, mut key: K) {
        unsafe {
            bpf_sys::bpf_delete_elem(self.base.fd, &mut key as *mut _ as *mut _);
        }
    }

    pub fn iter<'a>(&'a self) -> MapIter<'a, '_, K, V> {
        MapIter {
            map: self,
            key: None,
        }
    }
}

pub struct MapIter<'a, 'b, K: Clone, V: Clone> {
    map: &'a HashMap<'b, K, V>,
    key: Option<K>,
}

impl<K: Clone, V: Clone> Iterator for MapIter<'_, '_, K, V> {
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.key.take();
        self.key = match key {
            Some(mut key) => {
                let mut next_key = MaybeUninit::<K>::zeroed();
                let ret = unsafe {
                    bpf_sys::bpf_get_next_key(
                        self.map.base.fd,
                        &mut key as *mut _ as *mut _,
                        &mut next_key as *mut _ as *mut _,
                    )
                };
                if ret < 0 {
                    None
                } else {
                    Some(unsafe { next_key.assume_init() })
                }
            }
            None => {
                let mut key = MaybeUninit::<K>::zeroed();
                if unsafe {
                    bpf_sys::bpf_get_first_key(
                        self.map.base.fd,
                        &mut key as *mut _ as *mut _,
                        self.map.base.config.key_size as usize,
                    )
                } < 0
                {
                    None
                } else {
                    Some(unsafe { key.assume_init() })
                }
            }
        };

        if self.key.is_none() {
            return None;
        }

        let key = self.key.clone().unwrap();
        Some((key.clone(), self.map.get(key).unwrap()))
    }
}

#[inline]
fn add_rel(
    rels: &mut Vec<Rel>,
    shndx: usize,
    shdr: &SectionHeader,
    shdr_relocs: &[(usize, RelocSection<'_>)],
) {
    // if unwrap blows up, something's really bad
    let section_rels = &shdr_relocs.iter().find(|(idx, _)| idx == &shndx).unwrap().1;
    rels.extend(section_rels.iter().map(|rel| Rel {
        shndx,
        target: shdr.sh_info as usize,
        sym: rel.r_sym,
        offset: rel.r_offset,
    }));
}

#[inline]
fn get_version(bytes: &[u8]) -> u32 {
    let version = zero::read::<u32>(bytes);
    match version {
        0xFFFF_FFFE => get_kernel_internal_version().unwrap(),
        _ => *version,
    }
}

#[inline]
fn data<'d>(bytes: &'d [u8], shdr: &SectionHeader) -> &'d [u8] {
    let offset = shdr.sh_offset as usize;
    let end = (shdr.sh_offset + shdr.sh_size) as usize;

    &bytes[offset..end]
}
