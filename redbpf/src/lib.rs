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

#[cfg(feature = "build")]
#[macro_use]
extern crate lazy_static;
#[cfg(feature = "build")]
#[macro_use]
extern crate serde_derive;

#[cfg(feature = "build")]
pub mod build;
pub mod cpus;
mod error;
#[cfg(feature = "load")]
pub mod load;
mod perf;
pub mod sys;
pub mod xdp;
pub use bpf_sys::uname;

use bpf_sys::{bpf_insn, bpf_map_def};
use goblin::elf::{reloc::RelocSection, section_header as hdr, Elf, SectionHeader, Sym};

use std::collections::HashMap as RSHashMap;
use std::ffi::CString;
use std::io;
use std::marker::PhantomData;
use std::mem;
use std::mem::MaybeUninit;
use std::os::unix::io::RawFd;

pub use crate::error::{Error, Result};
pub use crate::perf::*;
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

/// You can load an eBPF module, and all the programs in it like so:
///
/// ```no_run
/// use redbpf::Module;
///
/// let code = std::fs::read("bpf.elf").unwrap();
/// let mut module = Module::parse(&code).unwrap();
/// for prog in module.programs.iter_mut() {
///     prog.load(module.version, module.license.clone()).unwrap();
/// }
/// ```
///
/// Note that during the parsing the ELF file all BPF maps are automatically
/// initialised.
///
/// You can attach kprobes like very easily:
///
/// ```no_run
/// use redbpf::Module;
/// use redbpf::ProgramKind::*;
///
/// let code = std::fs::read("bpf.elf").unwrap();
/// let mut module = Module::parse(&code).unwrap();
/// for prog in module
///     .programs
///     .iter_mut()
///     .filter(|p| p.kind == Kprobe || p.kind == Kretprobe)
/// {
///     prog.attach_probe().unwrap();
/// }
/// ```
///
/// XDP and socket filters additionally require an interface to attach to.
/// Note that in case of XDP, the driver needs to support XDP probes, so, for
/// example, network bridges may not work out of the box.
///
/// ```no_run
/// use redbpf::Module;
/// use redbpf::ProgramKind::*;
/// use redbpf::xdp;
///
/// let code = std::fs::read("bpf.elf").unwrap();
/// let mut module = Module::parse(&code).unwrap();
/// for prog in module
///     .programs
///     .iter_mut()
///     .filter(|p| p.kind == XDP)
/// {
///     prog.attach_xdp("eth0", xdp::Flags::default()).unwrap();
/// }
/// ```
pub struct Program {
    pfd: Option<RawFd>,
    fd: Option<RawFd>,
    pub kind: ProgramKind,
    pub name: String,
    code: Vec<bpf_insn>,
    code_bytes: i32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProgramKind {
    Kprobe,
    Kretprobe,
    XDP,
    SocketFilter,
    Tracepoint,
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

impl ProgramKind {
    pub fn to_prog_type(&self) -> bpf_sys::bpf_prog_type {
        use crate::ProgramKind::*;
        match self {
            Kprobe | Kretprobe => bpf_sys::bpf_prog_type_BPF_PROG_TYPE_KPROBE,
            XDP => bpf_sys::bpf_prog_type_BPF_PROG_TYPE_XDP,
            SocketFilter => bpf_sys::bpf_prog_type_BPF_PROG_TYPE_SOCKET_FILTER,
            Tracepoint => bpf_sys::bpf_prog_type_BPF_PROG_TYPE_TRACEPOINT,
        }
    }

    pub fn to_attach_type(&self) -> bpf_sys::bpf_probe_attach_type {
        use crate::ProgramKind::*;
        match self {
            Kprobe => bpf_sys::bpf_probe_attach_type_BPF_PROBE_ENTRY,
            Kretprobe => bpf_sys::bpf_probe_attach_type_BPF_PROBE_RETURN,
            a @ Tracepoint => panic!("Program type cannot be used with attach(): {:?}", a),
            a @ SocketFilter => panic!("Program type cannot be used with attach(): {:?}", a),
            a @ XDP => panic!("Program type cannot be used with attach(): {:?}", a),
        }
    }

    pub fn from_section(section: &str) -> Result<ProgramKind> {
        use crate::ProgramKind::*;
        match section {
            "kretprobe" => Ok(Kretprobe),
            "kprobe" => Ok(Kprobe),
            "xdp" => Ok(XDP),
            "socketfilter" => Ok(SocketFilter),
            "tracepoint" => Ok(Tracepoint),
            sec => Err(Error::Section(sec.to_string())),
        }
    }
}

impl Program {
    pub fn new(kind: &str, name: &str, code: &[u8]) -> Result<Program> {
        let code_bytes = code.len() as i32;
        let code = zero::read_array(code).to_vec();
        let name = name.to_string();
        let kind = ProgramKind::from_section(kind)?;

        Ok(Program {
            pfd: None,
            fd: None,
            kind,
            name,
            code,
            code_bytes,
        })
    }

    pub fn is_loaded(&self) -> bool {
        self.fd.is_some()
    }

    pub fn is_attached(&self) -> bool {
        self.pfd.is_some()
    }

    pub fn load(&mut self, kernel_version: u32, license: String) -> Result<RawFd> {
        let clicense = CString::new(license)?;
        let cname = CString::new(self.name.clone())?;
        let log_buffer: MutDataPtr =
            unsafe { libc::malloc(mem::size_of::<i8>() * 16 * 65535) as MutDataPtr };
        let buf_size = 64 * 65535 as u32;

        let fd = unsafe {
            bpf_sys::bcc_prog_load(
                self.kind.to_prog_type(),
                cname.as_ptr() as DataPtr,
                self.code.as_ptr(),
                self.code_bytes,
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
            self.fd = Some(fd);
            Ok(fd)
        }
    }

    pub fn attach_probe(&mut self) -> Result<RawFd> {
        self.attach_probe_to_name(&self.name.clone())
    }

    pub fn attach_probe_to_name(&mut self, name: &str) -> Result<RawFd> {
        let ev_name = CString::new(format!("{}{}", name, self.kind.to_attach_type())).unwrap();
        let cname = CString::new(name).unwrap();
        let pfd = unsafe {
            bpf_sys::bpf_attach_kprobe(
                self.fd.unwrap(),
                self.kind.to_attach_type(),
                ev_name.as_ptr(),
                cname.as_ptr(),
                0,
                0,
            )
        };

        if pfd < 0 {
            Err(Error::BPF)
        } else {
            self.pfd = Some(pfd);
            Ok(pfd)
        }
    }

    pub fn attach_tracepoint(&mut self, category: &str, name: &str) -> Result<RawFd> {
        let category = CString::new(category)?;
        let name = CString::new(name)?;
        let res = unsafe {
            bpf_sys::bpf_attach_tracepoint(
                self.fd.unwrap(),
                category.as_c_str().as_ptr(),
                name.as_c_str().as_ptr(),
            )
        };

        if res < 0 {
            Err(Error::BPF)
        } else {
            Ok(res)
        }
    }

    pub fn attach_xdp(&mut self, iface: &str, flags: xdp::Flags) -> Result<()> {
        let ciface = CString::new(iface).unwrap();
        let res =
            unsafe { bpf_sys::bpf_attach_xdp(ciface.as_ptr(), self.fd.unwrap(), flags as u32) };

        if res < 0 {
            Err(Error::BPF)
        } else {
            Ok(())
        }
    }

    pub fn attach_socketfilter(&mut self, iface: &str) -> Result<RawFd> {
        let ciface = CString::new(iface).unwrap();
        let sfd = unsafe { bpf_sys::bpf_open_raw_sock(ciface.as_ptr()) };

        if sfd < 0 {
            return Err(Error::IO(io::Error::last_os_error()));
        }

        match unsafe { bpf_sys::bpf_attach_socket(sfd, self.fd.ok_or(Error::BPF)?) } {
            0 => {
                self.pfd = Some(sfd);
                Ok(sfd)
            }
            _ => Err(Error::IO(io::Error::last_os_error())),
        }
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
        let map = maps
            .get(&symtab[self.sym].st_shndx)
            .ok_or(Error::Reloc)?;
        let insn_idx = (self.offset / std::mem::size_of::<bpf_insn>() as u64) as usize;

        prog.code[insn_idx].set_src_reg(bpf_sys::BPF_PSEUDO_MAP_FD as u8);
        prog.code[insn_idx].imm = map.fd;

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
