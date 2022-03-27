// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
/*!
Rust API to load BPF programs.

# Overview

The redbpf crate provides an idiomatic Rust API to load and interact with BPF
programs. It is part of the larger [redbpf
project](https://github.com/foniod/redbpf).

BPF programs used with `redbpf` are typically created and built with
[`cargo-bpf`](../../cargo_bpf/), and use the
[`redbpf-probes`](../../redbpf_probes/) and
[`redbpf-macros`](../../redbpf_macros/) APIs.

For full featured examples on how to use redbpf see
<https://github.com/foniod/redbpf/tree/master/redbpf-tools>.

# Example

The following example loads all the `kprobes` defined in the file `iotop.elf`.

```no_run
use redbpf::load::Loader;

let mut loader = Loader::load_file("iotop.elf").expect("error loading probe");

// attach all the kprobes defined in iotop.elf
for kprobe in loader.kprobes_mut() {
    kprobe
        .attach_kprobe(&kprobe.name(), 0)
        .expect(&format!("error attaching program {}", kprobe.name()));
}
```
*/
#![deny(clippy::all)]
#![allow(non_upper_case_globals)]

#[macro_use]
extern crate lazy_static;

pub mod btf;
pub mod cpus;
mod error;
#[cfg(feature = "load")]
pub mod load;
mod perf;
mod symbols;
pub mod sys;
pub mod xdp;

pub use bpf_sys::uname;
use goblin::elf::{reloc::RelocSection, section_header as hdr, Elf, SectionHeader, Sym};
use libbpf_sys::{
    bpf_create_map_attr, bpf_create_map_xattr, bpf_insn, bpf_iter_create, bpf_link_create,
    bpf_load_program_xattr, bpf_map_def, bpf_map_info, bpf_prog_type, BPF_ANY, BPF_MAP_TYPE_ARRAY,
    BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_LRU_HASH, BPF_MAP_TYPE_LRU_PERCPU_HASH,
    BPF_MAP_TYPE_PERCPU_ARRAY, BPF_MAP_TYPE_PERCPU_HASH, BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    BPF_MAP_TYPE_LPM_TRIE,
    BPF_SK_LOOKUP, BPF_SK_SKB_STREAM_PARSER, BPF_SK_SKB_STREAM_VERDICT, BPF_TRACE_ITER,
};

use libc::{self, pid_t};
use std::collections::HashMap as RSHashMap;
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{self, BufReader, ErrorKind, Read};
use std::marker::PhantomData;
use std::mem::{self, MaybeUninit};
use std::ops::{Deref, DerefMut};
use std::os::unix::io::{FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::ptr;

use crate::btf::{BtfKind, MapBtfTypeId, BTF};
pub use crate::error::{Error, Result};
pub use crate::perf::*;
use crate::symbols::*;
use crate::uname::get_kernel_internal_version;

use tracing::{debug, error, warn};

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

/// A builder of [Module](struct.Module.html)
///
/// In most cases
/// [`redbpf::load::Loader::load`](./load/struct.Loader.html#method.load) or
/// [`redbpf::Module::parse`](struct.Module.html#method.parse) is enough to
/// achieve your goal. These functions parse maps and programs from the ELF
/// relocatable file and then load them into kernel directly. But sometimes you
/// need to manipulate the maps or the programs before load them. That's why
/// `ModuleBuilder` exists.
///
/// By `ModuleBuilder` you can achieve one goal at this moment: sharing maps
/// among multiple independent BPF programs and their corresponding userspace
/// programs by calling
/// [`ModuleBuilder::replace_map`](struct.ModuleBuilder.html#method.replace_map)
///
/// cf. Here, "independent BPF programs" means that each BPF program had been
/// compiled into a different ELF relocatable file. You don't have to deal with
/// `ModuleBuilder` if all BPF programs are compiled into one ELF relocatable
/// file.
pub struct ModuleBuilder<'a> {
    object: Elf<'a>,
    programs: RSHashMap<usize, Program>,
    map_builders: RSHashMap<usize, MapBuilder<'a>>,
    symval_to_map_builders: RSHashMap<u64, MapBuilder<'a>>,
    rels: Vec<RelocationInfo>,
    license: String,
    version: u32,
    // BTF should survive until all maps are created with it. So keep it
    #[allow(dead_code)]
    btf: Option<BTF>,
}

enum ProbeAttachType {
    Entry,
    Return,
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
    StreamParser(StreamParser),
    StreamVerdict(StreamVerdict),
    TaskIter(TaskIter),
    SkLookup(SkLookup),
}

struct ProgramData {
    pub name: String,
    code: Vec<bpf_insn>,
    fd: Option<RawFd>,
}

struct KProbeAttachmentPoint {
    fn_name: String,
    offset: u64,
    pfd: RawFd, // file descriptor of perf event
}

struct UProbeAttachmentPoint {
    fn_name: Option<String>,
    offset: u64,
    target: String,
    pid: Option<pid_t>,
    pfd: RawFd, // file descriptor of perf event
}

/// Type to work with `kprobes` or `kretprobes`.
pub struct KProbe {
    common: ProgramData,
    attach_type: ProbeAttachType,
    attachment_points: Vec<KProbeAttachmentPoint>,
}

/// Type to work with `uprobes` or `uretprobes`.
pub struct UProbe {
    common: ProgramData,
    attach_type: ProbeAttachType,
    attachment_points: Vec<UProbeAttachmentPoint>,
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
    interfaces: Vec<u32>,
}

/// Type to work with `stream_parser` BPF programs.
pub struct StreamParser {
    common: ProgramData,
}

/// Type to work with `stream_verdict` BPF programs.
pub struct StreamVerdict {
    common: ProgramData,
}

/// A structure supporting BPF iterators that handle `task`
///
/// # Example
/// ```no_run
/// # const DATA: [u8; 16] = [0u8; 16];
/// # fn probe_code() -> &'static [u8] {
/// #     &DATA[..]
/// # }
/// use redbpf::load::Loader;
/// let mut loaded = Loader::load(probe_code()).unwrap();
/// let tasks = loaded
///     .task_iter_mut("dump_tgid")
///     .expect("dump_tgid task iterator not found");
/// for tgid in tasks
///     .bpf_iter::<libc::pid_t>()
///     .expect("error on Taskiter::bpf_iter")
/// {
///     println!("{}", tgid);
/// }
/// ```
pub struct TaskIter {
    common: ProgramData,
    attach_btf_id: u32,
    link_fd: Option<RawFd>,
}

/// Type to work with [`sk_lookup`] BPF programs.
///
/// `sk_lookup` programs were introduced with Linux 5.9 and make it possible to
/// programmatically perform socket lookup for new connections.
/// This can be used, for instance, to listen on a large number of addresses and ports
/// with a single socket.
///
/// In order to take effect, `sk_lookup` programs must be attached to a
/// network namespace, which can be done with the [`attach_sk_lookup`] method.
///
/// # Example
///
/// The userland code for listening on a port range could look something like this.
///
/// ```no_run
/// # static SK_LOOKUP: &[u8] = &[];
/// use std::net::TcpListener;
/// use std::os::unix::io::AsRawFd;
///
/// use redbpf::{HashMap, SockMap};
/// use redbpf::load::Loader;
///
/// let mut listener = TcpListener::bind(("127.0.0.1", 12345)).unwrap();
/// let mut loaded = Loader::load(SK_LOOKUP).unwrap();
///
/// // Pass the listener fd to the BPF program
/// let mut socket = SockMap::new(loaded.map("socket").unwrap()).unwrap();
/// socket.set(0, listener.as_raw_fd());
///
/// // Pass our port range to the BPF program
/// let mut ports = HashMap::<u16, u8>::new(loaded.map("ports").unwrap()).unwrap();
/// for port in 80..430 {
///     ports.set(port, 1);
/// }
///
/// // Attach the BPF program to the current process' network namespace
/// loaded
///     .sk_lookup_mut("range_listener")
///     .unwrap()
///     .attach_sk_lookup("/proc/self/ns/net")
///     .unwrap();
///
/// loop {
///     let (client, _) = listener.accept().unwrap();
///     let addr = client.local_addr().unwrap();
///     println!("accepted new connection on `{}`", addr);
/// }
/// ```
///
/// [`sk_lookup`]: https://github.com/torvalds/linux/blob/master/Documentation/bpf/prog_sk_lookup.rst
pub struct SkLookup {
    common: ProgramData,
    link: Option<(RawFd, RawFd)>,
}

/// A base BPF map data structure
///
/// It is a base data structure that contains a map definition and auxiliary
/// data. It just hods data but it does not provide any useful API to users.
/// See [`HashMap`](./struct.HashMap.html),
/// [`LruHashMap`](./struct.LruHashMap.html),
/// [`PerCpuHashMap`](./struct.PerCpuHashMap.html),
/// [`LruPerCpuHashMap`](./struct.LruPerCpuHashMap.html),
/// [`Array`](./struct.Array.html), [`PerCpuArray`](./struct.PerCpuArray.html)
/// that wrap `Map` to provide API of BPF maps to userspace programs.
#[derive(Debug)]
pub struct Map {
    pub name: String,
    pub kind: u32,
    fd: RawFd,
    config: bpf_map_def,
    section_data: bool,
    pin_file: Option<Box<Path>>,
}

enum MapBuilder<'a> {
    Normal {
        name: String,
        def: bpf_map_def,
        btf_type_id: Option<MapBtfTypeId>,
    },
    SectionData {
        name: String,
        bytes: &'a [u8],
    },
    ExistingMap(Map),
}

/// A BPF hash map structure
///
/// This provides higher level API for BPF maps whose type is
/// `BPF_MAP_TYPE_HASH`
pub struct HashMap<'a, K: Clone, V: Clone> {
    base: &'a Map,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

/// A BPF LRU hash map structure
///
/// This provides higher level API for BPF maps whose type is
/// `BPF_MAP_TYPE_LRU_HASH`
pub struct LruHashMap<'a, K: Clone, V: Clone> {
    base: &'a Map,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

/// A per-cpu BPF hash map structure
///
/// This provides higher level API for BPF maps whose type is
/// `BPF_MAP_TYPE_PERCPU_HASH`
pub struct PerCpuHashMap<'a, K: Clone, V: Clone> {
    base: &'a Map,
    _k: PhantomData<K>,
    _v: PhantomData<PerCpuValues<V>>,
}

/// An LRU per-cpu BPF hash map structure
///
/// This provides higher level API for BPF maps whose type is
/// `BPF_MAP_TYPE_LRU_PERCPU_HASH`
pub struct LruPerCpuHashMap<'a, K: Clone, V: Clone> {
    base: &'a Map,
    _k: PhantomData<K>,
    _v: PhantomData<PerCpuValues<V>>,
}

/// A stacktrace BPF map structure
///
/// Stacktrace map provides a feature of getting an array of instruction
/// pointers that are stored in the BPF map whose type is
/// `BPF_MAP_TYPE_STACK_TRACE`.
pub struct StackTrace<'a> {
    base: &'a Map,
}

/// SockMap structure for storing file descriptors of TCP sockets by userspace
/// program.
///
/// A sockmap is a BPF map type that holds references to sock structs. BPF
/// programs can use the sockmap to redirect `skb`s between sockets using
/// related BPF helpers.
///
/// The counterpart which is used by BPF program is:
/// [`redbpf_probes::maps::SockMap`](../redbpf_probes/maps/struct.SockMap.html).
pub struct SockMap<'a> {
    base: &'a Map,
}

/// Array map corresponding to BPF_MAP_TYPE_ARRAY
///
/// # Example
/// ```no_run
/// use redbpf::{load::Loader, Array};
/// let loaded = Loader::load(b"biolatpcts.elf").expect("error loading BPF program");
/// let biolat = Array::<u64>::new(loaded.map("biolat").expect("arr not found")).expect("error creating Array in userspace");
/// let v = biolat.get(0).unwrap();
/// ```
///
/// This structure is used by userspace programs. For BPF program's API, see [`redbpf_probes::maps::Array`](../redbpf_probes/maps/struct.Array.html)
pub struct Array<'a, T: Clone> {
    base: &'a Map,
    _element: PhantomData<T>,
}

/// Per-cpu array map corresponding to BPF_MAP_TYPE_PERCPU_ARRAY
///
/// # Example
/// ```no_run
/// use redbpf::{load::Loader, PerCpuArray, PerCpuValues};
/// let loaded = Loader::load(b"biolatpcts.elf").expect("error loading BPF program");
/// let biolat = PerCpuArray::<u64>::new(loaded.map("biolat").expect("arr not found")).expect("error creating Array in userspace");
/// let mut values = PerCpuValues::new(0);
/// values[0] = 1;
/// values[1] = 10;
/// biolat.set(0, &values);
/// ```
///
/// This structure is used by userspace programs. For BPF program's API, see [`redbpf_probes::maps::PerCpuArray`](../redbpf_probes/maps/struct.PerCpuArray.html)
pub struct PerCpuArray<'a, T: Clone> {
    base: &'a Map,
    _element: PhantomData<T>,
}

#[repr(C)]
#[derive(Clone)]
pub struct LpmTrieMapKey<T> {
    pub prefix_len: u32,
    pub data: T,
}

/// A BPF LPM trie map structure
///
/// This provides higher level API for BPF maps whose type is
/// `BPF_MAP_TYPE_LPM_TRIE`
pub struct LpmTrieMap<'a, K: Clone, V: Clone> {
    base: &'a Map,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

// TODO Use PERF_MAX_STACK_DEPTH
const BPF_MAX_STACK_DEPTH: usize = 127;
const BPF_FS_MAGIC: i64 = 0xcafe4a11;

#[repr(C)]
pub struct BpfStackFrames {
    pub ip: [u64; BPF_MAX_STACK_DEPTH],
}

/// Program array map.
///
/// An array of eBPF programs that can be used as a jump table.
///
/// To use this from eBPF code, see
/// [`redbpf_probes::maps::ProgramArray`](../redbpf_probes/maps/struct.ProgramArray.html).
pub struct ProgramArray<'a> {
    base: &'a Map,
}

#[allow(dead_code)]
pub struct RelocationInfo {
    target_sec_idx: usize,
    offset: u64,
    sym_idx: usize,
}

trait MapIterable<K: Clone, V: Clone> {
    fn get(&self, key: K) -> Option<V>;
    fn next_key(&self, key: Option<K>) -> Option<K>;
}

impl Program {
    #[allow(clippy::unnecessary_wraps)]
    fn new(kind: &str, name: &str, code: &[u8]) -> Result<Program> {
        let code = unsafe { zero::read_array_unsafe(code) }.to_vec();
        let name = name.to_string();

        let common = ProgramData {
            name,
            code,
            fd: None,
        };

        Ok(match kind {
            "kprobe" => Program::KProbe(KProbe {
                common,
                attach_type: ProbeAttachType::Entry,
                attachment_points: Vec::new(),
            }),
            "kretprobe" => Program::KProbe(KProbe {
                common,
                attach_type: ProbeAttachType::Return,
                attachment_points: Vec::new(),
            }),
            "uprobe" => Program::UProbe(UProbe {
                common,
                attach_type: ProbeAttachType::Entry,
                attachment_points: Vec::new(),
            }),
            "uretprobe" => Program::UProbe(UProbe {
                common,
                attach_type: ProbeAttachType::Return,
                attachment_points: Vec::new(),
            }),
            "tracepoint" => Program::TracePoint(TracePoint { common }),
            "socketfilter" => Program::SocketFilter(SocketFilter { common }),
            "xdp" => Program::XDP(XDP {
                common,
                interfaces: Vec::new(),
            }),
            "streamparser" => Program::StreamParser(StreamParser { common }),
            "streamverdict" => Program::StreamVerdict(StreamVerdict { common }),
            "sk_lookup" => Program::SkLookup(SkLookup { common, link: None }),
            _ => return Err(Error::Section(kind.to_string())),
        })
    }

    fn with_btf(kind: &str, name: &str, code: &[u8], btf: &BTF) -> Result<Program> {
        let code = unsafe { zero::read_array_unsafe(code) }.to_vec();
        let name = name.to_string();

        let common = ProgramData {
            name,
            code,
            fd: None,
        };

        Ok(match kind {
            "task_iter" => {
                let btf_id = btf
                    .find_type_id("bpf_iter_task", BtfKind::Function)
                    .ok_or_else(|| Error::BTF("type id of bpf_iter_task not found".to_string()))?;
                debug!("btf_id of bpf_iter_task: {}", btf_id);
                Program::TaskIter(TaskIter {
                    common,
                    attach_btf_id: btf_id,
                    link_fd: None,
                })
            }
            _ => return Err(Error::Section(kind.to_string())),
        })
    }

    fn to_prog_type(&self) -> bpf_prog_type {
        use Program::*;

        match self {
            KProbe(_) | KRetProbe(_) | UProbe(_) | URetProbe(_) => libbpf_sys::BPF_PROG_TYPE_KPROBE,
            XDP(_) => libbpf_sys::BPF_PROG_TYPE_XDP,
            SocketFilter(_) => libbpf_sys::BPF_PROG_TYPE_SOCKET_FILTER,
            TracePoint(_) => libbpf_sys::BPF_PROG_TYPE_TRACEPOINT,
            StreamParser(_) | StreamVerdict(_) => libbpf_sys::BPF_PROG_TYPE_SK_SKB,
            TaskIter(_) => libbpf_sys::BPF_PROG_TYPE_TRACING,
            SkLookup(_) => libbpf_sys::BPF_PROG_TYPE_SK_LOOKUP,
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
            StreamParser(p) => &p.common,
            StreamVerdict(p) => &p.common,
            TaskIter(p) => &p.common,
            SkLookup(p) => &p.common,
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
            StreamParser(p) => &mut p.common,
            StreamVerdict(p) => &mut p.common,
            TaskIter(p) => &mut p.common,
            SkLookup(p) => &mut p.common,
        }
    }

    pub fn name(&self) -> &str {
        &self.data().name
    }

    pub fn fd(&self) -> &Option<RawFd> {
        &self.data().fd
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
        if self.fd().is_some() {
            return Err(Error::ProgramAlreadyLoaded);
        }
        // Should bind CString to local variable not to make a dangling pointer
        // with .as_ptr() method
        let cname = CString::new(self.name().clone())?;
        let clicense = CString::new(license)?;

        let mut attr = unsafe { mem::zeroed::<libbpf_sys::bpf_load_program_attr>() };

        attr.prog_type = self.to_prog_type();
        attr.name = cname.as_ptr();
        attr.insns = self.data().code.as_ptr();
        attr.insns_cnt = self.data().code.len() as u64;
        attr.license = clicense.as_ptr();
        attr.log_level = 0;

        match self {
            Program::TaskIter(bpf_iter) => {
                attr.expected_attach_type = BPF_TRACE_ITER;
                attr.__bindgen_anon_2.attach_btf_id = bpf_iter.attach_btf_id;
            }
            Program::SkLookup(_) => {
                attr.expected_attach_type = BPF_SK_LOOKUP;
                attr.__bindgen_anon_1.kern_version = kernel_version;
            }
            _ => {
                attr.expected_attach_type = 0;
                attr.__bindgen_anon_1.kern_version = kernel_version;
            }
        }

        // do not pass log buffer. it is filled with verifier's log but
        // insufficient buffer size can cause ENOSPC error. pass log buffer
        // only after bpf_load_program_xattr fails
        let fd = unsafe { bpf_load_program_xattr(&attr, ptr::null_mut(), 0) };
        if fd >= 0 {
            self.data_mut().fd = Some(fd);
            return Ok(());
        }

        // At kernel v5.11, BPF switched from rlimit-based to memcg-based
        // memory accounting. So before that kernel version, memlock rlimit was
        // used for the memory accounting and bpf() syscall returned -EPERM on
        // exceeding the limit.
        if let Some(libc::EPERM) = io::Error::last_os_error().raw_os_error() {
            let mut uninit = MaybeUninit::<libc::rlimit>::zeroed();
            let p = uninit.as_mut_ptr();
            unsafe {
                if libc::getrlimit(libc::RLIMIT_MEMLOCK, p) == 0 {
                    (*p).rlim_max = libc::RLIM_INFINITY;
                    (*p).rlim_cur = (*p).rlim_max;
                    let rlim = uninit.assume_init();
                    if libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) == 0 {
                        let fd = bpf_load_program_xattr(&attr, ptr::null_mut(), 0);
                        if fd >= 0 {
                            self.data_mut().fd = Some(fd);
                            return Ok(());
                        }
                    }
                }
            }
        }

        // unknown error. print log from bpf verifier and give up loading BPF program
        attr.log_level = 1;
        let mut printed = false;
        let mut vec_len = 64 * 1024;
        while !printed {
            let mut buf_vec = vec![0; vec_len];
            let log_buffer: MutDataPtr = buf_vec.as_mut_ptr();
            let buf_size = buf_vec.capacity() * mem::size_of_val(unsafe { &*log_buffer });
            let fd =
                unsafe { libbpf_sys::bpf_load_program_xattr(&attr, log_buffer, buf_size as u64) };
            if fd >= 0 {
                warn!(
                    "bpf_load_program_xattr had failed but it unexpectedly succeeded while reproducing the error"
                );
                self.data_mut().fd = Some(fd);
                return Ok(());
            }
            if let Some(libc::ENOSPC) = io::Error::last_os_error().raw_os_error() {
                // If the size of the buffer is not large
                // enough to store all verifier messages, errno
                // is set to ENOSPC. So, pass the bigger log
                // buffer.
                vec_len *= 2;
                continue;
            }

            let cstr = unsafe { CStr::from_ptr(log_buffer) };
            error!(
                "error loading BPF program `{}' with bpf_load_program_xattr. ret={} os error={}: {}",
                self.name(),
                fd, io::Error::last_os_error(),
                cstr.to_str().unwrap()
            );
            printed = true;
        }

        Err(Error::BPF)
    }
}

impl Drop for ProgramData {
    fn drop(&mut self) {
        if self.fd.is_some() {
            unsafe {
                let _ = libc::close(self.fd.unwrap());
            }
        }
    }
}

fn pin_bpf_obj(fd: RawFd, file: impl AsRef<Path>) -> Result<()> {
    let mut file: PathBuf = PathBuf::from(file.as_ref());
    if file.exists() {
        error!("pinned path already exists: {:?}", file);
        return Err(Error::IO(io::Error::from(ErrorKind::AlreadyExists)));
    }
    if file.is_relative() {
        file = Path::new(".").join(file);
    }
    let dir = file.parent().unwrap();
    let existing_ancestor: Option<&Path> = dir.ancestors().find(|x| x.exists());
    if existing_ancestor.is_none() {
        if file.is_absolute() {
            error!("root directory does not exist");
        } else {
            error!("current working directory does not exist");
        }
        return Err(Error::IO(io::Error::from(ErrorKind::NotFound)));
    }
    unsafe {
        let path = existing_ancestor.unwrap();
        let cpath = CString::new(path.to_str().unwrap()).unwrap();
        let mut stat = mem::zeroed::<libc::statfs>();
        if libc::statfs(cpath.as_ptr(), &mut stat as *mut _) != 0 {
            error!("error on statfs {:?}: {}", path, io::Error::last_os_error());
            return Err(Error::IO(io::Error::last_os_error()));
        }
        if stat.f_type as i64 != BPF_FS_MAGIC {
            error!("not BPF FS");
            return Err(Error::IO(io::Error::from(ErrorKind::PermissionDenied)));
        }
    };
    fs::create_dir_all(dir)?;
    unsafe {
        let cpathname = CString::new(file.to_str().unwrap())?;
        if libbpf_sys::bpf_obj_pin(fd, cpathname.as_ptr()) != 0 {
            error!("error on bpf_obj_pin: {}", io::Error::last_os_error());
            Err(Error::IO(io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }
}

fn unpin_bpf_obj(file: impl AsRef<Path>) -> Result<()> {
    let _ = fs::remove_file(file)?;
    Ok(())
}

impl Drop for KProbeAttachmentPoint {
    fn drop(&mut self) {
        unsafe {
            let _ = perf::detach_perf_event(self.pfd);
            let _ = libc::close(self.pfd);
        }
    }
}

impl Drop for UProbeAttachmentPoint {
    fn drop(&mut self) {
        unsafe {
            let _ = perf::detach_perf_event(self.pfd);
            let _ = libc::close(self.pfd);
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
        unsafe {
            let pfd = match self.attach_type {
                ProbeAttachType::Entry => perf::open_kprobe_perf_event(fn_name, offset)?,

                ProbeAttachType::Return => perf::open_kretprobe_perf_event(fn_name, offset)?,
            };
            let ret = perf::attach_perf_event(fd, pfd);
            if ret.is_ok() {
                self.attachment_points.push(KProbeAttachmentPoint {
                    fn_name: fn_name.to_owned(),
                    offset,
                    pfd,
                });
            } else {
                libc::close(pfd);
            }
            ret
        }
    }

    /// Detach the `kprobe` or `kretprobe`
    ///
    /// This method is not needed to be called manually because all attachment
    /// points are detached and closed automatically when `KProbe` is
    /// dropped. But this method provides a feature for detaching a bpf program
    /// from kprobe event selectively.
    ///
    /// # Example
    /// ```no_run
    /// use redbpf::Module;
    /// let mut module = Module::parse(&std::fs::read("file.elf").unwrap()).unwrap();
    /// for kprobe in module.kprobes_mut() {
    ///     kprobe.attach_kprobe(&kprobe.name(), 0).unwrap();
    ///     // do some stuff...
    ///     kprobe.detach_kprobe(&kprobe.name(), 0).unwrap();
    /// }
    /// ```
    pub fn detach_kprobe(&mut self, fn_name: &str, offset: u64) -> Result<()> {
        // bpf program is detached from perf event and the perf event is closed
        // by dropping KProbeAttachmentPoint
        self.attachment_points
            .retain(|ap| !(ap.fn_name == fn_name && ap.offset == offset));
        Ok(())
    }

    pub fn name(&self) -> String {
        self.common.name.to_string()
    }

    pub fn attach_type_str(&self) -> &'static str {
        match self.attach_type {
            ProbeAttachType::Entry => "Kprobe",
            ProbeAttachType::Return => "Kretprobe",
        }
    }
}

impl UProbe {
    /// Attach the `uprobe` or `uretprobe`.
    ///
    /// Attach the probe to the function `fn_name` defined in the library or
    /// binary at `path`. If an `offset` is given, the probe will be attached at
    /// that byte offset inside the function. If `fn_name` is `None`, then
    /// `offset` is treated as an absolute address.
    ///
    /// If a `pid` is passed, only the corresponding process is traced.
    ///
    /// # Example
    /// ```no_run
    /// use redbpf::Module;
    /// let mut module = Module::parse(&std::fs::read("file.elf").unwrap()).unwrap();
    /// for uprobe in module.uprobes_mut() {
    ///     uprobe.attach_uprobe(Some(&uprobe.name()), 0, "/lib/x86_64-linux-gnu/libc-2.30.so", None).unwrap();
    /// }
    /// ```
    pub fn attach_uprobe(
        &mut self,
        fn_name: Option<&str>,
        offset: u64,
        target: &str,
        pid: Option<pid_t>,
    ) -> Result<()> {
        let fd = self.common.fd.ok_or(Error::ProgramNotLoaded)?;

        let path = if let Some(pid) = pid {
            resolve_proc_maps_lib(pid, target).unwrap_or_else(|| target.to_string())
        } else {
            match (target.starts_with('/'), LD_SO_CACHE.as_ref()) {
                (false, Ok(cache)) => cache.resolve(target).unwrap_or(target).to_string(),
                _ => target.to_owned(),
            }
        };
        let sym_offset = if let Some(fn_name) = fn_name {
            let data = fs::read(&path)?;
            let parser = ElfSymbols::parse(&data)?;
            parser
                .resolve(fn_name)
                .ok_or_else(|| Error::SymbolNotFound(fn_name.to_string()))?
                .st_value
        } else {
            0
        };
        unsafe {
            let pfd = match self.attach_type {
                ProbeAttachType::Entry => {
                    perf::open_uprobe_perf_event(&path, offset + sym_offset, pid)?
                }
                ProbeAttachType::Return => {
                    perf::open_uretprobe_perf_event(&path, offset + sym_offset, pid)?
                }
            };
            let ret = perf::attach_perf_event(fd, pfd);
            if ret.is_ok() {
                self.attachment_points.push(UProbeAttachmentPoint {
                    fn_name: fn_name.map(String::from),
                    offset,
                    target: target.to_owned(),
                    pid,
                    pfd,
                });
            } else {
                libc::close(pfd);
            }
            ret
        }
    }

    /// Detach the `uprobe` or `uretprobe`
    ///
    /// This method is not needed to be called manually because all attachment
    /// points are detached and closed automatically when `UProbe` is
    /// dropped. But this method provides a feature for detaching a bpf program
    /// from uprobe event selectively.
    ///
    /// # Example
    /// ```no_run
    /// use redbpf::Module;
    /// let mut module = Module::parse(&std::fs::read("file.elf").unwrap()).unwrap();
    /// let uprobe = module.uprobe_mut("count_strlen").expect("bpf program not found");
    /// uprobe.attach_uprobe(Some(&uprobe.name()), 0, "/lib/x86_64-linux-gnu/libc-2.30.so", None).unwrap();
    /// // do some stuff...
    /// uprobe.detach_uprobe(Some(&uprobe.name()), 0, "/lib/x86_64-linux-gnu/libc-2.30.so", None);
    /// ```
    pub fn detach_uprobe(
        &mut self,
        fn_name: Option<&str>,
        offset: u64,
        target: &str,
        pid: Option<pid_t>,
    ) -> Result<()> {
        // bpf program is detached from perf event and the perf event is closed
        // by dropping UProbeAttachmentPoint
        self.attachment_points.retain(|ap| {
            !(ap.fn_name.as_deref() == fn_name
                && ap.offset == offset
                && ap.target == target
                && ap.pid == pid)
        });
        Ok(())
    }

    pub fn name(&self) -> String {
        self.common.name.to_string()
    }
}

impl TracePoint {
    pub fn attach_trace_point(&mut self, category: &str, name: &str) -> Result<()> {
        let fd = self.common.fd.ok_or(Error::ProgramNotLoaded)?;
        // TODO Check this works correctly
        unsafe {
            let pfd = perf::open_tracepoint_perf_event(category, name)?;
            perf::attach_perf_event(fd, pfd)
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
        self.attach_xdp_by_index(if_nametoindex(interface)?, flags)
    }

    /// Attach the XDP program to interface by it's index.
    ///
    /// Attach the XDP program to the given network interface.
    ///
    /// # Example
    /// ```no_run
    /// # use redbpf::{Module, xdp};
    /// # let mut module = Module::parse(&std::fs::read("file.elf").unwrap()).unwrap();
    /// # for uprobe in module.xdps_mut() {
    /// uprobe.attach_xdp_by_index(2, xdp::Flags::default()).unwrap();
    /// # }
    /// ```
    pub fn attach_xdp_by_index(&mut self, ifindex: u32, flags: xdp::Flags) -> Result<()> {
        let fd = self.common.fd.ok_or(Error::ProgramNotLoaded)?;
        self.interfaces.push(ifindex);
        if let Err(e) = unsafe { attach_xdp(ifindex, fd, flags as u32) } {
            if let Error::IO(oserr) = e {
                error!("error attaching xdp to interface #{}: {}", ifindex, oserr);
            }
            Err(Error::BPF)
        } else {
            Ok(())
        }
    }

    /// Detach the XDP program.
    ///
    /// Detach the XDP program from the given network interface, if attached.
    ///
    /// # Example
    /// ```no_run
    /// # use redbpf::{Module, xdp};
    /// # let mut module = Module::parse(&std::fs::read("file.elf").unwrap()).unwrap();
    /// # for uprobe in module.xdps_mut() {
    /// uprobe.attach_xdp("eth0", xdp::Flags::default()).unwrap();
    /// uprobe.detach_xdp("eth0").unwrap();
    /// # }
    /// ```
    pub fn detach_xdp(&mut self, interface: &str) -> Result<()> {
        self.detach_xdp_by_index(if_nametoindex(interface)?)
    }

    /// Detach the XDP program from interface by it's index.
    ///
    /// Detach the XDP program from the given network interface, if attached.
    ///
    /// # Example
    /// ```no_run
    /// # use redbpf::{Module, xdp};
    /// # let mut module = Module::parse(&std::fs::read("file.elf").unwrap()).unwrap();
    /// # for uprobe in module.xdps_mut() {
    /// uprobe.attach_xdp_by_index(23, xdp::Flags::default()).unwrap();
    /// uprobe.detach_xdp_by_index(23).unwrap();
    /// # }
    /// ```
    pub fn detach_xdp_by_index(&mut self, ifindex: u32) -> Result<()> {
        // The linear search here isn't great, but self.interfaces will almost always be short.
        let index = self
            .interfaces
            .iter()
            .enumerate()
            .find_map(|(i, v)| (*v == ifindex).then(|| i))
            .ok_or(Error::ProgramNotLoaded)?;
        if let Err(e) = unsafe { detach_xdp(ifindex) } {
            if let Error::IO(ref oserr) = e {
                error!(
                    "error detaching xdp from interface #{}: {}",
                    ifindex, oserr
                );
            }
            return Err(e);
        }
        self.interfaces.swap_remove(index);
        Ok(())
    }

    pub fn name(&self) -> String {
        self.common.name.to_string()
    }
}

impl Drop for XDP {
    fn drop(&mut self) {
        for ifindex in self.interfaces.iter() {
            let _ = unsafe { detach_xdp(*ifindex) };
        }
    }
}

unsafe fn open_raw_sock(name: &str) -> Result<RawFd> {
    let sock = libc::socket(
        libc::PF_PACKET,
        libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
        (libc::ETH_P_ALL as u16).to_be().into(),
    );
    if sock < 0 {
        return Err(Error::IO(io::Error::last_os_error()));
    }

    // Do not bind on empty interface names
    if name.is_empty() {
        return Ok(sock);
    }

    let mut sll = mem::zeroed::<libc::sockaddr_ll>();
    sll.sll_family = libc::AF_PACKET as u16;
    let ciface = CString::new(name).unwrap();
    sll.sll_ifindex = libc::if_nametoindex(ciface.as_ptr()) as i32;
    if sll.sll_ifindex == 0 {
        libc::close(sock);
        return Err(Error::IO(io::Error::last_os_error()));
    }

    sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be() as u16;
    if libc::bind(
        sock,
        &sll as *const _ as *const _,
        mem::size_of_val(&sll) as u32,
    ) < 0
    {
        libc::close(sock);
        return Err(Error::IO(io::Error::last_os_error()));
    }

    Ok(sock)
}

fn if_nametoindex(dev_name: &str) -> Result<u32> {
    let ciface = CString::new(dev_name).unwrap();
    let ifindex = unsafe { libc::if_nametoindex(ciface.as_ptr()) };
    if ifindex == 0 {
        return Err(Error::IO(io::Error::last_os_error()));
    }
    Ok(ifindex)
}

unsafe fn attach_xdp(ifindex: u32, progfd: libc::c_int, flags: libc::c_uint) -> Result<()> {
    if libbpf_sys::bpf_set_link_xdp_fd(ifindex as i32, progfd, flags) != 0 {
        return Err(Error::IO(io::Error::last_os_error()));
    }
    Ok(())
}

unsafe fn detach_xdp(ifindex: u32) -> Result<()> {
    attach_xdp(ifindex, -1, 0)
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
        unsafe {
            let sfd = open_raw_sock(interface)?;
            if libc::setsockopt(
                sfd,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_BPF,
                &fd as *const _ as *const _,
                mem::size_of_val(&fd) as u32,
            ) < 0
            {
                libc::close(sfd);
                Err(Error::IO(io::Error::last_os_error()))
            } else {
                Ok(sfd)
            }
        }
    }

    pub fn name(&self) -> String {
        self.common.name.to_string()
    }
}

impl SkLookup {
    /// Attach the `sk_lookup` to the given network namespace.
    ///
    /// In most cases it should be attached to `/proc/self/ns/net`.
    pub fn attach_sk_lookup(&mut self, namespace: &str) -> Result<()> {
        if self.link.is_some() {
            return Err(Error::ProgramAlreadyLinked);
        }

        let fd = self.common.fd.ok_or(Error::ProgramNotLoaded)?;
        unsafe {
            let namespace = CString::new(namespace)?;
            let nfd = libc::open(namespace.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
            if nfd < 0 {
                return Err(Error::IO(io::Error::last_os_error()));
            }

            let lfd = bpf_link_create(fd, nfd, BPF_SK_LOOKUP, ptr::null());
            if lfd < 0 {
                libc::close(nfd);
                return Err(Error::IO(io::Error::last_os_error()));
            }

            self.link = Some((nfd, lfd));
        }

        Ok(())
    }
}

impl Drop for SkLookup {
    fn drop(&mut self) {
        if let Some((nfd, lfd)) = self.link.take() {
            unsafe {
                libc::close(lfd);
                libc::close(nfd);
            }
        }
    }
}

impl Module {
    pub fn parse(bytes: &[u8]) -> Result<Module> {
        ModuleBuilder::parse(bytes)?.to_module()
    }

    pub fn map(&self, name: &str) -> Option<&Map> {
        self.maps.iter().find(|m| m.name == name)
    }

    pub fn map_mut(&mut self, name: &str) -> Option<&mut Map> {
        self.maps.iter_mut().find(|m| m.name == name)
    }

    pub fn program(&self, name: &str) -> Option<&Program> {
        self.programs.iter().find(|p| p.name() == name)
    }

    pub fn program_mut(&mut self, name: &str) -> Option<&mut Program> {
        self.programs.iter_mut().find(|p| p.name() == name)
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

    pub fn kprobe_mut(&mut self, name: &str) -> Option<&mut KProbe> {
        self.kprobes_mut().find(|p| p.common.name == name)
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

    pub fn uprobe_mut(&mut self, name: &str) -> Option<&mut UProbe> {
        self.uprobes_mut().find(|p| p.common.name == name)
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

    pub fn xdp_mut(&mut self, name: &str) -> Option<&mut XDP> {
        self.xdps_mut().find(|p| p.common.name == name)
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

    pub fn socket_filter_mut(&mut self, name: &str) -> Option<&mut SocketFilter> {
        self.socket_filters_mut().find(|p| p.common.name == name)
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

    pub fn trace_point_mut(&mut self, name: &str) -> Option<&mut TracePoint> {
        self.trace_points_mut().find(|p| p.common.name == name)
    }

    pub fn stream_parsers(&self) -> impl Iterator<Item = &StreamParser> {
        use Program::*;
        self.programs.iter().filter_map(|prog| match prog {
            StreamParser(p) => Some(p),
            _ => None,
        })
    }

    pub fn stream_parsers_mut(&mut self) -> impl Iterator<Item = &mut StreamParser> {
        use Program::*;
        self.programs.iter_mut().filter_map(|prog| match prog {
            StreamParser(p) => Some(p),
            _ => None,
        })
    }

    pub fn stream_parser_mut(&mut self, name: &str) -> Option<&mut StreamParser> {
        self.stream_parsers_mut().find(|p| p.common.name == name)
    }

    pub fn stream_verdicts(&self) -> impl Iterator<Item = &StreamVerdict> {
        use Program::*;
        self.programs.iter().filter_map(|prog| match prog {
            StreamVerdict(p) => Some(p),
            _ => None,
        })
    }

    pub fn stream_verdicts_mut(&mut self) -> impl Iterator<Item = &mut StreamVerdict> {
        use Program::*;
        self.programs.iter_mut().filter_map(|prog| match prog {
            StreamVerdict(p) => Some(p),
            _ => None,
        })
    }

    pub fn stream_verdict_mut(&mut self, name: &str) -> Option<&mut StreamVerdict> {
        self.stream_verdicts_mut().find(|p| p.common.name == name)
    }

    pub fn sk_lookups(&self) -> impl Iterator<Item = &SkLookup> {
        use Program::*;
        self.programs.iter().filter_map(|prog| match prog {
            SkLookup(p) => Some(p),
            _ => None,
        })
    }

    pub fn sk_lookups_mut(&mut self) -> impl Iterator<Item = &mut SkLookup> {
        use Program::*;
        self.programs.iter_mut().filter_map(|prog| match prog {
            SkLookup(p) => Some(p),
            _ => None,
        })
    }

    pub fn sk_lookup_mut(&mut self, name: &str) -> Option<&mut SkLookup> {
        self.sk_lookups_mut().find(|p| p.common.name == name)
    }

    pub fn task_iters(&self) -> impl Iterator<Item = &TaskIter> {
        use Program::*;
        self.programs.iter().filter_map(|prog| match prog {
            TaskIter(p) => Some(p),
            _ => None,
        })
    }

    pub fn task_iters_mut(&mut self) -> impl Iterator<Item = &mut TaskIter> {
        use Program::*;
        self.programs.iter_mut().filter_map(|prog| match prog {
            TaskIter(p) => Some(p),
            _ => None,
        })
    }

    pub fn task_iter_mut(&mut self, name: &str) -> Option<&mut TaskIter> {
        self.task_iters_mut().find(|p| p.common.name == name)
    }
}

impl<'a> ModuleBuilder<'a> {
    /// Parse binary data of ELF relocatable file
    ///
    /// # Example
    /// ```no_run
    /// # static ELF_BINARY: [u8; 128] = [0u8; 128];
    /// # fn probe_code() -> &'static [u8] { &ELF_BINARY }
    /// use redbpf::ModuleBuilder;
    /// let mut builder = ModuleBuilder::parse(probe_code()).expect("error on ModuleBuilder::parse");
    /// ```
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let object = Elf::parse(bytes)?;
        let strtab = &object.strtab;
        let symtab = object.syms.to_vec();
        let shdr_relocs = &object.shdr_relocs;

        let mut rels = vec![];
        let mut programs = RSHashMap::new();
        // maps: section header index => map
        let mut map_builders = RSHashMap::new();
        // symval_to_maps: symbol value => map
        let mut symval_to_map_builders = RSHashMap::new();

        let mut license = String::new();
        let mut version = 0u32;
        // BTF is optional
        let btf: Option<BTF> = BTF::parse_elf(&object, bytes)
            .and_then(|mut btf| btf.load().map(|_| btf))
            .or_else(|e| {
                warn!("Failed to load BTF but BTF is optional. Ignore it");
                Err(e)
            })
            .ok();
        let mut vmlinux_btf = None;
        for (shndx, shdr) in object.section_headers.iter().enumerate() {
            let (kind, name) = get_split_section_name(&object, &shdr, shndx)?;

            let section_type = shdr.sh_type;
            let content = data(&bytes, &shdr);
            match (section_type, kind, name) {
                (hdr::SHT_REL, _, _) => add_relocation(&mut rels, shndx, &shdr, shdr_relocs),
                (hdr::SHT_PROGBITS, Some("version"), _) => version = get_version(&content),
                (hdr::SHT_PROGBITS, Some("license"), _) => {
                    license = zero::read_str(content).to_string()
                }
                (hdr::SHT_NOBITS, Some(name @ ".bss"), None) => {
                    let map_builder = MapBuilder::with_section_data(name, &content)?;
                    map_builders.insert(shndx, map_builder);
                }
                (hdr::SHT_PROGBITS, Some(name), None)
                    if name.starts_with(".data") || name.starts_with(".rodata") =>
                {
                    let map_builder = MapBuilder::with_section_data(name, &content)?;
                    map_builders.insert(shndx, map_builder);
                }
                (hdr::SHT_PROGBITS, Some("maps"), Some(name)) => {
                    let syms = symtab
                        .iter()
                        .filter(|sym| sym.st_shndx == shndx)
                        .collect::<Vec<&Sym>>();
                    if syms.len() > 1 {
                        error!("{} maps are defined in section `{}`. Only `maps` section is allowed to accommodate multiple maps", syms.len(), get_section_name(&object, shdr).unwrap());
                        return Err(Error::Map);
                    }
                    let mut map_builder = MapBuilder::parse(name, &content)?;
                    if let Some(ref btf) = btf {
                        if let Some(ref sym) = syms.get(0) {
                            // Map's name and map's symbol name can be
                            // different each other. But BTF info can be found
                            // by map's symbol name.
                            let map_sym_name = strtab.get_at(sym.st_name).ok_or(Error::ElfError)?;
                            if let Ok(map_btf_type_id) = btf.get_map_type_ids(map_sym_name) {
                                debug!("Map `{}' has BTF info. {:?}", name, map_btf_type_id);
                                let _ = map_builder.set_btf(map_btf_type_id);
                            }
                        }
                    }
                    map_builders.insert(shndx, map_builder);
                }
                (hdr::SHT_PROGBITS, Some("maps"), None) => {
                    // Somehow clang direct compiled binary (in C) uses this approach to define maps.
                    // More specifically, the maps contains all map definitions (except names).
                    let maps_syms = symtab.iter().filter(|sym| sym.st_shndx == shndx);

                    for sym in maps_syms {
                        let offset = sym.st_value as usize;
                        let name = strtab.get_at(sym.st_name).ok_or(Error::ElfError)?;
                        let cur_content = &content[offset..];
                        let mut map_builder = MapBuilder::parse(name, cur_content)?;
                        if let Some(ref btf) = btf {
                            if let Ok(map_btf_type_id) = btf.get_map_type_ids(name) {
                                debug!(
                                    "Map `{}' in the maps section has BTF info. {:?}",
                                    name, map_btf_type_id
                                );
                                let _ = map_builder.set_btf(map_btf_type_id);
                            }
                        }
                        symval_to_map_builders.insert(sym.st_value, map_builder);
                    }
                }
                (hdr::SHT_PROGBITS, Some(kind @ "kprobe"), Some(name))
                | (hdr::SHT_PROGBITS, Some(kind @ "kretprobe"), Some(name))
                | (hdr::SHT_PROGBITS, Some(kind @ "uprobe"), Some(name))
                | (hdr::SHT_PROGBITS, Some(kind @ "uretprobe"), Some(name))
                | (hdr::SHT_PROGBITS, Some(kind @ "xdp"), Some(name))
                | (hdr::SHT_PROGBITS, Some(kind @ "socketfilter"), Some(name))
                | (hdr::SHT_PROGBITS, Some(kind @ "streamparser"), Some(name))
                | (hdr::SHT_PROGBITS, Some(kind @ "streamverdict"), Some(name))
                | (hdr::SHT_PROGBITS, Some(kind @ "sk_lookup"), Some(name)) => {
                    let prog = Program::new(kind, name, &content)?;
                    programs.insert(shndx, prog);
                }
                (hdr::SHT_PROGBITS, Some(kind @ "task_iter"), Some(name)) => {
                    if vmlinux_btf.is_none() {
                        vmlinux_btf = Some(btf::parse_vmlinux_btf().map_err(|e| {
                            // Raise an error because BPF iter programs can not run without BTF support.
                            error!("error on btf::parse_vmlinux_btf: {:?}", e);
                            e
                        })?);
                    }

                    let prog =
                        Program::with_btf(kind, name, &content, vmlinux_btf.as_ref().unwrap())
                            .map_err(|e| {
                                error!("error on Program::with_btf for {}/{}: {:?}", kind, name, e);
                                e
                            })?;
                    programs.insert(shndx, prog);
                }
                _ => {}
            }
        }

        Ok(ModuleBuilder {
            object,
            programs,
            map_builders,
            symval_to_map_builders,
            rels,
            license,
            version,
            btf,
        })
    }

    /// Create [`Module`](struct.Module.html) from `ModuleBuilder`
    ///
    /// When this method is called, `ModuleBuilder` is moved out so the
    /// instance can not be used any more.
    ///
    /// # Example
    /// ```no_run
    /// # let arr = [0u8; 128];
    /// # let bytes = &arr;
    /// use redbpf::ModuleBuilder;
    /// let module = ModuleBuilder::parse(bytes).expect("error on ModuleBuilder::parse").to_module();
    /// ```
    pub fn to_module(mut self) -> Result<Module> {
        let symtab = self.object.syms.to_vec();
        let mut maps = RSHashMap::new();
        for (shndx, map_builder) in self.map_builders.into_iter() {
            let map = map_builder.to_map()?;
            maps.insert(shndx, map);
        }

        let mut symval_to_maps = RSHashMap::new();
        for (symval, map_builder) in self.symval_to_map_builders.into_iter() {
            let map = map_builder.to_map()?;
            symval_to_maps.insert(symval, map);
        }

        // Rewrite programs with relocation data
        for rel in self.rels.iter() {
            if self.programs.contains_key(&rel.target_sec_idx) {
                if let Err(_) = rel.apply(&mut self.programs, &maps, &symtab) {
                    // means that not normal case, we should rely on symbol value instead of section header index
                    rel.apply_with_symmap(&mut self.programs, &symval_to_maps, &symtab)
                        .map_err(|e| {
                            error!("can not relocate map");
                            e
                        })?;
                }
            }
        }

        let programs = self.programs.drain().map(|(_, v)| v).collect();
        let mut maps: Vec<Map> = maps.drain().map(|(_, v)| v).collect();
        maps.extend(symval_to_maps.drain().map(|(_, v)| v));

        Ok(Module {
            programs,
            maps,
            license: self.license,
            version: self.version,
        })
    }

    /// Replace a map whose name is `map_name` with a `new` [`Map`](struct.Map.html)
    ///
    /// This method can fail if there does not exist a map whose name is
    /// `map_name` or definitions of `new` map and a map whose name is
    /// `map_name` do not match each other. The compared definition includes
    /// key size, value size, map type and the max entry number.
    ///
    /// # Example
    /// ```no_run
    /// # let arr = [0u8; 128];
    /// # let bytes = &arr;
    /// use redbpf::{ModuleBuilder, Map};
    /// let mut builder = ModuleBuilder::parse(bytes).expect("error on ModuleBuilder::parse");
    /// builder.replace_map("sharedmap", Map::from_pin_file("/sys/fs/bpf/sharedmap").expect("error on Map::from_pin_file")).expect("error on ModuleBuilder::replace_map");
    /// let mut module = builder.to_module().expect("error on ModuleBuilder::to_module");
    /// ```
    pub fn replace_map(&mut self, map_name: &str, new: Map) -> Result<&mut Self> {
        for (_, map_builder) in self.map_builders.iter_mut() {
            match map_builder {
                MapBuilder::Normal {
                    name,
                    def,
                    btf_type_id: _,
                } => {
                    if name == map_name {
                        if !(def.type_ == new.config.type_
                            && def.key_size == new.config.key_size
                            && def.value_size == new.config.value_size
                            && def.max_entries == new.config.max_entries)
                        {
                            error!("map definition does not match");
                            return Err(Error::Map);
                        }
                        *map_builder = MapBuilder::with_existing_map(new)?;
                        return Ok(self);
                    }
                }
                MapBuilder::SectionData { name, .. } => {
                    if name == map_name {
                        if !new.section_data {
                            error!("map is not for section data");
                            return Err(Error::Map);
                        }
                        *map_builder = MapBuilder::with_existing_map(new)?;
                        return Ok(self);
                    }
                }
                MapBuilder::ExistingMap(map) => {
                    if map.name == map_name {
                        if !(map.config.type_ == new.config.type_
                            && map.config.key_size == new.config.key_size
                            && map.config.value_size == new.config.value_size
                            && map.config.max_entries == new.config.max_entries)
                        {
                            error!("map definition does not match");
                            return Err(Error::Map);
                        }
                        *map_builder = MapBuilder::with_existing_map(new)?;
                        return Ok(self);
                    }
                }
            }
        }
        error!("map of which name is `{}' not found", map_name);
        Err(Error::Map)
    }
}

fn get_section_name<'o>(object: &'o Elf, shdr: &SectionHeader) -> Result<&'o str> {
    let name = object
        .shdr_strtab
        .get_unsafe(shdr.sh_name)
        .ok_or_else(|| Error::Section(format!("Section name not found")))?;
    Ok(name)
}

#[inline]
fn get_split_section_name<'o>(
    object: &'o Elf<'_>,
    shdr: &'o SectionHeader,
    shndx: usize,
) -> Result<(Option<&'o str>, Option<&'o str>)> {
    let name = get_section_name(object, shdr)
        .or_else(|_| Err(Error::Section(format!("Section name not found: {}", shndx))))?;

    let mut names = name.splitn(2, '/');

    let kind = names.next();
    let name = names.next();

    Ok((kind, name))
}

impl RelocationInfo {
    #[inline]
    pub fn apply(
        &self,
        programs: &mut RSHashMap<usize, Program>,
        maps: &RSHashMap<usize, Map>,
        symtab: &[Sym],
    ) -> Result<()> {
        // get the program we need to apply relocations to based on the program section index
        let prog = programs.get_mut(&self.target_sec_idx).ok_or(Error::Reloc)?;
        // lookup the symbol we're relocating in the symbol table
        let sym = symtab[self.sym_idx];
        // get the map referenced by the program based on the symbol section index
        let insn_idx = (self.offset / std::mem::size_of::<bpf_insn>() as u64) as usize;
        let code = &mut prog.data_mut().code;
        let map = maps.get(&sym.st_shndx).ok_or(Error::Reloc)?;

        // the index of the instruction we need to patch
        if map.section_data {
            code[insn_idx].set_src_reg(libbpf_sys::BPF_PSEUDO_MAP_VALUE as u8);
            code[insn_idx + 1].imm = code[insn_idx].imm + sym.st_value as i32;
        } else {
            code[insn_idx].set_src_reg(libbpf_sys::BPF_PSEUDO_MAP_FD as u8);
        }
        code[insn_idx].imm = map.fd;
        Ok(())
    }

    #[inline]
    fn apply_with_symmap(
        &self,
        programs: &mut RSHashMap<usize, Program>,
        symval_to_maps: &RSHashMap<u64, Map>,
        symtab: &[Sym],
    ) -> Result<()> {
        let prog = programs.get_mut(&self.target_sec_idx).ok_or(Error::Reloc)?;
        let sym = symtab[self.sym_idx];
        let insn_idx = (self.offset / std::mem::size_of::<bpf_insn>() as u64) as usize;
        let code = &mut prog.data_mut().code;
        let map = symval_to_maps.get(&sym.st_value).ok_or(Error::Reloc)?;
        code[insn_idx].set_src_reg(libbpf_sys::BPF_PSEUDO_MAP_FD as u8);
        code[insn_idx].imm = map.fd;
        Ok(())
    }
}

impl Map {
    pub fn load(name: &str, code: &[u8]) -> Result<Map> {
        let config: bpf_map_def = *unsafe { zero::read_unsafe(code) };
        Map::with_map_def(name, config, None)
    }

    fn with_section_data(name: &str, data: &[u8], flags: u32) -> Result<Map> {
        let mut map = Map::with_map_def(
            name,
            bpf_map_def {
                type_: libbpf_sys::BPF_MAP_TYPE_ARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: data.len() as u32,
                max_entries: 1,
                map_flags: flags,
            },
            None,
        )?;
        map.section_data = true;
        // for BSS we don't need to copy the data, it's already 0-initialized
        if name != ".bss" {
            unsafe {
                let ret = libbpf_sys::bpf_map_update_elem(
                    map.fd,
                    &mut 0 as *mut _ as *mut _,
                    data.as_ptr() as *mut u8 as *mut _,
                    0,
                );
                if ret < 0 {
                    return Err(Error::BPF);
                }
            }
        }
        Ok(map)
    }

    fn with_map_def(
        name: &str,
        config: bpf_map_def,
        btf_type_id: Option<MapBtfTypeId>,
    ) -> Result<Map> {
        let cname = CString::new(name)?;
        let attr = unsafe {
            let mut attr_uninit = MaybeUninit::<bpf_create_map_attr>::zeroed();
            let attr_ptr = attr_uninit.as_mut_ptr();
            (*attr_ptr).name = cname.as_ptr();
            (*attr_ptr).map_type = config.type_;
            (*attr_ptr).map_flags = config.map_flags;
            (*attr_ptr).key_size = config.key_size;
            (*attr_ptr).value_size = config.value_size;
            (*attr_ptr).max_entries = config.max_entries;
            if let Some(type_id) = btf_type_id {
                (*attr_ptr).btf_fd = type_id.btf_fd as u32;
                (*attr_ptr).btf_key_type_id = type_id.key_type_id;
                (*attr_ptr).btf_value_type_id = type_id.value_type_id;
            }
            attr_uninit.assume_init()
        };
        let mut fd = unsafe { bpf_create_map_xattr(&attr) };
        // At kernel v5.11, BPF switched from rlimit-based to memcg-based
        // memory accounting. So before that kernel version, memlock rlimit was
        // used for the memory accounting and bpf() syscall returned -EPERM on
        // exceeding the limit.
        if fd < 0 {
            if let Some(libc::EPERM) = io::Error::last_os_error().raw_os_error() {
                let mut uninit = MaybeUninit::<libc::rlimit>::zeroed();
                let p = uninit.as_mut_ptr();
                unsafe {
                    if libc::getrlimit(libc::RLIMIT_MEMLOCK, p) == 0 {
                        (*p).rlim_max = libc::RLIM_INFINITY;
                        (*p).rlim_cur = (*p).rlim_max;
                        let rlim = uninit.assume_init();
                        if libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) == 0 {
                            fd = bpf_create_map_xattr(&attr);
                        }
                    }
                }
            }
        }
        if fd >= 0 {
            Ok(Map {
                name: name.to_string(),
                kind: config.type_,
                fd,
                config,
                section_data: false,
                pin_file: None,
            })
        } else {
            error!(
                "error on bpf_create_map_xattr. failed to load map `{}`: {}",
                name,
                io::Error::last_os_error()
            );
            Err(Error::Map)
        }
    }

    /// Create `Map` from a file which represents pinned map
    ///
    /// # Example
    /// ```no_run
    /// use redbpf::{Array, Map};
    /// let map = Map::from_pin_file("/sys/fs/bpf/persist_map").expect("error on creating map from file");
    /// let array = Array::<u64>::new(&map).expect("error on creating array");
    /// ```
    pub fn from_pin_file(file: impl AsRef<Path>) -> Result<Map> {
        let file = file.as_ref();
        let fd = unsafe {
            let cpathname = CString::new(file.to_str().unwrap())?;
            libbpf_sys::bpf_obj_get(cpathname.as_ptr())
        };
        if fd < 0 {
            error!("error on bpf_obj_get: {}", io::Error::last_os_error());
            return Err(Error::IO(io::Error::last_os_error()));
        }
        let map_info = unsafe {
            let mut info = mem::zeroed::<bpf_map_info>();
            let mut info_len = mem::size_of_val(&info) as u32;
            if libbpf_sys::bpf_obj_get_info_by_fd(fd, &mut info as *mut _ as *mut _, &mut info_len)
                != 0
            {
                error!(
                    "error on bpf_obj_get_info_by_fd: {}",
                    io::Error::last_os_error()
                );
                return Err(Error::IO(io::Error::last_os_error()));
            }
            info
        };

        let name = unsafe {
            CStr::from_ptr(&map_info.name as *const _)
                .to_string_lossy()
                .into_owned()
        };
        Ok(Map {
            name,
            kind: map_info.type_,
            fd,
            config: bpf_map_def {
                type_: map_info.type_,
                key_size: map_info.key_size,
                value_size: map_info.value_size,
                max_entries: map_info.max_entries,
                map_flags: map_info.map_flags,
            },
            section_data: false,
            pin_file: Some(Box::from(file)),
        })
    }

    /// Pin map to BPF FS
    ///
    /// # Example
    /// ```no_run
    /// use redbpf::Module;
    /// use redbpf::load::Loader;
    /// let mut loaded = Loader::load_file("file.elf").expect("error loading probe");
    /// loaded.map_mut("persist_map").expect("map not found").pin("/sys/fs/bpf/persist_map").expect("error on pinning");
    /// ```
    pub fn pin(&mut self, file: impl AsRef<Path>) -> Result<()> {
        let file = file.as_ref();
        if self.pin_file.is_some() {
            error!("already pinned");
            return Err(Error::Map);
        }
        pin_bpf_obj(self.fd, file)?;
        self.pin_file = Some(Box::from(file));
        Ok(())
    }

    /// Unpin map
    ///
    /// # Example
    /// ```no_run
    /// use redbpf::Module;
    /// use redbpf::load::Loader;
    /// let mut loaded = Loader::load_file("file.elf").expect("error loading probe");
    /// let persist_map = loaded.map_mut("persist_map").expect("map not found");
    /// persist_map.pin("/sys/fs/bpf/persist_map").expect("error on pinning");
    /// // do some stuff...
    /// persist_map.unpin().expect("error on unpinning");
    /// ```
    pub fn unpin(&mut self) -> Result<()> {
        if self.pin_file.is_none() {
            error!("not pinned");
            return Err(Error::Map);
        }
        unpin_bpf_obj(self.pin_file.as_ref().unwrap())?;
        self.pin_file = None;
        Ok(())
    }
}

impl Drop for Map {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::close(self.fd);
        }
    }
}

impl<'a> MapBuilder<'a> {
    fn parse(name: &str, bytes: &[u8]) -> Result<Self> {
        let def = unsafe { ptr::read_unaligned(bytes.as_ptr() as *const bpf_map_def) };
        Ok(MapBuilder::Normal {
            def,
            name: name.to_string(),
            btf_type_id: None,
        })
    }

    fn with_section_data(name: &str, bytes: &'a [u8]) -> Result<Self> {
        Ok(MapBuilder::SectionData {
            name: name.to_string(),
            bytes,
        })
    }

    fn with_existing_map(map: Map) -> Result<Self> {
        Ok(MapBuilder::ExistingMap(map))
    }

    fn set_btf(&mut self, type_id: MapBtfTypeId) -> Result<&mut Self> {
        match self {
            MapBuilder::Normal { btf_type_id, .. } => {
                *btf_type_id = Some(type_id);
                Ok(self)
            }
            MapBuilder::SectionData { .. } => {
                error!("map for section data does not support BTF");
                Err(Error::Map)
            }
            MapBuilder::ExistingMap(_) => {
                error!("can not set BTF type id to already existing map");
                Err(Error::Map)
            }
        }
    }

    fn to_map(self) -> Result<Map> {
        match self {
            MapBuilder::Normal {
                name,
                def,
                btf_type_id,
            } => Map::with_map_def(name.as_ref(), def, btf_type_id),
            MapBuilder::SectionData { name, bytes } => Map::with_section_data(
                name.as_ref(),
                bytes,
                if name.starts_with(".rodata") {
                    libbpf_sys::BPF_F_RDONLY_PROG
                } else {
                    0
                },
            ),
            MapBuilder::ExistingMap(map) => Ok(map),
        }
    }
}

impl<'base, K: Clone, V: Clone> HashMap<'base, K, V> {
    pub fn new(base: &Map) -> Result<HashMap<K, V>> {
        if mem::size_of::<K>() != base.config.key_size as usize
            || mem::size_of::<V>() != base.config.value_size as usize
            || (BPF_MAP_TYPE_HASH != base.config.type_
                && BPF_MAP_TYPE_PERF_EVENT_ARRAY != base.config.type_)
        {
            error!(
                "map definitions (map type and key/value size) of base `Map' and
            `HashMap' do not match"
            );
            return Err(Error::Map);
        }

        Ok(HashMap {
            base,
            _k: PhantomData,
            _v: PhantomData,
        })
    }

    pub fn set(&self, key: K, value: V) {
        let _ = bpf_map_set(self.base.fd, key, value);
    }

    pub fn get(&self, key: K) -> Option<V> {
        bpf_map_get(self.base.fd, key)
    }

    pub fn delete(&self, key: K) {
        let _ = bpf_map_delete(self.base.fd, key);
    }

    /// Return an iterator over all items in the map
    pub fn iter<'a>(&'a self) -> MapIter<'a, K, V> {
        MapIter {
            iterable: self,
            last_key: None,
        }
    }
}

impl<K: Clone, V: Clone> MapIterable<K, V> for HashMap<'_, K, V> {
    fn get(&self, key: K) -> Option<V> {
        HashMap::get(self, key)
    }

    fn next_key(&self, key: Option<K>) -> Option<K> {
        bpf_map_get_next_key(self.base.fd, key)
    }
}

impl<'base, K: Clone, V: Clone> LruHashMap<'base, K, V> {
    pub fn new(base: &Map) -> Result<LruHashMap<K, V>> {
        if mem::size_of::<K>() != base.config.key_size as usize
            || mem::size_of::<V>() != base.config.value_size as usize
            || BPF_MAP_TYPE_LRU_HASH != base.config.type_
        {
            error!(
                "map definitions (map type and key/value sizes) of base `Map' and `LruHashMap' do not match"
            );
            return Err(Error::Map);
        }

        Ok(LruHashMap {
            base,
            _k: PhantomData,
            _v: PhantomData,
        })
    }

    pub fn set(&self, key: K, value: V) {
        let _ = bpf_map_set(self.base.fd, key, value);
    }

    pub fn get(&self, key: K) -> Option<V> {
        bpf_map_get(self.base.fd, key)
    }

    pub fn delete(&self, key: K) {
        let _ = bpf_map_delete(self.base.fd, key);
    }

    /// Return an iterator over all items in the map
    pub fn iter<'a>(&'a self) -> MapIter<'a, K, V> {
        MapIter {
            iterable: self,
            last_key: None,
        }
    }
}

impl<K: Clone, V: Clone> MapIterable<K, V> for LruHashMap<'_, K, V> {
    fn get(&self, key: K) -> Option<V> {
        LruHashMap::<'_, K, V>::get(self, key)
    }

    fn next_key(&self, key: Option<K>) -> Option<K> {
        bpf_map_get_next_key(self.base.fd, key)
    }
}

impl<'base, K: Clone, V: Clone> PerCpuHashMap<'base, K, V> {
    pub fn new(base: &Map) -> Result<PerCpuHashMap<K, V>> {
        if mem::size_of::<K>() != base.config.key_size as usize
            || mem::size_of::<V>() != base.config.value_size as usize
            || BPF_MAP_TYPE_PERCPU_HASH != base.config.type_
        {
            error!("map definitions (size of key/value and map type) of base `Map' and `PerCpuHashMap' do not match");
            return Err(Error::Map);
        }

        Ok(PerCpuHashMap {
            base,
            _k: PhantomData,
            _v: PhantomData,
        })
    }

    /// Set per-cpu `values` to the BPF map at `key`
    ///
    /// The number of elements in `values` should be equal to the number of
    /// possible CPUs. This requirement is automatically fulfilled when
    /// `values` is created by
    /// [`PerCpuValues::new`](./struct.PerCpuValues.html#method.new)
    ///
    /// `Err` can be returned if the number of elements is wrong or underlying
    /// bpf_map_update_elem function returns a negative value.
    pub fn set(&self, key: K, values: PerCpuValues<V>) -> Result<()> {
        bpf_percpu_map_set(self.base.fd, key, values)
    }

    /// Get per-cpu values corresponding to the `key` from the BPF map
    ///
    /// If `key` is found, `Some([PerCpuValues](./struct.PerCpuValues.html))`
    /// is returned.
    pub fn get(&self, key: K) -> Option<PerCpuValues<V>> {
        bpf_percpu_map_get(self.base.fd, key)
    }

    /// Delete `key` from the BPF map
    pub fn delete(&self, key: K) {
        let _ = bpf_map_delete(self.base.fd, key);
    }

    /// Return an iterator over all items in the map
    pub fn iter<'a>(&'a self) -> MapIter<'a, K, PerCpuValues<V>> {
        MapIter {
            iterable: self,
            last_key: None,
        }
    }
}

impl<K: Clone, V: Clone> MapIterable<K, PerCpuValues<V>> for PerCpuHashMap<'_, K, V> {
    fn get(&self, key: K) -> Option<PerCpuValues<V>> {
        PerCpuHashMap::get(self, key)
    }

    fn next_key(&self, key: Option<K>) -> Option<K> {
        bpf_map_get_next_key(self.base.fd, key)
    }
}

impl<'base, K: Clone, V: Clone> LruPerCpuHashMap<'base, K, V> {
    pub fn new(base: &Map) -> Result<LruPerCpuHashMap<K, V>> {
        if mem::size_of::<K>() != base.config.key_size as usize
            || mem::size_of::<V>() != base.config.value_size as usize
            || BPF_MAP_TYPE_LRU_PERCPU_HASH != base.config.type_
        {
            error!("map definitions (size of key/value and map type) of base `Map' and `LruPerCpuHashMap' do not match");
            return Err(Error::Map);
        }

        Ok(LruPerCpuHashMap {
            base,
            _k: PhantomData,
            _v: PhantomData,
        })
    }

    /// Set per-cpu `values` to the BPF map at `key`
    ///
    /// The number of elements in `values` should be equal to the number of
    /// possible CPUs. This requirement is automatically fulfilled when
    /// `values` is created by
    /// [`PerCpuValues::new`](./struct.PerCpuValues.html#method.new)
    ///
    /// `Err` can be returned if the number of elements is wrong or underlying
    /// bpf_map_update_elem function returns a negative value.
    pub fn set(&self, key: K, values: PerCpuValues<V>) -> Result<()> {
        bpf_percpu_map_set(self.base.fd, key, values)
    }

    /// Get per-cpu values corresponding to the `key` from the BPF map
    ///
    /// If `key` is found, `Some([PerCpuValues](./struct.PerCpuValues.html))`
    /// is returned.
    pub fn get(&self, key: K) -> Option<PerCpuValues<V>> {
        bpf_percpu_map_get(self.base.fd, key)
    }

    /// Delete `key` from the BPF map
    pub fn delete(&self, key: K) {
        let _ = bpf_map_delete(self.base.fd, key);
    }

    /// Return an iterator over all items in the map
    pub fn iter<'a>(&'a self) -> MapIter<'a, K, PerCpuValues<V>> {
        MapIter {
            iterable: self,
            last_key: None,
        }
    }
}

impl<K: Clone, V: Clone> MapIterable<K, PerCpuValues<V>> for LruPerCpuHashMap<'_, K, V> {
    fn get(&self, key: K) -> Option<PerCpuValues<V>> {
        LruPerCpuHashMap::get(self, key)
    }

    fn next_key(&self, key: Option<K>) -> Option<K> {
        bpf_map_get_next_key(self.base.fd, key)
    }
}

impl<'base, T: Clone> Array<'base, T> {
    /// Create `Array` map from `base`
    pub fn new(base: &Map) -> Result<Array<T>> {
        if mem::size_of::<T>() != base.config.value_size as usize
            || BPF_MAP_TYPE_ARRAY != base.config.type_
        {
            error!(
                "map definitions (size of value, map type) of base `Map' and
            `Array' do not match"
            );
            return Err(Error::Map);
        }

        Ok(Array {
            base,
            _element: PhantomData,
        })
    }

    /// Set `value` into this array map at `index`
    ///
    /// This method can fail if `index` is out of bound
    pub fn set(&self, mut index: u32, mut value: T) -> Result<()> {
        let rv = unsafe {
            libbpf_sys::bpf_map_update_elem(
                self.base.fd,
                &mut index as *mut _ as *mut _,
                &mut value as *mut _ as *mut _,
                0,
            )
        };
        if rv < 0 {
            Err(Error::Map)
        } else {
            Ok(())
        }
    }

    /// Get an element at `index` from this array map
    ///
    /// This method always returns a `Some(T)` if `index` is valid, but `None`
    /// can be returned if `index` is out of bound.
    pub fn get(&self, mut index: u32) -> Option<T> {
        let mut value = MaybeUninit::zeroed();
        if unsafe {
            libbpf_sys::bpf_map_lookup_elem(
                self.base.fd,
                &mut index as *mut _ as *mut _,
                &mut value as *mut _ as *mut _,
            )
        } < 0
        {
            return None;
        }
        Some(unsafe { value.assume_init() })
    }

    /// Get length of this array map.
    pub fn len(&self) -> usize {
        self.base.config.max_entries as usize
    }
}

// round up to multiple of `unit_size`
//
// `unit_size` must be power of 2
fn round_up<T>(unit_size: usize) -> usize {
    let value_size = std::mem::size_of::<T>();
    ((value_size - 1) | (unit_size - 1)) + 1
}

/// A structure representing values of per-cpu map structures such as [`PerCpuArray`](./struct.PerCpuArray.html)
///
/// It is a kind of newtype of `Box<[T]>`. The length of the slice is always
/// the same with [`cpus::get_possible_num`](./cpus/fn.get_possible_num.html).
/// It also implements `Deref` and `DerefMut` so it can be used as a normal
/// array.
///
/// # Example
/// ```no_run
/// use redbpf::PerCpuValues;
/// let mut values = PerCpuValues::<u64>::new(0);
/// values[0] = 1;
/// ```
#[derive(Clone, Debug)]
pub struct PerCpuValues<T: Clone>(Box<[T]>);

impl<T: Clone> PerCpuValues<T> {
    /// Create a `PerCpuValues<T>` instance
    ///
    /// The created instance contains the fixed number of elements filled with
    /// `default_value`
    pub fn new(default_value: T) -> Self {
        let count = cpus::get_possible_num();
        let v = vec![default_value; count];
        Self(v.into())
    }
}

impl<T: Clone> From<Box<[T]>> for PerCpuValues<T> {
    fn from(values: Box<[T]>) -> Self {
        Self(values)
    }
}

impl<T: Clone> From<Vec<T>> for PerCpuValues<T> {
    fn from(values: Vec<T>) -> Self {
        Self::from(values.into_boxed_slice())
    }
}

impl<T: Clone> Deref for PerCpuValues<T> {
    type Target = Box<[T]>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Clone> DerefMut for PerCpuValues<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'base, T: Clone> PerCpuArray<'base, T> {
    pub fn new(base: &Map) -> Result<PerCpuArray<T>> {
        if mem::size_of::<T>() != base.config.value_size as usize
            || BPF_MAP_TYPE_PERCPU_ARRAY != base.config.type_
        {
            error!(
                "map definitions (size of value, map type) of base `Map' and
            `PerCpuArray' do not match"
            );
            return Err(Error::Map);
        }

        Ok(PerCpuArray {
            base,
            _element: PhantomData,
        })
    }

    /// Set per-cpu `values` to the BPF map
    ///
    /// The number of elements in `values` should be equal to the number of
    /// possible CPUs. It is guranteed if `values` is created by
    /// [`PerCpuValues::new`](./struct.PerCpuValues.html#method.new)
    ///
    /// This method can fail if `index` is out of bound of array map.
    pub fn set(&self, mut index: u32, values: &PerCpuValues<T>) -> Result<()> {
        let count = cpus::get_possible_num();
        if values.len() != count {
            return Err(Error::Map);
        }

        // It is needed to round up the value size to 8*N bytes
        // cf., https://elixir.bootlin.com/linux/v5.8/source/kernel/bpf/syscall.c#L1103
        let value_size = round_up::<T>(8);
        let alloc_size = value_size * count;
        let mut alloc = vec![0u8; alloc_size];
        let data = alloc.as_mut_ptr();
        for i in 0..count {
            unsafe {
                let dst_ptr = data.add(value_size * i) as *mut T;
                dst_ptr.write_unaligned(values[i].clone());
            }
        }

        if unsafe {
            libbpf_sys::bpf_map_update_elem(
                self.base.fd,
                &mut index as *mut _ as *mut _,
                data as *mut _,
                0,
            )
        } < 0
        {
            Err(Error::Map)
        } else {
            Ok(())
        }
    }

    /// Get per-cpu values from the BPF map
    ///
    /// Get per-cpu values at `index`. This method returns
    /// [`PerCpuValues`](./struct.PerCpuValues.html)
    ///
    /// This method can return None if `index` is out of bound.
    pub fn get(&self, mut index: u32) -> Option<PerCpuValues<T>> {
        // It is needed to round up the value size to 8*N
        // cf., https://elixir.bootlin.com/linux/v5.8/source/kernel/bpf/syscall.c#L1035
        let value_size = round_up::<T>(8);
        let count = cpus::get_possible_num();
        let alloc_size = value_size * count;
        let mut alloc = vec![0u8; alloc_size];
        let ptr = alloc.as_mut_ptr();
        if unsafe {
            libbpf_sys::bpf_map_lookup_elem(
                self.base.fd,
                &mut index as *mut _ as *mut _,
                ptr as *mut _,
            )
        } < 0
        {
            return None;
        }

        let mut values = Vec::with_capacity(count);
        for i in 0..count {
            unsafe {
                let elem_ptr = ptr.offset((value_size * i) as isize) as *const T;
                values.push(ptr::read_unaligned(elem_ptr));
            }
        }

        Some(values.into())
    }

    /// Get length of array map
    pub fn len(&self) -> usize {
        self.base.config.max_entries as usize
    }
}

impl<'base> ProgramArray<'base> {
    pub fn new(base: &Map) -> Result<ProgramArray> {
        if mem::size_of::<u32>() != base.config.key_size as usize
            || mem::size_of::<RawFd>() != base.config.value_size as usize
        {
            error!(
                "map definitions (sizes of key and value) of base `Map' and
            `ProgramArray' do not match"
            );
            return Err(Error::Map);
        }

        Ok(ProgramArray { base })
    }

    /// Get the `fd` of the eBPF program at `index`.
    pub fn get(&self, mut index: u32) -> Result<RawFd> {
        let mut fd: RawFd = 0;
        if unsafe {
            libbpf_sys::bpf_map_lookup_elem(
                self.base.fd,
                &mut index as *mut _ as *mut _,
                &mut fd as *mut _ as *mut _,
            )
        } < 0
        {
            return Err(Error::Map);
        }
        Ok(fd)
    }

    /// Set the `index` entry to the given eBPF program `fd`.
    ///
    /// To jump to a program from eBPF, see
    /// [`redbpf_probes::maps::ProgramArray::tail_call`](../redbpf_probes/maps/struct.ProgramArray.html#method.tail_call).
    ///
    /// # Example
    /// ```no_run
    /// pub const PROGRAM_PARSE_HTTP: u32 = 0;
    ///
    /// use redbpf::{load::Loader, ProgramArray};
    /// let mut loader = Loader::load_file("iotop.elf").expect("error loading probe");
    /// let mut programs = ProgramArray::new(loader.map("program_map").unwrap()).unwrap();
    ///
    /// programs.set(
    ///     PROGRAM_PARSE_HTTP,
    ///     loader.program("parse_http").unwrap().fd().unwrap(),
    /// );
    /// ```
    pub fn set(&mut self, mut index: u32, mut fd: RawFd) -> Result<()> {
        let ret = unsafe {
            libbpf_sys::bpf_map_update_elem(
                self.base.fd,
                &mut index as *mut _ as *mut _,
                &mut fd as *mut _ as *mut _,
                0,
            )
        };
        if ret < 0 {
            return Err(Error::Map);
        }

        Ok(())
    }
}

pub struct MapIter<'a, K: Clone, V: Clone> {
    iterable: &'a dyn MapIterable<K, V>,
    last_key: Option<K>,
}

impl<K: Clone, V: Clone> Iterator for MapIter<'_, K, V> {
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.last_key.take();
        self.last_key = self.iterable.next_key(key);
        Some((
            self.last_key.as_ref()?.clone(),
            self.iterable.get(self.last_key.as_ref()?.clone())?,
        ))
    }
}

impl StackTrace<'_> {
    pub fn new(map: &Map) -> StackTrace<'_> {
        StackTrace { base: map }
    }

    pub fn get(&mut self, mut id: i64) -> Option<BpfStackFrames> {
        unsafe {
            let mut value = MaybeUninit::uninit();

            let ret = libbpf_sys::bpf_map_lookup_elem(
                self.base.fd,
                &mut id as *const _ as *mut _,
                value.as_mut_ptr() as *mut _,
            );

            if ret == 0 {
                Some(value.assume_init())
            } else {
                None
            }
        }
    }

    pub fn delete(&mut self, id: i64) -> Result<()> {
        unsafe {
            let ret = libbpf_sys::bpf_map_delete_elem(self.base.fd, &id as *const _ as *mut _);

            if ret == 0 {
                Ok(())
            } else {
                Err(Error::Map)
            }
        }
    }
}

impl StreamParser {
    /// Attach `sock_map` to stream parser BPF program.
    ///
    /// # Example
    /// ```no_run
    /// use redbpf::{load::Loader, SockMap};
    ///
    /// let loaded = Loader::load(b"echo.elf").expect("error loading BPF program");
    /// let mut echo_sockmap = SockMap::new(loaded.map("echo_sockmap").expect("sockmap not found")).unwrap();
    /// loaded.stream_parsers().next().unwrap().attach_sockmap(&echo_sockmap).expect("Attaching sockmap failed");
    /// ```
    pub fn attach_sockmap(&self, sock_map: &SockMap) -> Result<()> {
        let attach_fd = sock_map.base.fd;
        let prog_fd = self.common.fd.unwrap();

        let ret =
            unsafe { libbpf_sys::bpf_prog_attach(prog_fd, attach_fd, BPF_SK_SKB_STREAM_PARSER, 0) };
        if ret < 0 {
            Err(Error::BPF)
        } else {
            Ok(())
        }
    }
}

impl StreamVerdict {
    /// Attach `sock_map` to stream verdict BPF program.
    ///
    /// # Example
    /// ```no_run
    /// use redbpf::{load::Loader, SockMap};
    ///
    /// let loaded = Loader::load(b"echo.elf").expect("error loading BPF program");
    /// let mut echo_sockmap = SockMap::new(loaded.map("echo_sockmap").expect("sockmap not found")).unwrap();
    /// loaded.stream_verdicts().next().unwrap().attach_sockmap(&echo_sockmap).expect("Attaching sockmap failed");
    /// ```
    pub fn attach_sockmap(&self, sock_map: &SockMap) -> Result<()> {
        let attach_fd = sock_map.base.fd;
        let prog_fd = self.common.fd.unwrap();

        let ret = unsafe {
            libbpf_sys::bpf_prog_attach(prog_fd, attach_fd, BPF_SK_SKB_STREAM_VERDICT, 0)
        };
        if ret < 0 {
            Err(Error::BPF)
        } else {
            Ok(())
        }
    }
}

impl<'a> SockMap<'a> {
    pub fn new(map: &'a Map) -> Result<SockMap<'a>> {
        Ok(SockMap { base: map })
    }

    pub fn set(&mut self, mut idx: u32, mut fd: RawFd) -> Result<()> {
        let ret = unsafe {
            libbpf_sys::bpf_map_update_elem(
                self.base.fd,
                &mut idx as *mut _ as *mut _,
                &mut fd as *mut _ as *mut _,
                BPF_ANY.into(), // No condition on the existence of the entry for `idx`.
            )
        };
        if ret < 0 {
            error!(
                "error on updating sockmap: {:?}",
                io::Error::last_os_error()
            );
            Err(Error::Map)
        } else {
            Ok(())
        }
    }

    pub fn delete(&mut self, mut idx: u32) -> Result<()> {
        let ret =
            unsafe { libbpf_sys::bpf_map_delete_elem(self.base.fd, &mut idx as *mut _ as *mut _) };
        if ret < 0 {
            Err(Error::Map)
        } else {
            Ok(())
        }
    }
}

impl<'base, K: Clone, V: Clone> LpmTrieMap<'base, K, V> {
    pub fn new(base: &'base Map) -> Result<Self> {
        if mem::size_of::<K>() + mem::size_of::<u32>() != base.config.key_size as usize
            || mem::size_of::<V>() != base.config.value_size as usize
            || BPF_MAP_TYPE_LPM_TRIE != base.config.type_
        {
            error!(
                "map definitions (map type and key/value size) of base `Map' and
            `LpmTrieMap' do not match"
            );
            return Err(Error::Map);
        }

        Ok(Self {
            base,
            _k: PhantomData,
            _v: PhantomData,
        })
    }

    pub fn set(&self, key: LpmTrieMapKey<K>, value: V) {
        let _ = bpf_map_set(self.base.fd, key, value);
    }

    pub fn get(&self, key: LpmTrieMapKey<K>) -> Option<V> {
        bpf_map_get(self.base.fd, key)
    }

    pub fn delete(&self, key: LpmTrieMapKey<K>) {
        let _ = bpf_map_delete(self.base.fd, key);
    }

    /// Return an iterator over all items in the map
    pub fn iter<'a>(&'a self) -> MapIter<'a, LpmTrieMapKey<K>, V> {
        MapIter {
            iterable: self,
            last_key: None,
        }
    }
}

impl<K: Clone, V: Clone> MapIterable<LpmTrieMapKey<K>, V> for LpmTrieMap<'_, K, V> {
    fn get(&self, key: LpmTrieMapKey<K>) -> Option<V> {
        LpmTrieMap::get(self, key)
    }

    fn next_key(&self, key: Option<LpmTrieMapKey<K>>) -> Option<LpmTrieMapKey<K>> {
        bpf_map_get_next_key(self.base.fd, key)
    }
}

/// A structure for reading data from BPF iterators
///
/// The data read by this structure is written by BPF iterators from the kernel
/// context. BPF iterators use the `bpf_seq_write` BPF helper function to write
/// data. And userspace programs can read the data by `read()` system
/// call. `BPFIter` implements `Iterator` trait to provide a convenient way for
/// reading data. See
/// [`TaskIter::bpf_iter`](./struct.TaskIter.html#method.bpf_iter) that creates
/// this structure.
pub struct BPFIter<T> {
    file: BufReader<File>,
    _elem: PhantomData<T>,
}

impl<T> BPFIter<T> {
    fn from(fd: RawFd) -> Result<Self> {
        Ok(BPFIter {
            file: unsafe { BufReader::new(File::from_raw_fd(fd)) },
            _elem: PhantomData,
        })
    }

    fn item(&mut self) -> Option<T> {
        let mut buf = vec![0u8; mem::size_of::<T>()];
        // read_exact handles `ErrorKind::Iterrupted`
        self.file
            .read_exact(&mut buf[..mem::size_of::<T>()])
            .map_err(|e| match e.kind() {
                ErrorKind::UnexpectedEof => {}
                _ => error!("error on reading data from BPF iterator {}", e),
            })
            .ok()?;
        let val = unsafe { ptr::read_unaligned(buf.as_ptr() as *const T) };
        Some(val)
    }
}

impl<T> Iterator for BPFIter<T> {
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        self.item()
    }
}

impl TaskIter {
    fn create_link(&mut self) -> Result<()> {
        let link_fd =
            unsafe { bpf_link_create(self.common.fd.unwrap(), 0, BPF_TRACE_ITER, ptr::null()) };
        if link_fd < 0 {
            error!("Error on bpf_link_create");
            return Err(Error::BPF);
        }
        self.link_fd = Some(link_fd);
        Ok(())
    }

    /// Create an iterator that iterates over data written by BPF iterators
    ///
    /// See [`BPFIter<T>`](./struct.BPFIter.html) for more information.
    pub fn bpf_iter<T>(&mut self) -> Result<impl Iterator<Item = T>> {
        if self.common.fd.is_none() {
            error!("can not call TaskIter::iter before program is loaded");
            return Err(Error::ProgramNotLoaded);
        }

        if self.link_fd.is_none() {
            self.create_link()?;
        }

        let iter_fd = unsafe { bpf_iter_create(self.link_fd.clone().unwrap()) };
        if iter_fd < 0 {
            error!("Error on bpf_iter_create");
            return Err(Error::BPF);
        }

        Ok(BPFIter::from(iter_fd)?)
    }
}

impl Drop for TaskIter {
    fn drop(&mut self) {
        if let Some(link_fd) = self.link_fd {
            unsafe {
                let _ = libc::close(link_fd);
            }
        }
    }
}

#[inline]
fn add_relocation(
    rels: &mut Vec<RelocationInfo>,
    shndx: usize,
    shdr: &SectionHeader,
    shdr_relocs: &[(usize, RelocSection<'_>)],
) {
    // if unwrap blows up, something's really bad
    let section_rels = &shdr_relocs.iter().find(|(idx, _)| idx == &shndx).unwrap().1;
    rels.extend(section_rels.iter().map(|rel| RelocationInfo {
        target_sec_idx: shdr.sh_info as usize,
        sym_idx: rel.r_sym,
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

fn bpf_map_set<K: Clone, V: Clone>(fd: RawFd, mut key: K, mut value: V) -> Result<()> {
    if unsafe {
        libbpf_sys::bpf_map_update_elem(
            fd,
            &mut key as *mut _ as *mut _,
            &mut value as *mut _ as *mut _,
            0,
        )
    } < 0
    {
        Err(Error::Map)
    } else {
        Ok(())
    }
}

fn bpf_map_get<K: Clone, V: Clone>(fd: RawFd, mut key: K) -> Option<V> {
    let mut value = MaybeUninit::zeroed();
    if unsafe {
        libbpf_sys::bpf_map_lookup_elem(
            fd,
            &mut key as *mut _ as *mut _,
            &mut value as *mut _ as *mut _,
        )
    } < 0
    {
        return None;
    }
    Some(unsafe { value.assume_init() })
}

fn bpf_map_delete<K: Clone>(fd: RawFd, mut key: K) -> Result<()> {
    if unsafe { libbpf_sys::bpf_map_delete_elem(fd, &mut key as *mut _ as *mut _) } < 0 {
        Err(Error::Map)
    } else {
        Ok(())
    }
}

fn bpf_map_get_next_key<K: Clone>(fd: RawFd, key: Option<K>) -> Option<K> {
    if let Some(mut key) = key {
        let mut next_key = MaybeUninit::<K>::zeroed();
        let ret = unsafe {
            libbpf_sys::bpf_map_get_next_key(
                fd,
                &mut key as *mut _ as *mut _,
                &mut next_key as *mut _ as *mut _,
            )
        };
        if ret < 0 {
            None
        } else {
            Some(unsafe { next_key.assume_init() })
        }
    } else {
        let mut key = MaybeUninit::<K>::zeroed();
        if unsafe {
            libbpf_sys::bpf_map_get_next_key(fd, ptr::null(), &mut key as *mut _ as *mut _)
        } < 0
        {
            None
        } else {
            Some(unsafe { key.assume_init() })
        }
    }
}

fn bpf_percpu_map_set<K: Clone, V: Clone>(
    fd: RawFd,
    mut key: K,
    values: PerCpuValues<V>,
) -> Result<()> {
    let count = cpus::get_possible_num();
    if values.len() != count {
        return Err(Error::Map);
    }

    // It is needed to round up the value size to 8*N bytes
    // cf., https://elixir.bootlin.com/linux/v5.8/source/kernel/bpf/syscall.c#L1103
    let value_size = round_up::<V>(8);
    let alloc_size = value_size * count;
    let mut alloc = vec![0u8; alloc_size];
    let data = alloc.as_mut_ptr();
    for i in 0..count {
        unsafe {
            let dst_ptr = data.add(value_size * i) as *mut V;
            dst_ptr.write_unaligned(values[i].clone());
        }
    }

    if unsafe {
        libbpf_sys::bpf_map_update_elem(fd, &mut key as *mut _ as *mut _, data as *mut _, 0)
    } < 0
    {
        Err(Error::Map)
    } else {
        Ok(())
    }
}

fn bpf_percpu_map_get<K: Clone, V: Clone>(fd: RawFd, mut key: K) -> Option<PerCpuValues<V>> {
    // It is needed to round up the value size to 8*N
    // cf., https://elixir.bootlin.com/linux/v5.8/source/kernel/bpf/syscall.c#L1035
    let value_size = round_up::<V>(8);
    let count = cpus::get_possible_num();
    let alloc_size = value_size * count;
    let mut alloc = vec![0u8; alloc_size];
    let data = alloc.as_mut_ptr();
    if unsafe { libbpf_sys::bpf_map_lookup_elem(fd, &mut key as *mut _ as *mut _, data as *mut _) }
        < 0
    {
        return None;
    }

    let mut values = Vec::with_capacity(count);
    for i in 0..count {
        unsafe {
            let elem_ptr = data.add(value_size * i) as *const V;
            values.push(ptr::read_unaligned(elem_ptr));
        }
    }

    Some(values.into())
}
