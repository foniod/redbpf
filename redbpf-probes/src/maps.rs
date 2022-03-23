// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/*!
eBPF maps.

Maps are a generic data structure for storage of different types of data.
They allow sharing of data between eBPF kernel programs, and also between
kernel and user-space code.
 */
use core::convert::TryInto;
use core::default::Default;
use core::marker::PhantomData;
use core::{mem, ptr};
use cty::*;

use crate::bindings::*;
use crate::helpers::*;

pub trait BpfMap {
    type Key;
    type Value;
}

macro_rules! define_hashmap {
    ($(#[$attr:meta])* $name:ident, $map_type:expr) => {
        $(#[$attr])*
        #[repr(transparent)]
        pub struct $name<K, V> {
            def: bpf_map_def,
            _k: PhantomData<K>,
            _v: PhantomData<V>,
        }

        impl<K, V> $name<K, V> {
            /// Creates a map with the specified maximum number of elements.
            pub const fn with_max_entries(max_entries: u32) -> Self {
                Self {
                    def: bpf_map_def {
                        type_: $map_type,
                        key_size: mem::size_of::<K>() as u32,
                        value_size: mem::size_of::<V>() as u32,
                        max_entries,
                        map_flags: 0,
                    },
                    _k: PhantomData,
                    _v: PhantomData,
                }
            }
            /// Returns a reference to the value corresponding to the key.
            ///
            /// **CUATION** The value that the returned reference refers to is
            /// stored at 8 bytes aligned memory. So the reference is not
            /// guaranteed to be aligned properly if the alignment of the value
            /// exceeds 8 bytes. So this method should not be called if the
            /// alignment is greater than 8 bytes.
            ///
            /// Use `get_val` method instead if the alignment of value is
            /// greater than 8 bytes.
            #[inline]
            pub fn get(&mut self, key: &K) -> Option<&V> {
                unsafe {
                    let value = bpf_map_lookup_elem(
                        &mut self.def as *mut _ as *mut c_void,
                        key as *const _ as *const c_void,
                    );
                    if value.is_null() {
                        None
                    } else {
                        Some(&*(value as *const V))
                    }
                }
            }

            /// Returns a mutable reference to the value corresponding to the key.
            ///
            /// **CUATION** The value that the returned mutable reference
            /// refers to is stored at 8 bytes aligned memory. So the mutable
            /// reference is not guaranteed to be aligned properly if the
            /// alignment of the value exceeds 8 bytes. So this method should
            /// not be called if the alignment is greater than 8 bytes.
            ///
            /// Use `get_val` method instead if the alignment of value is
            /// greater than 8 bytes. But you should call `set` method to
            /// update the modified value to BPF maps.
            #[inline]
            pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
                unsafe {
                    let value = bpf_map_lookup_elem(
                        &mut self.def as *mut _ as *mut c_void,
                        key as *const _ as *const c_void,
                    );
                    if value.is_null() {
                        None
                    } else {
                        Some(&mut *(value as *mut V))
                    }
                }
            }

            /// Returns a value corresponding to the key
            ///
            /// **NOTE** It is better to use more efficient `get_mut` method
            /// instead if the alignment of the value is equal to or less than
            /// 8 bytes. i.e, alignment is 8, 4, 2 bytes or 1 byte. Rust
            /// compiler expects that the value a reference refers to should be
            /// aligned properly. But the Linux kernel does not guarantee the
            /// alignment of the value the rust compiler assumes but the Linux
            /// kernel just stores values at 8 bytes aligned memory.
            #[inline]
            pub fn get_val(&mut self, key: &K) -> Option<V> {
                unsafe {
                    let value = bpf_map_lookup_elem(
                        &mut self.def as *mut _ as *mut c_void,
                        key as *const _ as *const c_void,
                    );
                    if value.is_null() {
                        None
                    } else {
                        Some(ptr::read_unaligned(value as *const V))
                    }
                }
            }

            /// Set the `value` in the map for `key`
            #[inline]
            pub fn set(&mut self, key: &K, value: &V) {
                unsafe {
                    bpf_map_update_elem(
                        &mut self.def as *mut _ as *mut c_void,
                        key as *const _ as *const c_void,
                        value as *const _ as *const c_void,
                        BPF_ANY.into(),
                    );
                }
            }

            /// Delete the entry indexed by `key`
            #[inline]
            pub fn delete(&mut self, key: &K) {
                unsafe {
                    bpf_map_delete_elem(
                        &mut self.def as *mut _ as *mut c_void,
                        key as *const _ as *const c_void,
                    );
                }
            }
        }

        impl<K, V> BpfMap for $name<K, V> {
            type Key = K;
            type Value = V;
        }
    };
}

macro_rules! define_array {
    ($(#[$attr:meta])* $name:ident, $map_type:expr) => {
        $(#[$attr])*
        #[repr(transparent)]
        pub struct $name<T> {
            def: bpf_map_def,
            _element: PhantomData<T>,
        }

        impl<T> $name<T> {
            /// Create array map of which length is `max_entries`
            pub const fn with_max_entries(max_entries: u32) -> Self {
                Self {
                    def: bpf_map_def {
                        type_: $map_type,
                        key_size: mem::size_of::<u32>() as u32,
                        value_size: mem::size_of::<T>() as u32,
                        max_entries,
                        map_flags: 0,
                    },
                    _element: PhantomData,
                }
            }

            /// Returns a reference to the value at `index`.
            #[inline]
            pub fn get(&mut self, index: u32) -> Option<&T> {
                unsafe {
                    let value = bpf_map_lookup_elem(
                        &mut self.def as *mut _ as *mut c_void,
                        &index as *const _ as *const c_void,
                    );
                    if value.is_null() {
                        None
                    } else {
                        Some(&*(value as *const T))
                    }
                }
            }

            /// Returns a mutable reference to the value at `index`.
            #[inline]
            pub fn get_mut(&mut self, index: u32) -> Option<&mut T> {
                unsafe {
                    let value = bpf_map_lookup_elem(
                        &mut self.def as *mut _ as *mut c_void,
                        &index as *const _ as *const c_void,
                    );
                    if value.is_null() {
                        None
                    } else {
                        Some(&mut *(value as *mut T))
                    }
                }
            }

            /// Set the `value` at `index`.
            #[inline]
            pub fn set(&mut self, index: u32, value: &T) {
                unsafe {
                    bpf_map_update_elem(
                        &mut self.def as *mut _ as *mut c_void,
                        &index as *const _ as *const c_void,
                        value as *const _ as *const c_void,
                        BPF_ANY.into(),
                    );
                }
            }
        }

        impl<T> BpfMap for $name<T> {
            type Key = u32;
            type Value = T;
        }
    };
}
define_hashmap!(
    /// Hash table map
    ///
    /// High level API of BPF_MAP_TYPE_HASH maps for BPF programs.
    ///
    /// If you are looking for userspace API, see
    /// [`redbpf::HashMap`](../../redbpf/struct.HashMap.html) instead.
    HashMap,
    bpf_map_type_BPF_MAP_TYPE_HASH
);
define_hashmap!(
    /// Per-cpu hash table map
    ///
    /// High level API of BPF_MAP_TYPE_PERCPU_HASH maps for BPF programs.
    ///
    /// If you are looking for userspace API, see
    /// [`redbpf::PerCpuHashMap`](../../redbpf/struct.PerCpuHashMap.html)
    /// instead.
    PerCpuHashMap,
    bpf_map_type_BPF_MAP_TYPE_PERCPU_HASH
);
define_hashmap!(
    /// LRU hash table map
    ///
    /// High level API of BPF_MAP_TYPE_LRU_HASH maps for BPF programs.
    ///
    /// If you are looking for userspace API, see
    /// [`redbpf::LruHashMap`](../../redbpf/struct.LruHashMap.html) instead.
    LruHashMap,
    bpf_map_type_BPF_MAP_TYPE_LRU_HASH
);
define_hashmap!(
    /// LRU per-cpu hash table map
    ///
    /// High level API of BPF_MAP_TYPE_LRU_PERCPU_HASH maps for BPF programs.
    ///
    /// If you are looking for userspace API, see
    /// [`redbpf::LruPerCpuHashMap`](../../redbpf/struct.LruPerCpuHashMap.html)
    /// instead.
    LruPerCpuHashMap,
    bpf_map_type_BPF_MAP_TYPE_LRU_PERCPU_HASH
);

define_array!(
    /// BPF array map for BPF programs
    ///
    /// High-level API of BPF_MAP_TYPE_ARRAY maps used by BPF programs.
    ///
    /// For userspace API, see [`redbpf::Array`](../../redbpf/struct.Array.html)
    Array,
    bpf_map_type_BPF_MAP_TYPE_ARRAY
);
define_array!(
    /// BPF per-cpu array map for BPF programs
    ///
    /// High-level API of BPF_MAP_TYPE_PERCPU_ARRAY maps used by BPF programs.
    ///
    /// For userspace API, see [`redbpf::PerCpuArray`](../../redbpf/struct.PerCpuArray.html)
    PerCpuArray,
    bpf_map_type_BPF_MAP_TYPE_PERCPU_ARRAY
);

/// Flags that can be passed to `PerfMap::insert_with_flags`.
#[derive(Debug, Copy, Clone)]
pub struct PerfMapFlags {
    index: Option<u32>,
    pub(crate) xdp_size: u32,
}

impl Default for PerfMapFlags {
    #[inline]
    fn default() -> Self {
        PerfMapFlags {
            index: None,
            xdp_size: 0,
        }
    }
}

impl PerfMapFlags {
    /// Create new default flags.
    ///
    /// Events inserted with default flags are keyed by the current CPU number
    /// and don't include any extra payload data.
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    /// Create flags for events carrying `size` extra bytes of `XDP` payload data.
    #[inline]
    pub fn with_xdp_size(size: u32) -> Self {
        *PerfMapFlags::new().xdp_size(size)
    }

    /// Set the index key for the event to insert.
    #[inline]
    pub fn index(&mut self, index: u32) -> &mut PerfMapFlags {
        self.index = Some(index);
        self
    }

    /// Set the number of bytes of the `XDP` payload data to append to the event.
    #[inline]
    pub fn xdp_size(&mut self, size: u32) -> &mut PerfMapFlags {
        self.xdp_size = size;
        self
    }
}

impl From<PerfMapFlags> for u64 {
    #[inline]
    fn from(flags: PerfMapFlags) -> u64 {
        (flags.xdp_size as u64) << 32
            | (flags
                .index
                .unwrap_or_else(|| BPF_F_CURRENT_CPU.try_into().unwrap()) as u64)
    }
}

/// Perf events map.
///
/// Perf events map that allows eBPF programs to store data in mmap()ed shared
/// memory accessible by user-space. This is a wrapper for
/// `BPF_MAP_TYPE_PERF_EVENT_ARRAY`.
///
/// If you're writing an `XDP` probe, you should use `xdp::PerfMap` instead which
/// exposes `XDP`-specific functionality.
#[repr(transparent)]
pub struct PerfMap<T> {
    def: bpf_map_def,
    _event: PhantomData<T>,
}

impl<T> PerfMap<T> {
    /// Creates a perf map with the specified maximum number of elements.
    pub const fn with_max_entries(max_entries: u32) -> Self {
        Self {
            def: bpf_map_def {
                type_: bpf_map_type_BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: 0,
            },
            _event: PhantomData,
        }
    }

    /// Insert a new event in the perf events array keyed by the current CPU number.
    ///
    /// Each array can hold up to `max_entries` events, see `with_max_entries`.
    /// If you want to use a key other than the current CPU, see
    /// `insert_with_flags`.
    #[inline]
    pub fn insert<C>(&mut self, ctx: *mut C, data: &T) {
        self.insert_with_flags(ctx, data, PerfMapFlags::default())
    }

    /// Insert a new event in the perf events array keyed by the index and with
    /// the additional xdp payload data specified in the given `PerfMapFlags`.
    #[inline]
    pub fn insert_with_flags<C>(&mut self, ctx: *mut C, data: &T, flags: PerfMapFlags) {
        bpf_perf_event_output(
            ctx as *mut _ as *mut c_void,
            &mut self.def as *mut _ as *mut c_void,
            flags.into(),
            data as *const _ as *const c_void,
            mem::size_of::<T>() as u64,
        );
    }
}

impl<T> BpfMap for PerfMap<T> {
    type Key = u32;
    type Value = u32;
}

// TODO Use PERF_MAX_STACK_DEPTH
const BPF_MAX_STACK_DEPTH: usize = 127;

#[repr(transparent)]
pub struct StackTrace {
    def: bpf_map_def,
}

#[repr(C)]
struct BpfStackFrames {
    ip: [u64; BPF_MAX_STACK_DEPTH],
}

impl StackTrace {
    pub const fn with_max_entries(cap: u32) -> Self {
        StackTrace {
            def: bpf_map_def {
                type_: bpf_map_type_BPF_MAP_TYPE_STACK_TRACE,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<BpfStackFrames>() as u32,
                max_entries: cap,
                map_flags: 0,
            },
        }
    }

    pub unsafe fn stack_id(&mut self, ctx: *mut pt_regs, flag: u64) -> Result<i64, i64> {
        let ret = bpf_get_stackid(ctx as _, &mut self.def as *mut _ as _, flag);
        if ret >= 0 {
            Ok(ret)
        } else {
            Err(ret)
        }
    }
}

impl BpfMap for StackTrace {
    type Key = u32;
    type Value = [u64; BPF_MAX_STACK_DEPTH];
}

/// Program array map.
///
/// An array of eBPF programs that can be used as a jump table.
///
/// To configure the map use
/// [`redbpf::ProgramArray`](../../redbpf/struct.ProgramArray.html)
/// from user-space.
///
/// To jump to a program, see the `tail_call` method.
#[repr(transparent)]
pub struct ProgramArray {
    def: bpf_map_def,
}

impl ProgramArray {
    /// Creates a program map with the specified maximum number of programs.
    pub const fn with_max_entries(max_entries: u32) -> Self {
        Self {
            def: bpf_map_def {
                type_: bpf_map_type_BPF_MAP_TYPE_PROG_ARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: 0,
            },
        }
    }

    /// Jump to the eBPF program referenced at `index`, passing `ctx` as context.
    ///
    /// This special method is used to trigger a "tail call", or in other words,
    /// to jump into another eBPF program.  The same stack frame is used (but
    /// values on stack and in registers for the caller are not accessible to
    /// the callee). This mechanism allows for program chaining, either for
    /// raising the maximum number of available eBPF instructions, or to execute
    /// given programs in conditional blocks. For security reasons, there is an
    /// upper limit to the number of successive tail calls that can be
    /// performed.
    ///
    /// If the call succeeds the kernel immediately runs the first instruction
    /// of the new program. This is not a function call, and it never returns to
    /// the previous program. If the call fails, then the helper has no effect,
    /// and the caller continues to run its subsequent instructions.
    ///
    /// A call can fail if the destination program for the jump does not exist
    /// (i.e. index is superior to the number of entries in the array), or
    /// if the maximum number of tail calls has been reached for this chain of
    /// programs.
    pub unsafe fn tail_call<C>(&mut self, ctx: *mut C, index: u32) -> Result<(), i64> {
        let ret = bpf_tail_call(ctx as *mut _, &mut self.def as *mut _ as *mut c_void, index);
        if ret < 0 {
            return Err(ret);
        }

        Ok(())
    }
}

impl BpfMap for ProgramArray {
    type Key = u32;
    type Value = u32;
}

/// SockMap.
///
/// A sockmap is a BPF map type that holds references to sock structs. BPF
/// programs can use the sockmap to redirect `skb`s between sockets using
/// related BPF helpers.
pub struct SockMap {
    def: bpf_map_def,
}

impl SockMap {
    pub const fn with_max_entries(max_entries: u32) -> Self {
        Self {
            def: bpf_map_def {
                type_: bpf_map_type_BPF_MAP_TYPE_SOCKMAP,
                key_size: mem::size_of::<i32>() as u32,
                value_size: mem::size_of::<i32>() as u32,
                max_entries,
                map_flags: 0,
            },
        }
    }

    /// Redirect the packet on `egress path` to the socket referenced by sockmap
    /// at index `key`.
    pub fn redirect(&mut self, skb: *mut __sk_buff, key: u32) -> Result<(), ()> {
        let ret = unsafe {
            bpf_sk_redirect_map(
                skb as *mut _,
                &mut self.def as *mut _ as *mut c_void,
                key,
                0,
            ) as sk_action
        };
        #[allow(non_upper_case_globals)]
        match ret {
            sk_action_SK_PASS => Ok(()),
            sk_action_SK_DROP => Err(()),
            _ => panic!("invalid return value of bpf_sk_redirect_map"),
        }
    }

    /// Redirect the packet on `ingress path` to the socket referenced by
    /// sockmap at index `key`.
    pub fn redirect_ingress(&mut self, skb: *mut __sk_buff, key: u32) -> Result<(), ()> {
        let ret: sk_action = unsafe {
            bpf_sk_redirect_map(
                skb as *mut _,
                &mut self.def as *mut _ as *mut c_void,
                key,
                BPF_F_INGRESS.into(),
            ) as sk_action
        };
        #[allow(non_upper_case_globals)]
        match ret {
            sk_action_SK_PASS => Ok(()),
            sk_action_SK_DROP => Err(()),
            _ => panic!("invalid return value of bpf_sk_redirect_map"),
        }
    }
}

impl BpfMap for SockMap {
    type Key = i32;
    type Value = i32;
}

/// LPM trie map.
///
/// An LPM (longest prefix match) trie map is a BPF map type that can be
/// used to find entry having longest prefix match with provided one.
#[repr(transparent)]
pub struct LpmTrieMap<K, V> {
    def: bpf_map_def,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

#[repr(C)]
pub struct LpmTrieMapKey<T> {
    pub prefix_len: u32,
    pub data: T,
}

impl<K, V> LpmTrieMap<K, V> {
    pub const fn with_max_entries(max_entries: u32) -> Self {
        Self {
            def: bpf_map_def {
                type_: bpf_map_type_BPF_MAP_TYPE_LPM_TRIE,
                key_size: mem::size_of::<LpmTrieMapKey<K>>() as u32,
                value_size: mem::size_of::<V>() as u32,
                max_entries,
                map_flags: BPF_F_NO_PREALLOC,
            },
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    /// Returns a reference to the value corresponding to the key.
    ///
    /// **CUATION** The value that the returned reference refers to is
    /// stored at 8 bytes aligned memory. So the reference is not
    /// guaranteed to be aligned properly if the alignment of the value
    /// exceeds 8 bytes. So this method should not be called if the
    /// alignment is greater than 8 bytes.
    ///
    /// Use `get_val` method instead if the alignment of value is
    /// greater than 8 bytes.
    #[inline]
    pub fn get(&mut self, key: &LpmTrieMapKey<K>) -> Option<&V> {
        unsafe {
            let value = bpf_map_lookup_elem(
                &mut self.def as *mut _ as *mut c_void,
                key as *const _ as *const c_void,
            );
            if value.is_null() {
                None
            } else {
                Some(&*(value as *const V))
            }
        }
    }

    /// Returns a mutable reference to the value corresponding to the key.
    ///
    /// **CUATION** The value that the returned mutable reference
    /// refers to is stored at 8 bytes aligned memory. So the mutable
    /// reference is not guaranteed to be aligned properly if the
    /// alignment of the value exceeds 8 bytes. So this method should
    /// not be called if the alignment is greater than 8 bytes.
    ///
    /// Use `get_val` method instead if the alignment of value is
    /// greater than 8 bytes. But you should call `set` method to
    /// update the modified value to BPF maps.
    #[inline]
    pub fn get_mut(&mut self, key: &LpmTrieMapKey<K>) -> Option<&mut V> {
        unsafe {
            let value = bpf_map_lookup_elem(
                &mut self.def as *mut _ as *mut c_void,
                key as *const _ as *const c_void,
            );
            if value.is_null() {
                None
            } else {
                Some(&mut *(value as *mut V))
            }
        }
    }

    /// Returns a value corresponding to the key
    ///
    /// **NOTE** It is better to use more efficient `get_mut` method
    /// instead if the alignment of the value is equal to or less than
    /// 8 bytes. i.e, alignment is 8, 4, 2 bytes or 1 byte. Rust
    /// compiler expects that the value a reference refers to should be
    /// aligned properly. But the Linux kernel does not guarantee the
    /// alignment of the value the rust compiler assumes but the Linux
    /// kernel just stores values at 8 bytes aligned memory.
    #[inline]
    pub fn get_val(&mut self, key: &LpmTrieMapKey<K>) -> Option<V> {
        unsafe {
            let value = bpf_map_lookup_elem(
                &mut self.def as *mut _ as *mut c_void,
                key as *const _ as *const c_void,
            );
            if value.is_null() {
                None
            } else {
                Some(ptr::read_unaligned(value as *const V))
            }
        }
    }

    /// Set the `value` in the map for `key`
    #[inline]
    pub fn set(&mut self, key: &LpmTrieMapKey<K>, value: &V) {
        unsafe {
            bpf_map_update_elem(
                &mut self.def as *mut _ as *mut c_void,
                key as *const _ as *const c_void,
                value as *const _ as *const c_void,
                BPF_ANY.into(),
            );
        }
    }

    /// Delete the entry indexed by `key`
    #[inline]
    pub fn delete(&mut self, key: &LpmTrieMapKey<K>) {
        unsafe {
            bpf_map_delete_elem(
                &mut self.def as *mut _ as *mut c_void,
                key as *const _ as *const c_void,
            );
        }
    }
}

impl<K, V> BpfMap for LpmTrieMap<K, V> {
    type Key = LpmTrieMapKey<K>;
    type Value = V;
}

