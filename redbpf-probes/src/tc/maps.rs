// Copyright 2021 Junyeong Jeong <rhdxmr@gmail.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
/*!
eBPF maps for tc

Provide BPF maps similar to
[`redbpf_probes::maps::HashMap`](../../maps/struct.HashMap.html) but can be
used only by `tc` BPF programs. So the counter part of
[`TcHashMap`](struct.TcHashMap.html) for userspace program does not
exist. However, if [`TcHashMap`](struct.TcHashMap.html) is created with
[`TcMapPinning::GlobalNamespace`](enum.TcMapPinning.html#variant.GlobalNamespace),
it is possible for userspace program of `redBPF` to load the pinning file by
calling
[`Map::from_pin_file`](../../../redbpf/struct.Map.html#method.from_pin_file). And
then, the base map can be wrapped by
[`redbpf::HashMap`](../../../redbpf/struct.HashMap.html).
*/
use core::marker::PhantomData;
use core::mem;

use crate::bindings::*;
use crate::helpers::*;
use crate::maps::BpfMap;

/// `bpf_elf_map` struct is defined by tc. It is not required to use the same
/// name, but it is better to do so.
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_elf_map {
    type_: u32,
    size_key: u32,
    size_value: u32,
    max_elem: u32,
    flags: u32,
    id: u32,
    pinning: u32,
}

/// BPF hashmap structure used by `tc` utility
///
/// `tc` supports attaching BPF programs to qdisc as direct action. And the
/// attached BPF programs can use BPF maps. But the internal structure of BPF
/// maps of `tc` is a bit different from the maps of `redBPF`. So in order to
/// define BPF maps for `tc` BPF programs, new structure should be used, not
/// the `HashMap`, `Array` or `PerCpuArray`. To solve this problem `TcHashMap`
/// is introduced to `redBPF`. It makes BPF maps available to `tc` BPF programs
/// that is also defined by `#[tc_action]` attribute macro of `redBPF`.
///
/// # Example
/// ```no_run
/// use redbpf_macros::map;
/// use redbpf_probes::tc::prelude::*;
///
/// // A section name of tc BPF map should be `maps`. You can define up to 64
/// // maps in the section (`tc` sets that constraints).
/// //
/// // key = port, value = blocked packet count
/// #[map(link_section = "maps")]
/// static mut blocked_packets: TcHashMap<u16, u64> =
///     TcHashMap::<u16, u64>::with_max_entries(1024, TcMapPinning::GlobalNamespace);
/// ```
pub struct TcHashMap<K, V> {
    def: bpf_elf_map,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

impl<K, V> BpfMap for TcHashMap<K, V> {
    type Key = K;
    type Value = V;
}

/// A structure representing types of map pinning
///
/// Pinning the map is conducted by `tc` utility when an ELF object file is
/// loaded by `tc filter add ... bpf direct-action object-file <ELF object
/// file> section <section>` command.
///
/// `GlobalNamespace` pins map to a stationary file path
///
/// `None` disables map pinning
#[repr(u32)]
#[derive(Clone, Copy)]
pub enum TcMapPinning {
    /// No sharing, no map pinning. so each tc invocation a new map instance is
    /// being created.
    None = 0,
    /// Map is private and thus shared among various program sections within
    /// the ELF object. That means a BPF map is pinned to `/sys/fs/bpf/tc/<some
    /// object id>/<map name>`
    ObjectNamespace,
    /// Place the map into a global namespace, so that it can be shared among
    /// different object files. That means a BPF map is pinned to
    /// `/sys/fs/bpf/tc/globals/<map name>`.
    GlobalNamespace,
}

impl<K, V> TcHashMap<K, V> {
    /// Creates a map with the specified maximum number of elements and pinning
    /// type.
    pub const fn with_max_entries(max_entries: u32, pinning: TcMapPinning) -> Self {
        Self {
            def: bpf_elf_map {
                type_: bpf_map_type_BPF_MAP_TYPE_HASH,
                size_key: mem::size_of::<K>() as u32,
                size_value: mem::size_of::<V>() as u32,
                max_elem: max_entries,
                flags: 0,
                id: 0,
                pinning: pinning as u32,
            },
            _k: PhantomData,
            _v: PhantomData,
        }
    }
    /// Returns a reference to the value corresponding to the key.
    ///
    /// NOTE: `tc` does not support relocation across ELF sections. So do not
    /// call this method like this `tcmap.get(&714)`. The correct code looks
    /// like the example below.
    ///
    /// # Example
    /// ```no_run
    /// # use redbpf_macros::map;
    /// # use redbpf_probes::tc::prelude::*;
    /// # use redbpf_probes::tc::{TcAction, TcActionResult};
    /// #[map(link_section = "maps")]
    /// static mut tcmap: TcHashMap<u16, u64> =
    ///     TcHashMap::<u16, u64>::with_max_entries(1024, TcMapPinning::GlobalNamespace);
    /// #[tc_action]
    /// fn tc_bpf_program(skb: SkBuff) -> TcActionResult {
    ///     let key = 714;
    ///     // use a reference of a local variable, Luke!
    ///     let val = unsafe { tcmap.get(&key).unwrap() };
    ///     Ok(TcAction::Ok)
    /// }
    /// ```
    #[inline]
    pub fn get(&mut self, key: &K) -> Option<&V> {
        unsafe {
            let value = bpf_map_lookup_elem(
                &mut self.def as *mut _ as *mut _,
                key as *const _ as *const _,
            );
            if value.is_null() {
                None
            } else {
                Some(&*(value as *const V))
            }
        }
    }

    /// Returns a mutable reference to the value corresponding to the key.
    #[inline]
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        unsafe {
            let value = bpf_map_lookup_elem(
                &mut self.def as *mut _ as *mut _,
                key as *const _ as *const _,
            );
            if value.is_null() {
                None
            } else {
                Some(&mut *(value as *mut V))
            }
        }
    }

    /// Set the `value` in the map for `key`
    #[inline]
    pub fn set(&mut self, key: &K, value: &V) {
        unsafe {
            bpf_map_update_elem(
                &mut self.def as *mut _ as *mut _,
                key as *const _ as *const _,
                value as *const _ as *const _,
                BPF_ANY.into(),
            );
        }
    }

    /// Delete the entry indexed by `key`
    #[inline]
    pub fn delete(&mut self, key: &K) {
        unsafe {
            bpf_map_delete_elem(
                &mut self.def as *mut _ as *mut _,
                key as *const _ as *const _,
            );
        }
    }
}
