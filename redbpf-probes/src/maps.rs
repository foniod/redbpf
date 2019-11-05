use core::default::Default;
use core::marker::PhantomData;
use core::mem;
use cty::*;

use crate::bindings::*;

use redbpf_macros::internal_helpers as helpers;

#[repr(transparent)]
pub struct HashMap<K, V> {
    def: bpf_map_def,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

impl<K, V> HashMap<K, V> {
    pub const fn new() -> Self {
        Self {
            def: bpf_map_def {
                type_: bpf_map_type_BPF_MAP_TYPE_HASH,
                key_size: mem::size_of::<K>() as u32,
                value_size: mem::size_of::<V>() as u32,
                max_entries: 10240u32,
                map_flags: 0,
            },
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    #[inline]
    #[helpers]
    pub fn get(&mut self, mut key: K) -> Option<&V> {
        let value = unsafe {
            let value = bpf_map_lookup_elem(
                &mut self.def as *mut _ as *mut c_void,
                &mut key as *mut _ as *mut c_void,
            );
            if value.is_null() {
                None
            } else {
                Some(&*(value as *const V))
            }
        };

        value
    }
}

#[derive(Debug, Copy, Clone)]
pub struct PerfMapFlags {
    index: Option<u32>,
    xdp_size: u32,
}

impl Default for PerfMapFlags {
    #[inline]
    fn default() -> Self {
        PerfMapFlags {
            index: None,
            xdp_size: 0
        }
    }
}

impl PerfMapFlags {
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    #[inline]
    pub fn with_xdp_size(size: u32) -> Self {
        *PerfMapFlags::new().xdp_size(size)
    }

    #[inline]
    pub fn index(&mut self, index: u32) -> &mut PerfMapFlags {
        self.index = Some(index);
        self
    }

    #[inline]
    pub fn xdp_size(&mut self, size: u32) -> &mut PerfMapFlags {
        self.xdp_size = size;
        self
    }
}

impl From<PerfMapFlags> for u64 {
    #[inline]
    fn from(flags: PerfMapFlags) -> u64 {
        (flags.xdp_size as u64) << 32 | (flags.index.unwrap_or(BPF_F_CURRENT_CPU) as u64)
    }
}

#[repr(transparent)]
pub struct PerfMap<T> {
    def: bpf_map_def,
    _event: PhantomData<T>,
}

impl<T> PerfMap<T> {
    pub const fn new() -> Self {
        Self {
            def: bpf_map_def {
                type_: bpf_map_type_BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries: 10240u32,
                map_flags: 0,
            },
            _event: PhantomData,
        }
    }

    #[inline]
    #[helpers]
    pub fn insert<C>(&mut self, ctx: *mut C, data: T) {
        self.insert_with_flags(ctx, data, PerfMapFlags::default())
    }

    #[inline]
    #[helpers]
    pub fn insert_with_flags<C>(&mut self, ctx: *mut C, mut data: T, flags: PerfMapFlags) {
        unsafe {
            bpf_perf_event_output(
                ctx as *mut _ as *mut c_void,
                &mut self.def as *mut _ as *mut c_void,
                flags.into(),
                &mut data as *mut _ as *mut c_void,
                mem::size_of::<T>() as u64,
            );
        };
    }
}
