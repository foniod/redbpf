use core::marker::PhantomData;
use core::mem;
use cty::*;

use crate::bindings::*;

use redbpf_macros::internal_helpers as helpers;

#[repr(transparent)]
pub struct HashMap<K, V> {
  def: bpf_map_def,
  _k: PhantomData<K>,
  _v: PhantomData<V>
}

impl<K, V: Copy> HashMap<K, V> {
  pub const fn new() -> Self {
    Self {
      def: bpf_map_def {
        type_: bpf_map_type_BPF_MAP_TYPE_HASH,
        key_size: mem::size_of::<K>() as u32,
        value_size: mem::size_of::<V>() as u32,
        max_entries: 10240u32,
        map_flags: 0
      },
      _k: PhantomData,
      _v: PhantomData
    }
  }

  #[inline]
  #[helpers]
  pub fn get(&mut self, mut key: K) -> Option<&V> {
    let value = unsafe {
        let value = bpf_map_lookup_elem(&mut self.def as *mut _ as *mut c_void, &mut key as *mut _ as *mut c_void);
        if value.is_null() {
            None
        } else {
            Some(&*(value as *const V))
        }
    };

    value
  }
}

#[repr(transparent)]
pub struct PerfMap<T> {
  def: bpf_map_def,
  _event: PhantomData<T>
}

impl<T> PerfMap<T> {
  pub const fn new() -> Self {
    Self {
      def: bpf_map_def {
        type_: bpf_map_type_BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        key_size: mem::size_of::<u32>() as u32,
        value_size: mem::size_of::<u32>() as u32,
        max_entries: 10240u32,
        map_flags: 0
      },
      _event: PhantomData
    }
  }

  #[inline]
  #[helpers]
  pub fn insert<C>(&mut self, ctx: *mut C, mut data: T) {
    unsafe {
      bpf_perf_event_output(
        ctx as *mut _ as *mut c_void,
        &mut self.def as *mut _ as *mut c_void,
        BPF_F_CURRENT_CPU as u64,
        &mut data as *mut _ as *mut c_void,
        mem::size_of::<T>() as u64,
      );
    };
  }

  #[inline]
  #[helpers]
  pub fn insert_xdp<C>(&mut self, ctx: *mut C, mut data: T, size: usize) {
    unsafe {
      bpf_perf_event_output(
        ctx as *mut _ as *mut c_void,
        &mut self.def as *mut _ as *mut c_void,
        (size as u64) << 32 | BPF_F_CURRENT_CPU as u64,
        &mut data as *mut _ as *mut c_void,
        mem::size_of::<T>() as u64,
      );
    };
  }
}
