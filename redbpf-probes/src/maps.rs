use core::marker::PhantomData;
use core::mem::{self, transmute};
use cty::*;

use crate::bindings::*;

#[repr(C)]
pub struct Helpers {
  pub bpf_trace_printk: unsafe extern "C" fn(
    fmt: *const c_char,
    fmt_size: c_int,
    ...
  ) -> c_int,
  pub bpf_map_lookup_elem: unsafe extern "C" fn(
    map: *mut c_void,
    key: *mut c_void,
  ) -> *mut c_void,
  pub bpf_perf_event_output: unsafe extern "C" fn(
    ctx: *mut c_void,
    map: *mut c_void,
    flags: c_ulonglong,
    data: *mut c_void,
    size: c_int,
  ) -> c_int,
  pub bpf_get_smp_processor_id: unsafe extern "C" fn() -> c_ulonglong,
  pub bpf_get_current_pid_tgid: unsafe extern "C" fn() -> c_ulonglong,
  pub bpf_get_current_comm: unsafe extern "C" fn(
    buf: *mut c_void,
    buf_size: c_int,
  ) -> c_int,
}

#[inline(always)]
pub const fn helpers() -> Helpers {
  Helpers {
    bpf_trace_printk: unsafe { transmute(bpf_func_id_BPF_FUNC_trace_printk as u64) },
    bpf_map_lookup_elem: unsafe { transmute(bpf_func_id_BPF_FUNC_map_lookup_elem as u64) },
    bpf_perf_event_output: unsafe { transmute(bpf_func_id_BPF_FUNC_perf_event_output as u64) },
    bpf_get_smp_processor_id: unsafe { transmute(bpf_func_id_BPF_FUNC_get_smp_processor_id as u64) },
    bpf_get_current_pid_tgid: unsafe { transmute(bpf_func_id_BPF_FUNC_get_current_pid_tgid as u64) },
    bpf_get_current_comm: unsafe { transmute(bpf_func_id_BPF_FUNC_get_current_comm as u64) },
  }
}

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
        map_flags: 0u32,
        pinning: 0u32,
        namespace: [0; 256],
      },
      _k: PhantomData,
      _v: PhantomData
    }
  }

  pub fn get(&mut self, mut key: K) -> Option<&V> {
    let Helpers {
      bpf_map_lookup_elem,
      ..
    } = helpers();

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
        map_flags: 0u32,
        pinning: 0u32,
        namespace: [0; 256],
      },
      _event: PhantomData
    }
  }

  pub fn insert<C>(&mut self, ctx: *mut C, mut data: T) {
    let Helpers {
      bpf_perf_event_output,
      bpf_get_smp_processor_id,
      ..
    } = helpers();
    let cpu = unsafe { bpf_get_smp_processor_id() };
    unsafe {
      bpf_perf_event_output(
        ctx as *mut _ as *mut c_void,
        &mut self.def as *mut _ as *mut c_void,
        cpu,
        &mut data as *mut _ as *mut c_void,
        mem::size_of::<T>() as i32,
      );
    };
  }
}
