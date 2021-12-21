// Copyright 2022 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/*!
eBPF ringbuf.
 */
use core::marker::PhantomData;
use core::mem;
use cty::*;

use crate::bindings::*;
use crate::helpers::*;
use crate::maps::BpfMap;

/// Flags that be passed to `RingBuf::output_with_flags`.
#[derive(Debug, Copy, Clone)]
pub struct RingBufMapFlags(u64);

impl Default for RingBufMapFlags {
    #[inline]
    fn default() -> Self {
        RingBufMapFlags(0)
    }
}

impl RingBufMapFlags {
    /// Create new default flags.
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    /// Set BPF_RB_NO_WAKEUP flag.
    #[inline]
    pub fn no_wakeup(&mut self) -> &mut RingBufMapFlags {
        self.0 |= BPF_RB_NO_WAKEUP as u64;
        self
    }

    /// Set BPF_RB_FORCE_WAKEUP flag
    #[inline]
    pub fn force_wakeup(&mut self) -> &mut RingBufMapFlags {
        self.0 |= BPF_RB_FORCE_WAKEUP as u64;
        self
    }
}

impl From<RingBufMapFlags> for u64 {
    #[inline]
    fn from(flags: RingBufMapFlags) -> u64 {
        flags.0
    }
}

/// Ring buffer map.
///
/// This is a wrapper for `BPF_MAP_TYPE_RINGBUF`.
pub struct RingBufMap<T> {
    def: bpf_map_def,
    _event: PhantomData<T>,
}

impl<T> RingBufMap<T> {
    /// Creates a ring buffer map with the specied maximum number of elements.
    ///
    /// `buffer_size` must be a power of 2 value and must be page aligned.
    pub const fn with_buffer_size(buffer_size: u32) -> Self {
        Self {
            def: bpf_map_def {
                type_: bpf_map_type_BPF_MAP_TYPE_RINGBUF,
                key_size: 0,
                value_size: 0,
                max_entries: buffer_size,
                map_flags: 0,
            },
            _event: PhantomData,
        }
    }

    /// Copy data to ring buffer.
    ///
    /// The ring buffer can hold up to `buffer_size` bytes, see `with_buffer_size`.
    /// No loss reporting occurs in user space. Monitoring must be done by the BPF
    /// program.
    ///
    /// This method will wake up the polling thread if it is currently waiting on the
    /// ring buffer. If this isn't desired, see `output_with_flags`.
    #[inline]
    pub fn output(&mut self, data: &T) -> Result<(), i64> {
        self.output_with_flags(data, RingBufMapFlags::default())
    }

    /// Copy data to ring buffer specifying wake options in the given
    /// `RingBufMapFlags`.
    #[inline]
    pub fn output_with_flags(&mut self, data: &T, flags: RingBufMapFlags) -> Result<(), i64> {
        unsafe {
            let ret = bpf_ringbuf_output(
                &mut self.def as *mut _ as *mut c_void,
                data as *const _ as *mut c_void,
                mem::size_of::<T>() as u64,
                flags.into(),
            );
            if ret == 0 {
                Ok(())
            } else {
                Err(ret)
            }
        }
    }

    /// Reserve sample in ring buffer.
    #[inline]
    pub fn reserve(&mut self) -> Option<RingBufPayload<T>> {
        unsafe {
            let ptr = bpf_ringbuf_reserve(
                &mut self.def as *mut _ as *mut c_void,
                mem::size_of::<T>() as u64,
                0,
            ) as *mut T;

            if ptr.is_null() {
                None
            } else {
                Some(RingBufPayload {
                    reserved: true,
                    ptr,
                })
            }
        }
    }
}

impl<T> BpfMap for RingBufMap<T> {
    type Key = u32;
    type Value = T;
}

/// Ring buffer map entry.
pub struct RingBufPayload<T> {
    reserved: bool,
    ptr: *mut T,
}

impl<T> RingBufPayload<T> {
    /// Retrieve payload as mutable reference.
    ///
    /// # Safety
    ///
    /// Safety of this funciton is the same as ptr::as_mut:
    ///
    /// * The pointer must be properly aligned.
    ///
    /// * It must be "dereferencable" in the sense defined in [the module documentation].
    ///
    /// * You must enforce Rust's aliasing rules, since the returned lifetime `'a` is
    ///   arbitrarily chosen and does not necessarily reflect the actual lifetime of the data.
    ///   In particular, for the duration of this lifetime, the memory the pointer points to must
    ///   not get accessed (read or written) through any other pointer.
    ///
    /// This pointer is already assumed to be non-null since it was checked in RingBufMap::reserve.
    pub unsafe fn as_mut(&self) -> &mut T {
        self.ptr.as_mut().unwrap()
    }

    /// Submit reserved sample.
    #[inline]
    pub fn submit(&mut self) {
        self.submit_with_flags(RingBufMapFlags::default())
    }

    /// Submit reserved sample specifying wake options in the given `RingBufMapFlags`.
    #[inline]
    pub fn submit_with_flags(&mut self, flags: RingBufMapFlags) {
        unsafe { bpf_ringbuf_submit(self.ptr as *mut c_void, flags.into()) }
        self.reserved = false;
    }

    /// Discard reserved sample.
    #[inline]
    pub fn discard(&mut self) {
        self.discard_with_flags(RingBufMapFlags::default());
    }

    /// Discard reserved sample specifying wake options in the given `RingBufMapFlags`.
    #[inline]
    pub fn discard_with_flags(&mut self, flags: RingBufMapFlags) {
        unsafe {
            bpf_ringbuf_discard(self.ptr as *mut c_void, flags.into());
        }
        self.reserved = false;
    }
}

impl<T> Drop for RingBufPayload<T> {
    fn drop(&mut self) {
        if self.reserved {
            self.discard();
        }
    }
}
