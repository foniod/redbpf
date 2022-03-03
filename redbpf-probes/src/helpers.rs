// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/*!
Wrappers for the helper functions provided by the BPF subsystem.

See <http://man7.org/linux/man-pages/man7/bpf-helpers.7.html>.
*/
use core::mem::{size_of, MaybeUninit};

use crate::bindings::*;
use cty::*;
pub use ufmt;
use ufmt::uWrite;
pub mod gen {
    /*!
    Low-level, generated bindings for the helper functions provided by the BPF
    subsystem.
    */
    include!(concat!(env!("OUT_DIR"), "/gen_helpers.rs"));
}

pub struct TraceMessage {
    msg: [u8; 50],
    write_i: usize,
}

impl TraceMessage {
    #[inline]
    pub fn new() -> Self {
        TraceMessage {
            msg: unsafe { core::mem::MaybeUninit::uninit().assume_init() },
            write_i: 0,
        }
    }

    #[inline]
    pub fn printk(&self) {
        bpf_trace_printk(&self.msg[..self.write_i]);
    }
}

impl uWrite for TraceMessage {
    type Error = ();

    #[inline]
    fn write_str(&mut self, s: &str) -> Result<(), Self::Error> {
        let bytes = s.as_bytes();
        let len = bytes.len();
        let available = self.msg.len() - self.write_i;
        if available < len {
            return Err(());
        }

        self.msg[self.write_i..self.write_i + len].copy_from_slice(bytes);
        self.write_i += len;
        Ok(())
    }
}

pub use gen::*;

/// Returns the current tgid and pid, encoded as `current_task->tgid << 32 |
/// current_task->pid`.
#[inline]
pub fn bpf_get_current_pid_tgid() -> u64 {
    unsafe { gen::bpf_get_current_pid_tgid() }
}

/// Returns the current GID and UID, encoded as `current_gid << 32 |
/// current_uid`.
#[inline]
pub fn bpf_get_current_uid_gid() -> u64 {
    unsafe { gen::bpf_get_current_uid_gid() }
}

/// Returns the `comm` attribute of the current task. The comm attribute contains
/// the name of the executable (excluding the path) for the current task.
#[inline]
pub fn bpf_get_current_comm() -> [c_char; 16] {
    let mut comm: [c_char; 16usize] = [0; 16];
    unsafe { gen::bpf_get_current_comm(&mut comm as *mut _ as *mut c_void, 16u32) };
    comm
}

/// Returns the time elapsed since system boot, in nanoseconds.
///
/// The time during the system was suspended is **NOT** included.
#[inline]
pub fn bpf_ktime_get_ns() -> u64 {
    unsafe { gen::bpf_ktime_get_ns() }
}

/// Return the time elapsed since system boot, in nanoseconds
///
/// The time during the system was suspended is included.
pub fn bpf_ktime_get_boot_ns() -> u64 {
    unsafe { gen::bpf_ktime_get_boot_ns() }
}

/// Return a coarse-grained version of the time elapsed since system boot, in nanoseconds
///
/// The time during the system was suspended is **NOT** included.
pub fn bpf_ktime_get_coarse_ns() -> u64 {
    unsafe { gen::bpf_ktime_get_coarse_ns() }
}

// For tracing programs, safely attempt to read `mem::size_of::<T>()` bytes from
// address src.
#[inline]
pub unsafe fn bpf_probe_read<T>(src: *const T) -> Result<T, i64> {
    let mut v: MaybeUninit<T> = MaybeUninit::uninit();
    let ret = gen::bpf_probe_read(
        v.as_mut_ptr() as *mut c_void,
        size_of::<T>() as u32,
        src as *const c_void,
    );
    if ret < 0 {
        return Err(ret);
    }

    Ok(v.assume_init())
}

/// Print a message to `/sys/kernel/debug/tracing/trace_pipe`
///
/// `message` should end with NUL byte. Otherwise, it is rejected by the Linux
/// kernel so it won't be shown at the `trace_pipe`
///
/// # Example
/// ```no_run
/// # use redbpf_probes::kprobe::prelude::*;
///
/// # #[kprobe]
/// # fn print_example(_regs: Registers) {
/// bpf_trace_printk(b"Hello world\0");
/// # }
/// ```
#[inline]
pub fn bpf_trace_printk(message: &[u8]) -> ::cty::c_int {
    unsafe {
        let f: unsafe extern "C" fn(fmt: *const ::cty::c_char, fmt_size: __u32) -> ::cty::c_int =
            ::core::mem::transmute(6usize);
        f(
            message.as_ptr() as *const ::cty::c_char,
            message.len() as u32,
        )
    }
}

#[inline]
pub fn bpf_trace_printk_raw(message: &[u8], arg1: u64, arg2: u64, arg3: u64) -> Result<i32, ()> {
    let res = unsafe {
        let f: unsafe extern "C" fn(
            fmt: *const ::cty::c_char,
            fmt_size: __u32,
            arg1: u64,
            arg2: u64,
            arg3: u64,
        ) -> ::cty::c_int = ::core::mem::transmute(6usize);
        f(
            message.as_ptr() as *const ::cty::c_char,
            message.len() as u32,
            arg1,
            arg2,
            arg3,
        )
    };
    return if res >= 0 { Ok(res) } else { Err(()) };
}

/// Get a pseudo-random number
#[inline]
pub fn bpf_get_prandom_u32() -> u32 {
    unsafe { gen::bpf_get_prandom_u32() }
}

/// Get the SMP (symmetric multiprocessing) processor id
#[inline]
pub fn bpf_get_smp_processor_id() -> u32 {
    unsafe { gen::bpf_get_smp_processor_id() }
}

/// A pointer to the current task struct
#[inline]
pub fn bpf_get_current_task() -> u64 {
    unsafe { gen::bpf_get_current_task() }
}

/// The id of current NUMA node
#[inline]
pub fn bpf_get_numa_node_id() -> i64 {
    unsafe { gen::bpf_get_numa_node_id() }
}

/// Current cgroup id within which the current task is running
#[inline]
pub fn bpf_get_current_cgroup_id() -> u64 {
    unsafe { gen::bpf_get_current_cgroup_id() }
}

/// Obtain the 64bit jiffies
#[inline]
pub fn bpf_jiffies64() -> u64 {
    unsafe { gen::bpf_jiffies64() }
}

#[inline]
pub fn bpf_perf_event_output(
    ctx: *mut c_void,
    map: *mut c_void,
    flags: u64,
    data: *const c_void,
    size: u64,
) -> i64 {
    unsafe {
        let f: unsafe extern "C" fn(
            ctx: *mut c_void,
            map: *mut c_void,
            flags: u64,
            data: *const c_void,
            size: u64,
        ) -> i64 = ::core::mem::transmute(25usize);
        f(ctx, map, flags, data, size)
    }
}

#[inline]
pub fn bpf_redirect_map(map: *mut c_void, key: u32, flags: u64) -> i64 {
    unsafe {
        let f: unsafe extern "C" fn(map: *mut c_void, key: u32, flags: u64) -> i64 =
            ::core::mem::transmute(51usize);
        f(map, key, flags)
    }
}
