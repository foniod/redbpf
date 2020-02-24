use core::mem::{size_of, MaybeUninit};

use crate::bindings::*;
use cty::*;
pub use ufmt;
use ufmt::uWrite;
pub mod gen {
    include!(concat!(env!("OUT_DIR"), "/gen_helpers.rs"));
}

pub struct TraceMessage {
    msg: [u8; 50],
    write_i: usize
}

impl TraceMessage {
    #[inline]
    pub fn new() -> Self {
        TraceMessage {
            msg: unsafe { core::mem::MaybeUninit::uninit().assume_init() },
            write_i: 0
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

#[inline]
pub fn bpf_get_current_pid_tgid() -> u64 {
    unsafe { gen::bpf_get_current_pid_tgid() }
}

#[inline]
pub fn bpf_get_current_uid_gid() -> u64 {
    unsafe { gen::bpf_get_current_uid_gid() }
}

#[inline]
pub fn bpf_get_current_comm() -> [c_char; 16] {
    let mut comm: [c_char; 16usize] = [0; 16];
    unsafe { gen::bpf_get_current_comm(&mut comm as *mut _ as *mut c_void, 16u32) };
    comm
}

#[inline]
pub fn bpf_ktime_get_ns() -> u64 {
    unsafe { gen::bpf_ktime_get_ns() }
}

#[inline]
pub unsafe fn bpf_probe_read<T>(src: *const T) -> Result<T, i32> {
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
pub fn bpf_perf_event_output(
    ctx: *mut c_void,
    map: *mut c_void,
    flags: u64,
    data: *const c_void,
    size: u64,
) -> i32 {
    unsafe {
        let f: unsafe extern "C" fn(
            ctx: *mut c_void,
            map: *mut c_void,
            flags: u64,
            data: *const c_void,
            size: u64,
        ) -> i32 = ::core::mem::transmute(25usize);
        f(ctx, map, flags, data, size)
    }
}