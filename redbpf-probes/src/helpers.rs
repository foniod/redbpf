use core::mem::{size_of, MaybeUninit};

use cty::*;
use crate::bindings::*;

mod gen {
    include!(concat!(env!("OUT_DIR"), "/gen_helpers.rs"));
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
pub fn bpf_probe_read<T>(src: *const T) -> T {
    unsafe {
        let mut v: MaybeUninit<T> = MaybeUninit::uninit();
        gen::bpf_probe_read(
            v.as_mut_ptr() as *mut c_void,
            size_of::<T>() as u32,
            src as *const c_void,
        );

        v.assume_init()
    }
}

#[macro_export]
macro_rules! bpf_probe_read {
    ( $x:expr ) => {
        bpf_probe_read(unsafe { $x })
    };
}