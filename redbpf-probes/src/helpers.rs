use crate::bindings::*;
use cty::*;

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
