#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

extern crate zero;
pub mod headers;
pub mod perf_reader;
pub mod uname;

pub const BUF_SIZE_MAP_NS: usize = 256;
pub struct bpf_map_def {
	  pub kind: u32,
	  pub key_size: u32,
	  pub value_size: u32,
	  pub max_entries: u32,
	  pub map_flags: u32,
	  pub pinning: u32,
	  pub namespace: [i8; BUF_SIZE_MAP_NS]
}
unsafe impl ::zero::Pod for bpf_map_def {}
unsafe impl ::zero::Pod for bpf_insn {}

include!(concat!(env!("OUT_DIR"), "/libbpf_bindings.rs"));