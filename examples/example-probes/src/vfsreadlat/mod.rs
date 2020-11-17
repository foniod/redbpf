// use cty::*;

// This is where you should define the types shared by the kernel and user
// space, eg:
//
// #[repr(C)]
// #[derive(Debug)]
// pub struct SomeEvent {
//     pub pid: u64,
//     ...
// }
#[derive(Debug)]
#[repr(C)]
pub struct VFSEvent {
    pub pid: u64,
    pub tgid: u64,
    pub timestamp: u64,
    pub latency: u64,
}
