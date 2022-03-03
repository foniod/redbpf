use cty::*;

#[derive(Clone, Debug)]
#[repr(C)]
pub struct Process {
    pub pid: u64,
    pub comm: [c_char; 16],
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct CounterKey {
    pub process: Process,
    pub major: i32,
    pub minor: i32,
    pub write: u64,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct Counter {
    pub bytes: u64,
    pub us: u64,
    pub io: u64,
}
