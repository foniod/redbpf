//! To read the input parameters for a tracepoint conveniently, define a struct
//! to hold the input arguments. Refer to to
//! `/sys/kernel/debug/tracing/events/<category>/<tracepoint>/format`
//! for information about a specific tracepoint.

#[repr(C, packed(1))]
pub struct TracepointCommonArgs {
    pub ctype: u16,
    pub flags: u8,
    pub preempt_count: u8,
    pub pid: i32,
}

/// Members defined in `cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/format
/// Note that offset addresses are important here, so ensure the compiler does not add padding.
/// Any required padding will be set explicitly here.
#[repr(C, packed(1))]
pub struct SysEnterConnectArgs {
    pub common: TracepointCommonArgs,
    pub sys_nr: i32,
    pad: u32,
    pub fd: u64,
    pub useraddr: u64,
    pub addrlen: u64,
}