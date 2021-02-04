#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct IdxMapKey {
    pub addr: u32,
    // u32 is used becase __sk_buff.remote_port is u32
    pub port: u32,
}
