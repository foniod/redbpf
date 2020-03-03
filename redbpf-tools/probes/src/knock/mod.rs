pub const MAX_SEQ_LEN: usize = 4;
#[derive(Debug, Clone)]
#[repr(C)]
pub struct PortSequence {
    pub ports: [u16; MAX_SEQ_LEN],
    pub len: usize,
    pub target: u64,
}

impl PortSequence {
    #[inline]
    pub fn is_complete(&self, other: &PortSequence) -> bool {
        if self.len != other.len {
            return false;
        }
        for i in 0..self.len {
            if self.ports[i] != other.ports[i] {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Knock {
    pub sequence: PortSequence,
    pub complete: u64,
}

impl Knock {
    pub fn new(target: u64) -> Knock {
        Knock {
            sequence: PortSequence {
                ports: [0u16; MAX_SEQ_LEN],
                len: 0,
                target,
            },
            complete: 0,
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct KnockAttempt {
    pub source_ip: u32,
    pub padding: u32,
    pub sequence: PortSequence,
}

#[derive(Debug)]
#[repr(C)]
pub struct Connection {
    pub source_ip: u32,
    pub allowed: u32,
}
