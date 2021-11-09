#[repr(C)]
#[derive(Clone, Debug)]
pub struct BigStructure {
    pub f1: usize,
    pub f2: [usize; 100],
}

impl Default for BigStructure {
    fn default() -> Self {
        BigStructure {
            f1: 0,
            f2: [0; 100],
        }
    }
}
