#[derive(Debug)]
#[repr(C)]
pub struct MallocEvent {
    pub stackid: i64,
    pub size: u64,
}
