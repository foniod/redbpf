#[derive(Debug)]
#[repr(C)]
pub struct MallocEvent {
    pub stackid: i32,
    pub _padding: i32,
    pub size: u64,
}
