use core::sync::atomic::AtomicU64;

use redbpf_macros::global;

/// global variable is shared between multiple cores so proper synchronization
/// should be involved carefully.
#[global]
pub static GLOBAL_VAR: AtomicU64 = AtomicU64::new(0);

/// global variable without any synchronization mechanism. This results in wrong
/// statistics.
#[global]
pub static mut GLOBAL_VAR_INCORRECT: u64 = 0;
