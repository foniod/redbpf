use std::slice;
use std::default::Default;

use bpf_sys::{XDP_FLAGS_UPDATE_IF_NOEXIST, XDP_FLAGS_SKB_MODE,
              XDP_FLAGS_DRV_MODE, XDP_FLAGS_HW_MODE, XDP_FLAGS_MODES, XDP_FLAGS_MASK};
use crate::Sample;

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum Flags {
    Unset = 0,
    UpdateIfNoExist = XDP_FLAGS_UPDATE_IF_NOEXIST,
    SkbMode = XDP_FLAGS_SKB_MODE,
    DrvMode = XDP_FLAGS_DRV_MODE,
    HwMode = XDP_FLAGS_HW_MODE,
    Modes = XDP_FLAGS_MODES,
    Mask = XDP_FLAGS_MASK
}

impl Default for Flags {
    fn default() -> Self {
        Flags::Unset
    }
}

/* NB: this needs to be kept in sync with redbpf_probes::xdp::MapData */
#[repr(C)]
pub struct MapData<T> {
    /// The custom data type to be exchanged with user space.
    data: T,
    offset: u32,
    size: u32,
    payload: [u8; 0],
}

impl<T> MapData<T> {
    pub unsafe fn from_sample<U>(sample: &Sample) -> &MapData<U> {
        &*(sample.data.as_ptr() as *const MapData<U>)
    }

    /// Return the data shared by the kernel space program.
    pub fn data(&self) -> &T {
        &self.data
    }

    /// Return the XDP payload shared by the kernel space program.
    ///
    /// Returns an empty slice if the kernel space program didn't share any XDP payload.
    pub fn payload(&self) -> &[u8] {
        unsafe {
            let base = self.payload.as_ptr().add(self.offset as usize);
            slice::from_raw_parts(base, (self.size - self.offset) as usize)
        }
    }
}
