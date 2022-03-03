use std::default::Default;
use std::mem;
use std::slice;

use crate::error::{Error, Result};
use crate::{Map, Sample};
use libbpf_sys::{
    BPF_ANY, BPF_MAP_TYPE_DEVMAP, XDP_FLAGS_DRV_MODE, XDP_FLAGS_HW_MODE, XDP_FLAGS_MASK,
    XDP_FLAGS_MODES, XDP_FLAGS_SKB_MODE, XDP_FLAGS_UPDATE_IF_NOEXIST,
};

use tracing::error;

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum Flags {
    Unset = 0,
    UpdateIfNoExist = XDP_FLAGS_UPDATE_IF_NOEXIST,
    SkbMode = XDP_FLAGS_SKB_MODE,
    DrvMode = XDP_FLAGS_DRV_MODE,
    HwMode = XDP_FLAGS_HW_MODE,
    Modes = XDP_FLAGS_MODES,
    Mask = XDP_FLAGS_MASK,
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
    /// # Safety
    ///
    /// Casts a pointer of `Sample.data` to `*const MapData<U>`
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

/// DevMap structure for storing interface indices to redirect packets to.
///
/// A devmap is a BPF map type that holds network interface indices. BPF XDP
/// program can use the devmap to redirect raw packets to another interface.
///
/// The counterpart which is used by BPF program is:
/// [`redbpf_probes::maps::DevMap`](../redbpf_probes/maps/struct.DevMap.html).
pub struct DevMap<'a> {
    base: &'a Map,
}

impl<'a> DevMap<'a> {
    pub fn new(base: &'a Map) -> Result<DevMap<'a>> {
        if mem::size_of::<u32>() != base.config.key_size as usize
            || mem::size_of::<u32>() != base.config.value_size as usize
            || (BPF_MAP_TYPE_DEVMAP != base.config.type_)
        {
            error!(
                "map definitions (map type and key/value size) of base `Map' and
            `DevMap' do not match"
            );
            return Err(Error::Map);
        }

        Ok(DevMap { base })
    }

    pub fn set(&mut self, mut idx: u32, mut interface_index: u32) -> Result<()> {
        let ret = unsafe {
            libbpf_sys::bpf_map_update_elem(
                self.base.fd,
                &mut idx as *mut _ as *mut _ as *mut _,
                &mut interface_index as *mut _ as *mut _,
                BPF_ANY.into(), // No condition on the existence of the entry for `idx`.
            )
        };
        if ret < 0 {
            Err(Error::Map)
        } else {
            Ok(())
        }
    }

    pub fn delete(&mut self, mut idx: u32) -> Result<()> {
        let ret =
            unsafe { libbpf_sys::bpf_map_delete_elem(self.base.fd, &mut idx as *mut _ as *mut _) };
        if ret < 0 {
            Err(Error::Map)
        } else {
            Ok(())
        }
    }
}
