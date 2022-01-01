use crate::xdp::{
    bpf_map_def, bpf_map_type_BPF_MAP_TYPE_DEVMAP, prelude::bpf_redirect_map, XdpAction,
};
use crate::maps::BpfMap;
use core::mem;
use cty::c_void;

/// Device map.
///
/// DevMap is array-like map which may be used to redirect packet to another
/// network interface. It's values are interface indices.
/// This is a wrapper for `BPF_MAP_TYPE_DEVMAP`.
#[repr(transparent)]
pub struct DevMap {
    def: bpf_map_def,
}

impl DevMap {
    /// Creates a device map with the specified maximum number of elements.
    pub const fn with_max_entries(max_entries: u32) -> Self {
        Self {
            def: bpf_map_def {
                type_: bpf_map_type_BPF_MAP_TYPE_DEVMAP,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: 0,
            },
        }
    }

    /// Redirects the packet to the endpoint referenced at key `key`.
    /// Returns Ok if device was found for specified key. XDP probe
    /// must return XdpAction::Redirect to actually redirect packet.
    /// If key is not found, Err is returned.
    #[inline]
    pub fn redirect(&mut self, key: u32) -> Result<(), ()> {
        let res = bpf_redirect_map(
            &mut self.def as *mut _ as *mut c_void,
            key,
            XdpAction::Aborted as u64,
        );
        if res == XdpAction::Redirect as i64 {
            Ok(())
        } else {
            Err(())
        }
    }
}

impl BpfMap for DevMap {
    type Key = u32;
    type Value = u32;
}
