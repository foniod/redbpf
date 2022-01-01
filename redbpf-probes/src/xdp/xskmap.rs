use crate::xdp::{
    bpf_map_def, bpf_map_type_BPF_MAP_TYPE_XSKMAP, prelude::bpf_redirect_map, XdpAction,
};
use crate::maps::BpfMap;
use core::mem;
use cty::c_void;

/// AF_XDP socket map.
///
/// XskMap is an array-like map which may be used to redirect a packet to a target
/// AF_XDP socket in user-level code. Its values are socket file descriptors.
/// This is a wrapper for `BPF_MAP_TYPE_XSKMAP`.
#[repr(transparent)]
pub struct XskMap {
    def: bpf_map_def,
}

impl XskMap {
    /// Creates an AF_XDP socket map with the specified maximum number of elements.
    pub const fn with_max_entries(max_entries: u32) -> Self {
        Self {
            def: bpf_map_def {
                type_: bpf_map_type_BPF_MAP_TYPE_XSKMAP,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: 0,
            },
        }
    }

    /// Redirects the packet to the AF_XDP socket referenced at key `key`.
    /// Returns Ok if socket was found for specified key. XDP probe
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

impl BpfMap for XskMap {
    type Key = u32;
    type Value = u32;
}
