//! Socket related type and functions

use crate::bindings::*;
use crate::helpers::bpf_skb_load_bytes;
use core::mem::{size_of, MaybeUninit};

pub trait FromBe {
    fn from_be(&self) -> Self;
}

macro_rules! impl_from_be {
    ($T:ident) => {
        impl FromBe for $T {
            fn from_be(&self) -> $T {
                $T::from_be(*self)
            }
        }
    };
}

impl_from_be!(u8);
impl_from_be!(u16);
impl_from_be!(u32);

// Errors in socket-related programs
pub enum SocketError {
    /// Loading data from the socket buffer failed.
    LoadFailed,
    /// Error in parsing inside a stream parser. The TCP stream is
    /// unrecoverable.
    ParserError,
}

/// SkAction is returned by verdict eBPF programs.
pub enum SkAction {
    Pass,
    Drop,
}

/// Context object provided to Socket-related programs.
pub struct SkBuff {
    /// The low level skb instance.
    pub skb: *const __sk_buff,
}

impl SkBuff {
    #[inline]
    /// Loads data from the socket buffer.
    ///
    /// Provide an easy way to load data from a packet.
    ///
    /// # Example
    /// ```no_run
    /// use core::mem;
    /// use memoffset::offset_of;
    /// use redbpf_probes::socket_filter::prelude::*;
    ///
    /// #[socket_filter]
    /// fn forward_tcp(skb: SkBuff) -> SkBuffResult {
    ///     let eth_len = mem::size_of::<ethhdr>();
    ///     let eth_proto: u16 = skb.load(offset_of!(ethhdr, h_proto))?;
    ///     let ip_proto: u8 = skb.load(eth_len + offset_of!(iphdr, protocol))?;
    ///
    ///     // only parse TCP
    ///     if !(eth_proto as u32 == ETH_P_IP && ip_proto as u32 == IPPROTO_TCP) {
    ///         return Ok(SkBuffAction::Ignore);
    ///     }
    ///     Ok(SkBuffAction::SendToUserspace)
    /// }
    /// ```
    pub fn load<T: FromBe>(&self, offset: usize) -> Result<T, SocketError> {
        unsafe {
            let mut data = MaybeUninit::<T>::uninit();
            let ret = bpf_skb_load_bytes(
                self.skb as *const _,
                offset as u32,
                &mut data as *mut _ as *mut _,
                size_of::<T>() as u32,
            );
            if ret < 0 {
                return Err(SocketError::LoadFailed);
            }

            Ok(data.assume_init().from_be())
        }
    }
}
