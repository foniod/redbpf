use crate::bindings::*;
use crate::helpers::bpf_skb_load_bytes;
use core::mem;

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

pub enum SkBuffAction {
    Ignore,
    SendToUserspace,
}

pub enum SkBuffError {
    LoadFailed,
}

pub type SkBuffResult = Result<SkBuffAction, SkBuffError>;

pub struct SkBuff {
    pub skb: *const __sk_buff,
}

impl SkBuff {
    #[inline]
    pub fn load<T: FromBe>(&self, offset: usize) -> Result<T, SkBuffError> {
        unsafe {
            let mut data = mem::MaybeUninit::<T>::uninit();
            let ret = bpf_skb_load_bytes(
                self.skb as *const _,
                offset as u32,
                &mut data as *mut _ as *mut _,
                mem::size_of::<T>() as u32,
            );
            if ret < 0 {
                return Err(SkBuffError::LoadFailed);
            }

            Ok(data.assume_init().from_be())
        }
    }
}
