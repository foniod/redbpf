// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::bindings::*;
use cty::*;

pub struct Registers {
    pub ctx: *mut pt_regs,
}

impl From<*mut c_void> for Registers {
    #[inline]
    fn from(ptr: *mut c_void) -> Registers {
        Registers {
            ctx: (ptr as *mut pt_regs),
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl Registers {
    #[inline]
    pub fn parm1(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            (*self.ctx).di
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            (*self.ctx).regs[0]
        }
    }

    #[inline]
    pub fn parm2(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            (*self.ctx).si
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            (*self.ctx).regs[1]
        }
    }

    #[inline]
    pub fn parm3(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            (*self.ctx).dx
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            (*self.ctx).regs[2]
        }
    }

    #[inline]
    pub fn parm4(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            (*self.ctx).cx
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            (*self.ctx).regs[3]
        }
    }

    #[inline]
    pub fn parm5(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            (*self.ctx).r8
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            (*self.ctx).regs[4]
        }
    }

    #[inline]
    pub fn ret(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            (*self.ctx).sp
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            (*self.ctx).regs[30]
        }
    }

    #[inline]
    pub fn fp(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            (*self.ctx).bp
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            (*self.ctx).regs[29]
        }
    }

    #[inline]
    pub fn rc(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            (*self.ctx).ax
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            (*self.ctx).regs[0]
        }
    }

    #[inline]
    pub fn sp(&self) -> u64 {
        unsafe { (*self.ctx).sp }
    }

    #[inline]
    pub fn ip(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            (*self.ctx).ip
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            (*self.ctx).pc
        }
    }
}
