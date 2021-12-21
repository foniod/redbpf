// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! # Ring Buffer Event handling
//!
//! The ringbuf module makes it easier to hook up and consume from ring buffers.
//! and provdes a safe interface for accesing the ring buffer
//!
//! The consumed data is a raw pointer and will require unsafe code to transform
//! into a data structure.

use crate::{Error, Map, Result};
use std::cell::RefCell;
use std::io;
use std::os::unix::io::RawFd;
use std::slice;

use libbpf_sys::{
    ring_buffer, ring_buffer__consume, ring_buffer__epoll_fd, ring_buffer__free, ring_buffer__new,
};
use libc::c_void;

#[derive(Debug)]
struct RingBufMapContext {
    messages: RefCell<Vec<Box<[u8]>>>,
}

impl RingBufMapContext {
    fn new() -> RingBufMapContext {
        RingBufMapContext {
            messages: RefCell::new(Vec::new()),
        }
    }

    pub fn read_message(&self, data: *mut c_void, size: u64) {
        unsafe {
            let mut messages = self.messages.borrow_mut();
            let message = slice::from_raw_parts(data as *const u8, size as usize).to_vec();
            messages.push(message.into_boxed_slice());
        }
    }

    pub fn take_messages(&self) -> Vec<Box<[u8]>> {
        let mut messages = self.messages.borrow_mut();
        let new_vec = messages.clone();
        messages.clear();
        new_vec
    }
}

#[derive(Debug)]
pub struct RingBufInner(*mut ring_buffer);
unsafe impl Send for RingBufInner {}

#[derive(Debug)]
pub struct RingBufMap {
    ctx: Box<RingBufMapContext>,
    ring_buffer: RingBufInner,
    pub fd: RawFd,
}

unsafe extern "C" fn ring_buffer_sample_cb(ctx: *mut c_void, data: *mut c_void, size: u64) -> i32 {
    let rb = &mut *(ctx as *mut RingBufMapContext);
    rb.read_message(data, size);
    0
}

impl RingBufMap {
    pub fn bind(map: &mut Map) -> Result<RingBufMap> {
        unsafe {
            if map.kind != 27 {
                return Err(Error::IO(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid map type {}", map.config.type_),
                )));
            }

            let mut ctx = Box::new(RingBufMapContext::new());
            let ring_buffer = ring_buffer__new(
                map.fd,
                Some(ring_buffer_sample_cb),
                &mut *ctx as *mut _ as *mut c_void,
                std::ptr::null(),
            );

            if ring_buffer.is_null() {
                Err(Error::IO(io::Error::last_os_error()))
            } else {
                let fd = ring_buffer__epoll_fd(ring_buffer);
                Ok(RingBufMap {
                    ctx,
                    ring_buffer: RingBufInner(ring_buffer),
                    fd,
                })
            }
        }
    }

    pub fn read_messages(&self) -> Vec<Box<[u8]>> {
        unsafe {
            ring_buffer__consume(self.ring_buffer.0);
            self.ctx.take_messages()
        }
    }
}

impl Drop for RingBufMap {
    fn drop(&mut self) {
        unsafe {
            ring_buffer__free(self.ring_buffer.0);
        }
    }
}
