// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use futures::{Async, Poll, Stream};
use mio::unix::EventedFd;
use mio::{Evented, PollOpt, Ready, Token};
use redbpf::PerfMap;
use std::io;
use std::os::unix::io::RawFd;
use std::slice;
use tokio::reactor::{Handle, PollEvented2};

pub struct GrainIo(RawFd);

impl Evented for GrainIo {
    fn register(
        &self,
        poll: &mio::Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        EventedFd(&self.0).register(poll, token, interest, opts)
    }

    fn reregister(
        &self,
        poll: &mio::Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        EventedFd(&self.0).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &mio::Poll) -> io::Result<()> {
        EventedFd(&self.0).deregister(poll)
    }
}

pub struct PerfMessageStream {
    poll: PollEvented2<GrainIo>,
    map: PerfMap,
    name: String,
}

impl PerfMessageStream {
    pub fn new(name: String, map: PerfMap) -> Self {
        let io = GrainIo(map.fd);
        let poll = PollEvented2::new_with_handle(io, &Handle::default()).unwrap();
        PerfMessageStream { poll, map, name }
    }

    fn read_messages(&mut self) -> Vec<Box<[u8]>> {
        use redbpf::Event;

        let mut ret = Vec::new();
        while let Some(ev) = self.map.read() {
            match ev {
                Event::Lost(lost) => {
                    eprintln!("Possibly lost {} samples for {}", lost.count, &self.name);
                }
                Event::Sample(sample) => {
                    let msg = unsafe {
                        slice::from_raw_parts(sample.data.as_ptr(), sample.size as usize)
                            .to_vec()
                            .into_boxed_slice()
                    };
                    ret.push(msg);
                }
            };
        }

        ret
    }
}

impl Stream for PerfMessageStream {
    type Item = Vec<Box<[u8]>>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let ready = Ready::readable();
        if self.poll.poll_read_ready(ready)? == Async::NotReady {
            return Ok(Async::NotReady);
        }

        let messages = self.read_messages();
        self.poll.clear_read_ready(ready).unwrap();
        Ok(Async::Ready(Some(messages)))
    }
}
