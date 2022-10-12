// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use futures::channel::mpsc;
use futures::prelude::*;
use std::convert::AsRef;
use std::fs;
use std::io;
use std::path::Path;

use crate::load::map_io::{PerfMessageStream, RingBufMessageStream};
use crate::{cpus, Program, TracePoint};
use crate::{
    Error, KProbe, Map, Module, PerfMap, RingBufMap, SkLookup, SocketFilter, StreamParser,
    StreamVerdict, TaskIter, UProbe, XDP,
};

#[derive(Debug)]
pub enum LoaderError {
    FileError(io::Error),
    ParseError(Error),
    LoadError(String, Error),
}

/// High level API to load bpf programs.
pub struct Loader {}

// save for tasks of PerfMessageStream and RingBufMessageStream to abort when Loaded destoryed to avoid fd leak
struct JoinHandles {
    inner: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for JoinHandles {
    fn drop(&mut self) {
        for handle in self.inner.iter() {
            handle.abort();
        }
    }
}

impl Loader {
    /// Loads the programs included in `data`.
    ///
    /// This will parse `data` with `Module::parse()` and load all the programs
    /// present in the module.
    pub fn load(data: &[u8]) -> Result<Loaded, LoaderError> {
        let mut module = Module::parse(&data).map_err(LoaderError::ParseError)?;
        for program in module.programs.iter_mut() {
            program
                .load(module.version, module.license.clone())
                .map_err(|e| LoaderError::LoadError(program.name().to_string(), e))?;
        }

        let online_cpus = cpus::get_online().unwrap();
        let (sender, receiver) = mpsc::unbounded();

        let mut _join_handles = JoinHandles { inner: Vec::new() };
        // bpf_map_type_BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4
        for m in module.maps.iter_mut().filter(|m| m.kind == 4) {
            for cpuid in online_cpus.iter() {
                let name = m.name.clone();
                let map = PerfMap::bind(m, -1, *cpuid, 16, -1, 0).unwrap();
                let stream = PerfMessageStream::new(name.clone(), map);
                let mut s = sender.clone();
                let fut = stream.for_each(move |events| {
                    s.start_send((name.clone(), events)).unwrap();
                    future::ready(())
                });
                _join_handles.inner.push(tokio::spawn(fut));
            }
        }

        // bpf_map_type_BPF_MAP_TYPE_RINGBUF
        for m in module.maps.iter_mut().filter(|m| m.kind == 27) {
            let name = m.name.clone();
            let map = RingBufMap::bind(m).unwrap();
            let stream = RingBufMessageStream::new(name.clone(), map);
            let mut s = sender.clone();
            let fut = stream.for_each(move |events| {
                s.start_send((name.clone(), events)).unwrap();
                future::ready(())
            });
            _join_handles.inner.push(tokio::spawn(fut));
        }

        Ok(Loaded {
            module,
            events: receiver,
            _join_handles,
        })
    }

    /// Loads the BPF programs included in `file`.
    ///
    /// See `load()`.
    pub fn load_file<P: AsRef<Path>>(file: P) -> Result<Loaded, LoaderError> {
        Loader::load(&fs::read(file).map_err(LoaderError::FileError)?)
    }
}

/// The `Loaded` object returned by `load()`.
pub struct Loaded {
    pub module: Module,
    /// The stream of events emitted by the BPF programs.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::path::Path;
    /// use futures::stream::StreamExt;
    /// use redbpf::load::Loader;
    /// # async {
    /// let mut loader = Loader::load_file(&Path::new("probe.elf")).unwrap();
    /// while let Some((map_name, events)) = loader.events.next().await {
    ///     for event in events {
    ///         // ...
    ///     }
    /// }
    /// # };
    /// ```
    pub events: mpsc::UnboundedReceiver<(String, <PerfMessageStream as Stream>::Item)>,
    _join_handles: JoinHandles,
}

impl Loaded {
    pub fn map(&self, name: &str) -> Option<&Map> {
        self.module.map(name)
    }

    pub fn map_mut(&mut self, name: &str) -> Option<&mut Map> {
        self.module.map_mut(name)
    }

    pub fn program(&self, name: &str) -> Option<&Program> {
        self.module.program(name)
    }

    pub fn program_mut(&mut self, name: &str) -> Option<&mut Program> {
        self.module.program_mut(name)
    }

    pub fn kprobes_mut(&mut self) -> impl Iterator<Item = &mut KProbe> {
        self.module.kprobes_mut()
    }

    pub fn kprobe_mut(&mut self, name: &str) -> Option<&mut KProbe> {
        self.module.kprobe_mut(name)
    }

    pub fn uprobes_mut(&mut self) -> impl Iterator<Item = &mut UProbe> {
        self.module.uprobes_mut()
    }

    pub fn uprobe_mut(&mut self, name: &str) -> Option<&mut UProbe> {
        self.module.uprobe_mut(name)
    }

    pub fn xdps_mut(&mut self) -> impl Iterator<Item = &mut XDP> {
        self.module.xdps_mut()
    }

    pub fn xdp_mut(&mut self, name: &str) -> Option<&mut XDP> {
        self.module.xdp_mut(name)
    }

    pub fn socket_filters_mut(&mut self) -> impl Iterator<Item = &mut SocketFilter> {
        self.module.socket_filters_mut()
    }

    pub fn socket_filter_mut(&mut self, name: &str) -> Option<&mut SocketFilter> {
        self.module.socket_filter_mut(name)
    }

    pub fn stream_parsers(&self) -> impl Iterator<Item = &StreamParser> {
        self.module.stream_parsers()
    }

    pub fn stream_parsers_mut(&mut self) -> impl Iterator<Item = &mut StreamParser> {
        self.module.stream_parsers_mut()
    }

    pub fn stream_parser_mut(&mut self, name: &str) -> Option<&mut StreamParser> {
        self.module.stream_parser_mut(name)
    }

    pub fn stream_verdicts(&self) -> impl Iterator<Item = &StreamVerdict> {
        self.module.stream_verdicts()
    }

    pub fn stream_verdicts_mut(&mut self) -> impl Iterator<Item = &mut StreamVerdict> {
        self.module.stream_verdicts_mut()
    }

    pub fn stream_verdict_mut(&mut self, name: &str) -> Option<&mut StreamVerdict> {
        self.module.stream_verdict_mut(name)
    }

    pub fn sk_lookups_mut(&mut self) -> impl Iterator<Item = &mut SkLookup> {
        self.module.sk_lookups_mut()
    }

    pub fn sk_lookup_mut(&mut self, name: &str) -> Option<&mut SkLookup> {
        self.module.sk_lookup_mut(name)
    }

    pub fn task_iters(&self) -> impl Iterator<Item = &TaskIter> {
        self.module.task_iters()
    }

    pub fn bpf_iters_mut(&mut self) -> impl Iterator<Item = &mut TaskIter> {
        self.module.task_iters_mut()
    }

    pub fn task_iter_mut(&mut self, name: &str) -> Option<&mut TaskIter> {
        self.module.task_iter_mut(name)
    }

    pub fn tracepoints_mut(&mut self) -> impl Iterator<Item = &mut TracePoint> {
        self.module.trace_points_mut()
    }

    pub fn tracepoint_mut(&mut self, name: &str) -> Option<&mut TracePoint> {
        self.module.trace_point_mut(name)
    }
}
