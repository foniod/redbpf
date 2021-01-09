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

use crate::{Program, cpus};
use crate::load::map_io::PerfMessageStream;
use crate::{Error, KProbe, Map, Module, PerfMap, SocketFilter, UProbe, TracePoint, XDP};

#[derive(Debug)]
pub enum LoaderError {
    FileError(io::Error),
    ParseError(Error),
    LoadError(String, Error),
}

/// High level API to load bpf programs.
pub struct Loader {}

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
                tokio::spawn(fut);
            }
        }

        Ok(Loaded {
            module,
            events: receiver,
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
}

impl Loaded {
    pub fn map(&self, name: &str) -> Option<&Map> {
        self.module.maps.iter().find(|m| m.name == name)
    }

    pub fn map_mut(&mut self, name: &str) -> Option<&mut Map> {
        self.module.maps.iter_mut().find(|m| m.name == name)
    }

    pub fn program(&self, name: &str) -> Option<&Program> {
        self.module.program(name)
    }

    pub fn kprobes_mut(&mut self) -> impl Iterator<Item = &mut KProbe> {
        self.module.kprobes_mut()
    }

    pub fn uprobes_mut(&mut self) -> impl Iterator<Item = &mut UProbe> {
        self.module.uprobes_mut()
    }

    pub fn xdps_mut(&mut self) -> impl Iterator<Item = &mut XDP> {
        self.module.xdps_mut()
    }

    pub fn socket_filters_mut(&mut self) -> impl Iterator<Item = &mut SocketFilter> {
        self.module.socket_filters_mut()
    }

    pub fn tracepoints_mut(&mut self) -> impl Iterator<Item = &mut TracePoint> {
        self.module.tracepoints_mut()
    }
}
