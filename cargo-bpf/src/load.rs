// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::ebpf_io::PerfMessageStream;
use crate::CommandError;

use bpf_sys;
use futures::channel::mpsc;
use futures::prelude::*;
use futures::stream::StreamExt;
use hexdump::hexdump;
use redbpf::cpus;
use redbpf::ProgramKind::*;
use redbpf::{LoadError, Module, PerfMap, XdpFlags};
use std::ffi::CString;
use std::fs;
use std::io;
use std::path::PathBuf;
use tokio;
use tokio::runtime::Runtime;
use tokio::signal;

#[derive(Debug)]
enum LoaderError {
    FileError(io::Error),
    ParseError(LoadError),
    LoadError(String, LoadError),
    XdpError(String, LoadError),
    KprobeError(String, LoadError),
}

/// High level API to load bpf programs.
struct Loader {
    xdp: XdpConfig
}

impl Loader {
    /// Creates a new loader.
    pub fn new() -> Self {
        Loader {
            xdp: XdpConfig::default()
        }
    }

    /// Sets the network interface and flags for XDP programs.
    pub fn xdp(&mut self, interface: Option<String>, flags: XdpFlags) -> &mut Self {
        self.xdp = XdpConfig {
            interface,
            flags
        };
        self
    }

    /// Loads the programs included in `data`.
    ///
    /// This will parse `data` with `Module::parse()` and load all the programs
    /// present in the module.
    pub async fn load(&self, data: &[u8]) -> Result<Loaded, LoaderError> {
        let mut module = Module::parse(&data).map_err(|e| LoaderError::ParseError(e))?;
        for prog in module.programs.iter_mut() {
            prog.load(module.version, module.license.clone())
                .map_err(|e| LoaderError::LoadError(prog.name.clone(), e))?;
        }

        if let Some(interface) = &self.xdp.interface {
            for prog in module.programs.iter_mut().filter(|p| p.kind == XDP) {
                println!("Loaded: {}, {:?}", prog.name, prog.kind);
                prog.attach_xdp(&interface, self.xdp.flags)
                    .map_err(|e| LoaderError::XdpError(prog.name.clone(), e))?;
            }
        }

        for prog in module
            .programs
            .iter_mut()
            .filter(|p| p.kind == Kprobe || p.kind == Kretprobe)
        {
            prog.attach_probe()
                .map_err(|e| LoaderError::KprobeError(prog.name.clone(), e))?;
            println!("Loaded: {}, {:?}", prog.name, prog.kind);
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
            xdp: self.xdp.clone(),
            events: receiver
        })
    }

    /// Loads the BPF programs included in `file`.
    ///
    /// See `load()`.
    pub async fn load_file(&self, file: &PathBuf) -> Result<Loaded, LoaderError> {
        self.load(&fs::read(file).map_err(|e| LoaderError::FileError(e))?)
            .await
    }
}

/// The `Loaded` object returned by `load()`.
struct Loaded {
    xdp: XdpConfig,
    /// The stream of events emitted by the BPF programs.
    ///
    /// # Example
    ///
    /// ```
    /// while let Some((map_name, events)) = loader.events.next().await {
    ///     for event in events {
    ///         println!("-- Event: {} --", map_name);
    ///             hexdump(&event);
    ///         }
    ///     }
    /// }
    /// ```
    pub events: mpsc::UnboundedReceiver<(String, <PerfMessageStream as Stream>::Item)>,
}

impl Drop for Loaded {
    fn drop(&mut self) {
        if let Some(interface) = &self.xdp.interface {
            let ciface = CString::new(interface.as_bytes()).unwrap();
            let _ = unsafe { bpf_sys::bpf_attach_xdp(ciface.as_ptr(), -1, 0) };
        }
    }
}

#[derive(Debug, Clone)]
struct XdpConfig {
    interface: Option<String>,
    flags: XdpFlags
}

impl Default for XdpConfig {
    fn default() -> XdpConfig {
        XdpConfig {
            interface: None,
            flags: XdpFlags::default()
        }
    }
}

pub fn load(program: &PathBuf, interface: Option<&str>) -> Result<(), CommandError> {
    let mut runtime = Runtime::new().unwrap();
    let _ = runtime.block_on(async {
        let mut loader = Loader::new()
            .xdp(interface.map(String::from), XdpFlags::default())
            .load_file(&program)
            .await
            .expect("error loading file");
        tokio::spawn(async move {
            while let Some((name, events)) = loader.events.next().await {
                for event in events {
                    println!("-- Event: {} --", name);
                    hexdump(&event);
                }
            }
        });

        signal::ctrl_c().await
    });

    println!("exiting");

    Ok(())
}
