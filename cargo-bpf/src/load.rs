// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::ebpf_io::PerfMessageStream;
use crate::CommandError;

use bpf_sys;
use futures::prelude::*;
use futures::stream::{self, StreamExt};
use futures::channel::mpsc;
use hexdump::hexdump;
use redbpf::cpus;
use redbpf::ProgramKind::*;
use redbpf::{Module, PerfMap, XdpFlags};
use std::ffi::CString;
use std::fs;
use std::path::PathBuf;
use tokio;
use tokio::runtime::Runtime;
use tokio::signal;

pub fn load(program: &PathBuf, interface: Option<&str>) -> Result<(), CommandError> {
    let data = fs::read(program)?;
    let iface = interface.map(String::from);
    let mut runtime = Runtime::new().unwrap();
    runtime
        .block_on(async {
            let mut module = Module::parse(&data).expect("failed to parse ELF data");
            for prog in module.programs.iter_mut() {
                prog.load(module.version, module.license.clone())
                    .expect("failed to load program");
            }

            if let Some(interface) = iface {
                for prog in module.programs.iter_mut().filter(|p| p.kind == XDP) {
                    println!("Loaded: {}, {:?}", prog.name, prog.kind);
                    prog.attach_xdp(&interface, XdpFlags::default()).unwrap();
                }
            }

            for prog in module
                .programs
                .iter_mut()
                .filter(|p| p.kind == Kprobe || p.kind == Kretprobe)
            {
                prog.attach_probe()
                    .expect(&format!("Failed to attach kprobe {}", prog.name));
                println!("Loaded: {}, {:?}", prog.name, prog.kind);
            }
            let online_cpus = cpus::get_online().unwrap();
            let (sender, mut receiver) = mpsc::unbounded();
            for m in module.maps.iter_mut().filter(|m| m.kind == 4) {
                for cpuid in online_cpus.iter() {
                    let name = m.name.clone();
                    let map = PerfMap::bind(m, -1, *cpuid, 16, -1, 0).unwrap();
                    let stream = PerfMessageStream::new(name.clone(), map);
                    let mut s = sender.clone();
                    let fut = stream.for_each(move |events| {
                        s.start_send(Some((name.clone(), events))).unwrap();
                        future::ready(())
                    });
                    tokio::spawn(fut);
                }
            }
            let mut s = sender.clone();
            tokio::spawn(signal::ctrl_c().map(move |_| s.start_send(None)));

            while let Some(Some((name, events))) = receiver.next().await {
                for event in events {
                    println!("-- Event: {} --", name);
                    hexdump(&event);
                }
            }
        });

    println!("exiting");

    if let Some(interface) = interface {
        let ciface = CString::new(interface).unwrap();
        let _res = unsafe { bpf_sys::bpf_attach_xdp(ciface.as_ptr(), -1, 0) };
    }

    Ok(())
}
