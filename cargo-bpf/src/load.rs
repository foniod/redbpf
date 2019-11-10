use crate::ebpf_io::PerfMessageStream;
use crate::CommandError;

use futures::future::{self, Future};
use futures::stream::Stream;
use hexdump::hexdump;
use redbpf::cpus;
use redbpf::ProgramKind::*;
use redbpf::{Module, PerfMap};
use std::fs;
use std::path::PathBuf;
use tokio;
use std::ffi::CString;
use bpf_sys;

pub fn load(program: &PathBuf, interface: Option<&str>) -> Result<(), CommandError> {
    let data = fs::read(program)?;
    let mut module = Module::parse(&data).expect("failed to parse ELF data");
    for prog in module.programs.iter_mut() {
        prog.load(module.version, module.license.clone())
            .expect("failed to load program");
    }

    if let Some(interface) = interface {
        for prog in module.programs.iter_mut().filter(|p| p.kind == XDP) {
            println!("Loaded: {}, {:?}", prog.name, prog.kind);
            prog.attach_xdp(interface).unwrap();
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
    tokio::run(futures::lazy(move || {
        let online_cpus = cpus::get_online().unwrap();
        for m in module.maps.iter_mut().filter(|m| m.kind == 4) {
            for cpuid in online_cpus.iter() {
                let map = PerfMap::bind(m, -1, *cpuid, 16, -1, 0).unwrap();
                let stream = PerfMessageStream::new(m.name.clone(), map);
                    let fut = stream
                    .for_each(|events| {
                        for event in events {
                            println!("-- Event --");
                            hexdump(&event);
                        }
                        future::ok(())
                    })
                    .map_err(|_| ());
                tokio::spawn(fut);
            }
        }

        future::ok(())
    }));

    if let Some(interface) = interface {
        let ciface = CString::new(interface).unwrap();
        let res = unsafe { bpf_sys::bpf_attach_xdp(ciface.as_ptr(), -1, 0) };
    }

    Ok(())
}
