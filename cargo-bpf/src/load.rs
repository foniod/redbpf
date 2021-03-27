// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::CommandError;

use futures::{future, stream::StreamExt};
use hexdump::hexdump;
use redbpf::xdp;
use redbpf::{load::Loader, Program::*};
use std::path::PathBuf;
use tokio::runtime;
use tokio::signal;

pub fn load(
    program: &PathBuf,
    interface: Option<&str>,
    uprobe_path: Option<&str>,
    pid: Option<i32>,
) -> Result<(), CommandError> {
    let rt = runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        // Load all the programs and maps included in the program
        let mut loader = Loader::load_file(&program).expect("error loading file");

        // attach the programs
        for program in loader.module.programs.iter_mut() {
            let name = program.name().to_string();
            let ret = match program {
                XDP(prog) => {
                    let iface = match interface {
                        Some(i) => i,
                        None => {
                            return Err(CommandError(
                                "XDP program found, but no interface specified".to_string(),
                            ))
                        }
                    };
                    prog.attach_xdp(&iface, xdp::Flags::default())
                }
                KProbe(prog) | KRetProbe(prog) => prog.attach_kprobe(&name, 0),
                UProbe(prog) | URetProbe(prog) => {
                    let path = match uprobe_path {
                        Some(p) => p,
                        None => {
                            return Err(CommandError(
                                "uprobe program found, but no path specified".to_string(),
                            ))
                        }
                    };
                    prog.attach_uprobe(Some(&prog.name()), 0, path, pid)
                }
                _ => Ok(()),
            };
            if let Err(e) = ret {
                return Err(CommandError(format!(
                    "failed to attach program {}: {:?}",
                    name, e
                )));
            }
        }

        // dump all the generated events on stdout
        tokio::spawn(async move {
            while let Some((name, events)) = loader.events.next().await {
                for event in events {
                    println!("-- Event: {} --", name);
                    hexdump(&event);
                }
            }

            // If the program doesn't have any maps and therefore doesn't fire any events, we still
            // need to keep `loader` alive here so that BPF programs are not dropped. The future
            // below will never complete, meaning that the programs will keep running until Ctrl-C
            future::pending::<()>().await;
        });

        // quit on SIGINT
        let _ = signal::ctrl_c().await;
        println!("exiting");
        Ok(())
    })
}
