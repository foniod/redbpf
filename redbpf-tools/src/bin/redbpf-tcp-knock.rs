// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use futures::stream::StreamExt;
use getopts::Options;
use redbpf::{load::Loader, xdp, HashMap};
use std::env;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process;
use std::ptr;
use tokio;
use tokio::runtime::Runtime;
use tokio::signal;

use probes::knock::{Connection, KnockAttempt, PortSequence, MAX_SEQ_LEN};

fn main() {
    let opts = match parse_opts() {
        Some(o) => o,
        None => process::exit(1),
    };

    let mut runtime = Runtime::new().unwrap();
    let _ = runtime.block_on(async {
        let interface = Some(opts.interface);
        let mut loader = Loader::new()
            .xdp(interface.map(String::from), xdp::Flags::default())
            .load(probe_code())
            .await
            .expect("error loading probe");

        // configure the knock sequence
        let mut sequence = PortSequence {
            ports: [0; MAX_SEQ_LEN],
            len: opts.knock.len(),
            target: opts.port as u64,
        };
        sequence.ports[..opts.knock.len()].copy_from_slice(&opts.knock);

        // store the sequence in the `sequence` BPF map so the XDP program can retrieve it
        let seq_map = loader
            .module
            .maps
            .iter()
            .find(|m| m.name == "sequence")
            .unwrap();
        let seq_map = HashMap::<u8, PortSequence>::new(seq_map).unwrap();
        seq_map.set(0u8, sequence);

        tokio::spawn(async move {
            // process perf events sent by the XDP program
            while let Some((name, events)) = loader.events.next().await {
                for event in events {
                    match name.as_str() {
                        "knock_attempts" => {
                            let knock = unsafe { ptr::read(event.as_ptr() as *const KnockAttempt) };
                            let seq = &knock.sequence;
                            println!(
                                "Received knock from {} sequence {}",
                                Ipv4Addr::from(knock.source_ip),
                                seq.ports[..seq.len]
                                    .iter()
                                    .enumerate()
                                    .map(|(i, port)| {
                                        if i == seq.len - 1 {
                                            format!("*{}", port)
                                        } else {
                                            format!("{}", port)
                                        }
                                    })
                                    .collect::<Vec<String>>()
                                    .join(" ")
                            )
                        }
                        "connections" => {
                            let conn = unsafe { ptr::read(event.as_ptr() as *const Connection) };
                            println!(
                                "{} access from {:?}",
                                if conn.allowed == 1 {
                                    "Allowed"
                                } else {
                                    "Blocked"
                                },
                                Ipv4Addr::from(conn.source_ip)
                            );
                        }
                        _ => panic!("unexpected event"),
                    }
                }
            }
        });

        signal::ctrl_c().await
    });
}

struct Opts {
    interface: String,
    knock: Vec<u16>,
    port: u16,
}

fn parse_opts() -> Option<Opts> {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optmulti(
        "k",
        "knock",
        &format!(
            "TCP port on which peers have to knock on, can be used up to {} times",
            MAX_SEQ_LEN
        ),
        "KNOCK",
    );
    opts.reqopt(
        "p",
        "port",
        "the port to open on completion of the given knock sequence",
        "PORT",
    );
    opts.reqopt(
        "i",
        "interface",
        "the network interface to listen on",
        "INTERFACE",
    );
    opts.optflag("h", "help", "print this help menu");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            eprintln!("{}\n", f);
            print_usage(&program, opts);
            return None;
        }
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return None;
    }
    let interface = matches.opt_str("i");
    let knock = matches.opt_strs("k");
    let port = matches.opt_str("p");
    if interface.is_none() || knock.is_empty() || port.is_none() {
        print_usage(&program, opts);
        return None;
    };

    if knock.len() > MAX_SEQ_LEN {
        eprintln!(
            "Knock sequence too long: {} maximum is {}",
            knock.len(),
            MAX_SEQ_LEN
        );
        return None;
    }

    let knock = knock.iter().map(|p| p.parse::<u16>().unwrap()).collect();
    let port = port.unwrap().parse::<u16>().unwrap();

    Some(Opts {
        interface: interface.unwrap(),
        knock,
        port,
    })
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/probes/target/release/bpf-programs/knock/knock.elf"
    ))
}