// This program can be executed by
// # cargo run --example tcp-lifetime [interface]
// It reports (saddr, sport, daddr, dport, lifetime) of which established and
// closed while the program is running.

// Example of execution
// $ sudo -E cargo run --example tcp-lifetime wlp0s20f3
// Attaching socket to interface wlp0s20f3
// Hit Ctrl-C to quit
//          src           →           dst          |  duration
// 192.168. 0 . 9 :36940  →   8 . 8 . 8 . 8 :53    |     1303 ms
//  8 . 8 . 8 . 8 :53     →  192.168. 0 . 9 :36940 |     1304 ms

use futures::stream::StreamExt;
use std::env;

use std::process;
use std::ptr;
use tokio::signal::ctrl_c;

use redbpf::load::Loader;
use redbpf::HashMap;

use probes::tcp_lifetime::{SocketAddr, TCPLifetime};

#[tokio::main]
async fn main() {
    if unsafe { libc::getuid() != 0 } {
        eprintln!("You must be root to use eBPF!");
        process::exit(1);
    }

    let args: Vec<String> = env::args().collect();
    let iface = match args.get(1) {
        Some(val) => val,
        None => "lo",
    };
    println!("Attaching socket to interface {}", iface);
    let mut raw_fds = Vec::new();
    let mut loaded = Loader::load(probe_code()).expect("error loading BPF program");
    for sf in loaded.socket_filters_mut() {
        if let Ok(sock_raw_fd) = sf.attach_socket_filter(iface) {
            raw_fds.push(sock_raw_fd);
        }
    }

    let event_fut = async {
        println!("{:^21}  →  {:^21} | {:^11}", "src", "dst", "duration");
        while let Some((name, events)) = loaded.events.next().await {
            match name.as_str() {
                "tcp_lifetime" => {
                    for event in events {
                        let tcp_lifetime =
                            unsafe { ptr::read(event.as_ptr() as *const TCPLifetime) };
                        println!(
                            "{:21}  →  {:21} | {:>8} ms",
                            tcp_lifetime.src.to_string(),
                            tcp_lifetime.dst.to_string(),
                            tcp_lifetime.duration / 1000 / 1000
                        );
                    }
                }
                _ => {
                    eprintln!("unknown event = {}", name);
                }
            }
        }
    };
    let ctrlc_fut = async {
        ctrl_c().await.unwrap();
    };
    println!("Hit Ctrl-C to quit");
    tokio::select! {
        _ = event_fut => {

        }
        _ = ctrlc_fut => {
            println!("");
        }
    }
    let estab: HashMap<(SocketAddr, SocketAddr), u64> =
        HashMap::new(loaded.map("established").unwrap()).unwrap();
    for ((src, dst), _) in estab.iter() {
        println!(
            "{:<21}  →  {:<21} | still established",
            src.to_string(),
            dst.to_string()
        );
    }
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/tcp-lifetime/tcp-lifetime.elf"
    ))
}
