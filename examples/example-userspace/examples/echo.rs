// echo data from tcp client using SOCKMAP
// # cargo run --example echo <port>

use std::env;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::{AsRawFd, RawFd};
use std::process;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task;

use probes::echo::IdxMapKey;
use redbpf::load::Loader;
use redbpf::{HashMap, SockMap};
#[derive(Debug)]
enum Command {
    Set { fd: RawFd, key: IdxMapKey },
    Delete { key: IdxMapKey },
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if unsafe { libc::getuid() != 0 } {
        eprintln!("You must be root to use eBPF!");
        process::exit(1);
    }

    let args: Vec<String> = env::args().collect();
    let port: u16 = args
        .get(1)
        .expect("port number should be specified")
        .parse()
        .expect("invalid port number");

    let (tx, mut rx) = mpsc::channel(128);
    let local = task::LocalSet::new();
    local.spawn_local(async move {
        let listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port)))
            .await
            .unwrap();
        loop {
            let (mut tcp_stream, client_addr) = listener.accept().await.unwrap();
            let fd = tcp_stream.as_raw_fd();
            if let IpAddr::V4(ipaddr) = client_addr.ip() {
                println!("new client: {:?}, fd: {}", client_addr, fd);
                let key = IdxMapKey {
                    // use big endian because __sk_buff.remote_ip4 and
                    // __sk_buff.remote_port are big endian
                    addr: u32::to_be(u32::from(ipaddr)),
                    port: u32::to_be(client_addr.port().into()),
                };
                tx.send(Command::Set { fd, key }).await.unwrap();
                let tx = tx.clone();
                task::spawn_local(async move {
                    let mut buf = [0; 0];
                    // Even though it awaits for something to read, it only
                    // ends after the connection is hung up. Because all data
                    // is echo-ed by BPF program, the user level socket does
                    // not receive anything.
                    tcp_stream.read(&mut buf[..]).await.unwrap();
                    println!("delete client: {:?} fd: {}", client_addr, fd);
                    tx.send(Command::Delete { key }).await.unwrap();
                });
            } else {
                eprintln!("error: not an IPv4 address: {:?}", client_addr);
            }
        }
    });

    local.spawn_local(async move {
        let loaded = Loader::load(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/target/bpf/programs/echo/echo.elf"
        )))
        .expect("error loading BPF program");
        let mut echo_sockmap =
            SockMap::new(loaded.map("echo_sockmap").expect("sockmap not found")).unwrap();
        loaded
            .stream_parser()
            .next()
            .unwrap()
            .attach_sockmap(&echo_sockmap)
            .expect("Attaching sockmap failed");
        loaded
            .stream_verdict()
            .next()
            .unwrap()
            .attach_sockmap(&echo_sockmap)
            .expect("Attaching sockmap failed");
        let idx_map =
            HashMap::<IdxMapKey, u32>::new(loaded.map("idx_map").expect("idx map not found"))
                .unwrap();
        let mut counter: u32 = 0;
        while let Some(cmd) = rx.recv().await {
            match cmd {
                Command::Set { fd, key } => {
                    unsafe {
                        let addr: [u8; 4] = std::mem::transmute(key.addr);
                        let port: [u8; 4] = std::mem::transmute(key.port);
                        println!(
                            "ipv4: {:x} {:x} {:x} {:x} port: {:x} {:x} {:x} {:x}",
                            addr[0], addr[1], addr[2], addr[3], port[0], port[1], port[2], port[3]
                        );
                    }

                    idx_map.set(key, counter);
                    echo_sockmap.set(counter, fd).unwrap();
                    counter += 1;
                }
                Command::Delete { key } => {
                    if let Some(idx) = idx_map.get(key) {
                        idx_map.delete(key);
                        // This can be failed when the fd had been closed
                        let _ = echo_sockmap.delete(idx);
                    }
                }
            }
        }
    });

    let _ = local.run_until(tokio::signal::ctrl_c()).await;
}
