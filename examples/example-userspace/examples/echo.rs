// echo data from tcp client using SOCKMAP
// # cargo run --example echo <port>

use std::env;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::process;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task;
use tracing::{debug, error, Level};
use tracing_subscriber::FmtSubscriber;

use probes::echo::IdxMapKey;
use redbpf::load::Loader;
use redbpf::{HashMap, SockMap};
#[derive(Debug)]
enum Command {
    Delete { key: IdxMapKey },
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    if unsafe { libc::geteuid() != 0 } {
        error!("You must be root to use eBPF!");
        process::exit(1);
    }

    let args: Vec<String> = env::args().collect();
    let port: u16 = args
        .get(1)
        .expect("port number should be specified")
        .parse()
        .expect("invalid port number");

    let loaded = Loader::load(include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/echo/echo.elf"
    )))
    .expect("error loading BPF program");
    let mut echo_sockmap =
        SockMap::new(loaded.map("echo_sockmap").expect("sockmap not found")).unwrap();
    loaded
        .stream_parsers()
        .next()
        .unwrap()
        .attach_sockmap(&echo_sockmap)
        .expect("Attaching sockmap failed");
    loaded
        .stream_verdicts()
        .next()
        .unwrap()
        .attach_sockmap(&echo_sockmap)
        .expect("Attaching sockmap failed");
    let idx_map =
        HashMap::<IdxMapKey, u32>::new(loaded.map("idx_map").expect("idx map not found")).unwrap();

    let mut counter: u32 = 0;
    let listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port)))
        .await
        .unwrap();
    let (tx, mut rx) = mpsc::channel(128);
    loop {
        tokio::select! {
            Ok((mut tcp_stream, client_addr)) = listener.accept() => {
                let fd = tcp_stream.as_raw_fd();
                let ipaddr = if let IpAddr::V4(ipaddr) = client_addr.ip() {
                    ipaddr
                } else {
                    error!("not an IPv4 address: {:?}", client_addr);
                    continue;
                };
                debug!("new client: {:?}, fd: {}", client_addr, fd);
                let key = IdxMapKey {
                    // use big endian because __sk_buff.remote_ip4 and
                    // __sk_buff.remote_port are big endian
                    addr: u32::from(ipaddr).to_be(),
                    port: (client_addr.port() as u32).to_be(),
                };
                idx_map.set(key, counter);
                // NOTE: Sockmap should be set before any data is read from the
                // socket descriptor or before some epoll event of the socket
                // descriptor occurs. Otherwise setting sockmap results in
                // EOPNOTSUPP error. So setting sockmap here asap.
                let _ = echo_sockmap
                    .set(counter, fd)
                    .map_err(|_| error!("SockMap::set failed. Perhaps the socket is already half closed"));
                counter += 1;

                // NOTE: Call setsockopt to trigger stream parser manually. If
                // this workaround is not involved, the packets received before
                // setting sockmap won't be handled until the next packet
                // arrives.
                let optval: u32 = 1;
                if unsafe {libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVLOWAT, &optval as *const _ as *const _, 4)} < 0 {
                    error!("setsockopt error: {:?}", std::io::Error::last_os_error());
                }

                // Keep tcp_stream not to be dropped. And notify connection
                // close to delete itself from the sockmap
                let tx = tx.clone();
                task::spawn(async move {
                    let mut buf = Vec::new();
                    // Even though it awaits for something to read, it only
                    // ends after the connection is half closed by the peer.
                    // Normally the read call reads nothing but some data can
                    // be read if setting sockmap had failed. So write all
                    // buffer to echo it.
                    tcp_stream.read_to_end(&mut buf).await.unwrap();
                    if !buf.is_empty() {
                        debug!("some data is read by userspace: {:x?}", &buf);
                    }
                    tcp_stream.write_all(&buf).await.unwrap();
                    debug!("delete client: {:?} fd: {}", client_addr, fd);
                    tx.send(Command::Delete { key }).await.unwrap();
                });
            }
            Some(cmd) = rx.recv() => {
                match cmd {
                    Command::Delete { key } => {
                        if let Some(idx) = idx_map.get(key) {
                            // This can be failed when the fd had been closed
                            let _ = echo_sockmap.delete(idx);
                            idx_map.delete(key);
                        }
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                break;
            }
        }
    }
}
