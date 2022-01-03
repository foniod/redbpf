/// This example shows how to steer connections to sockets using BPF socket lookup hook.
///
/// It's a Rust implementation of the following presentation:
/// https://ebpf.io/summit-2020-slides/eBPF_Summit_2020-Lightning-Jakub_Sitnicki-Steering_connections_to_sockets_with_BPF_socke_lookup_hook.pdf
///
/// Example usage:
///    cargo build --no-default-features --features llvm13,kernel5_9 --example socket-steering
///    sudo -Es $(which cargo) run --no-default-features --features llvm13,kernel5_9 --example socket-steering 7 77 777
///
use redbpf::{HashMap, SockMap};
use redbpf::load::Loader;
use std::{env, net::SocketAddr, os::unix::io::AsRawFd, process};
use tokio::net::TcpListener;
use tokio::task::{self, LocalSet};
use tokio::{io, signal};
use tracing::{debug, error, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    if unsafe { libc::getuid() != 0 } {
        error!("You must be root to use eBPF!");
        process::exit(1);
    }

    let ports = env::args()
        .skip(1)
        .map(|s| {
            s.parse::<u16>()
                .expect(format!("Unable to convert {} to u16", s).as_str())
        })
        .collect::<Vec<u16>>();
    if ports.is_empty() {
        error!("Specify port numbers to steer");
        process::exit(1);
    }

    debug!("Load steer_to_socket BPF program code");
    let mut loaded = Loader::load(probe_code()).unwrap();

    debug!("Attaching steer_to_socket BPF program");
    loaded
        .sk_lookup_mut("steer_to_socket")
        .unwrap()
        .attach_sk_lookup("/proc/self/ns/net")
        .unwrap();

    debug!("Listen on 0.0.0.0:8007");
    let listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], 8007)))
        .await
        .unwrap();
    let listener_fd = listener.as_raw_fd();

    debug!("Pass the listener fd {} to the BPF program", listener_fd);
    let destination_socket_map = loaded.map("destination_socket").unwrap();
    let mut destination_socket = SockMap::new(destination_socket_map).unwrap();
    destination_socket.set(0, listener_fd).unwrap();

    debug!("Pass the steered ports to the BPF program");
    let steered_ports_map = loaded.map("steered_ports").unwrap();
    let steered_ports = HashMap::<u16, u8>::new(steered_ports_map).unwrap();
    for port in ports {
        steered_ports.set(port, 1);
    }

    debug!("Echoing received data");
    let local = LocalSet::new();
    local.spawn_local(async move {
        loop {
            let (mut tcp_stream, client_addr) = listener.accept().await.unwrap();
            debug!("New client: {}", client_addr);
            task::spawn_local(async move {
                let (mut reader, mut writer) = tcp_stream.split();
                io::copy(&mut reader, &mut writer).await.unwrap();
            });
        }
    });

    debug!("Hit Ctrl-C to quit");
    let _ = local.run_until(signal::ctrl_c()).await;
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/socket_steering/socket_steering.elf"
    ))
}
