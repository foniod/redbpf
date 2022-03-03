// for details about the p0f, please refer to https://github.com/p0f/p0f

use futures::stream::StreamExt;
use probes::p0f::TcpSignature;
use redbpf::{load::Loader, xdp};

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(env!("OUT_DIR"), "/target/bpf/programs/p0f/p0f.elf"))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::result::Result<(), String> {
    let xdp_mode = xdp::Flags::DrvMode;
    let interfaces: Vec<String> = vec!["eth0".to_string()];

    let mut loaded = Loader::load(probe_code()).map_err(|err| format!("{:?}", err))?;

    for interface in &interfaces {
        println!(
            "Attach p0f on interface: {} with mode {:?}",
            interface, xdp_mode
        );
        for prog in loaded.xdps_mut() {
            prog.attach_xdp(interface, xdp_mode)
                .map_err(|err| format!("{:?}", err))?;
        }
    }

    let _ = tokio::spawn(async move {
        while let Some((name, events)) = loaded.events.next().await {
            for event in events {
                match name.as_str() {
                    "tcp_signatures" => {
                        let tcp_sig = unsafe {
                            std::ptr::read_unaligned(event.as_ptr() as *const TcpSignature)
                        };
                        println!("tcp_signature = {:?}", tcp_sig);
                    }

                    "log_events" => {
                        let log_value = unsafe { std::ptr::read(event.as_ptr() as *const usize) };
                        println!("read log_value = {}", log_value);
                    }

                    _ => panic!("unexpected event"),
                }
            }
        }
    })
    .await;

    Ok(())
}
