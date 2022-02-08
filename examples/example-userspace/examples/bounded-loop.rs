/// This example shows disassemble of bounded_loop probe file.
///
/// If `cargo bpf build` is executed, the resulting BPF bytecode is relatively
/// small. And you can see that the disassembled code is short and you can find
/// bounded loop code in there. Since the Linux kernel v5.3, the bounded loop
/// is permitted by the BPF verifier. So the default behavior of `cargo bpf
/// build` is to preserve the bounded loop if the loop iteration count is big
/// enough.
///
/// If `cargo bpf build --force-loop-unroll` is executed, the resulting BPF
/// bytecode does not contain loop code. Instead, it contains fully unrolled
/// loop. So you can see the disassembled code is pretty long.
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("Run llvm-objdump --disassemble");
    println!("========");
    let _ = Command::new("llvm-objdump")
        .arg("--disassemble")
        .arg(probe_path().into_os_string().into_string().unwrap())
        .status();
}

fn probe_path() -> PathBuf {
    let path = concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/bounded_loop/bounded_loop.elf"
    );
    PathBuf::from(path)
}
