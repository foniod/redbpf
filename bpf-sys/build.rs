fn main() {
    println!("cargo:rustc-link-lib=static=bpf");
    println!("cargo:rustc-link-search=./bpf-sys/lib/");
    println!("cargo:rustc-link-search=./lib/");
}
