use regex::Regex;
use std::env;
use std::process::Command;

fn print_cargo_bpf_llvm_version() {
    let config_path_re = Regex::new(r"DEP_LLVM_(\d+)_CONFIG_PATH").unwrap();
    let config_paths = env::vars()
        .filter_map(|(key, value)| {
            if config_path_re.is_match(&key) {
                Some(value)
            } else {
                None
            }
        })
        .collect::<Vec<String>>();
    if config_paths.is_empty() {
        panic!("llvm-config not found");
    } else if config_paths.len() > 1 {
        panic!("Multiple LLVMs are specified. Choose one LLVM version");
    }

    let llvm_config = &config_paths[0];
    let version_str = Command::new(llvm_config)
        .arg("--version")
        .output()
        .map(|output| {
            String::from_utf8(output.stdout).expect("Output from llvm-config was not valid UTF-8")
        })
        .unwrap();

    // LLVM isn't really semver and uses version suffixes to build
    // version strings like '3.8.0svn', so limit what we try to parse
    // to only the numeric bits.
    let semver_re = Regex::new(r"^(?P<major>\d+)\.(?P<minor>\d+)(?:\.(?P<patch>\d+))??").unwrap();
    let captures = semver_re
        .captures(&version_str)
        .expect("Could not determine LLVM version from llvm-config.");

    // some systems don't have a patch number but Version wants it so we just append .0 if it isn't
    // there
    let norm_version_str = match captures.name("patch") {
        None => format!("{}.0", &captures[0]),
        Some(_) => captures[0].to_string(),
    };

    // Support compiling cargo-bpf in gentoo.
    if let Some(major) = captures.name("major") {
        println!("cargo:rustc-link-lib=LLVM-{}", major.as_str());
    }

    println!(
        "cargo:rustc-env=CARGO_BPF_LLVM_VERSION={}",
        norm_version_str
    );
}

fn main() {
    cfg_if::cfg_if! {
        if #[cfg(all(feature = "llvm-sys-130", not(feature = "docsrs-llvm")))] {
            print_cargo_bpf_llvm_version();
        } else {
            println!("cargo:rustc-env=CARGO_BPF_LLVM_VERSION=0.0.0");
        }
    }
}
