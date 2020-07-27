// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use bpf_sys::headers::prefix_kernel_headers;
use lazy_static::lazy_static;
use std::convert::From;
use std::env;
use std::fmt::{self, Display};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str;
use toml_edit::{Document, Item};

use crate::llvm::process_ir;
use crate::CommandError;

#[derive(Debug)]
pub enum Error {
    MissingManifest(PathBuf),
    NoPrograms,
    NoLLC,
    NoOPT,
    Compile(String, Option<String>),
    MissingBitcode(String),
    Link(String),
    IOError(io::Error),
}

#[cfg(target_arch = "x86_64")]
const KERNEL_HEADERS: [&str; 7] = [
    "arch/x86/include",
    "arch/x86/include/generated",
    "include",
    "include/generated",
    "arch/include/generated/uapi",
    "arch/x86/include/uapi",
    "include/uapi",
];

#[cfg(target_arch = "aarch64")]
const KERNEL_HEADERS: [&str; 8] = [
    "arch/arm64/include",
    "arch/arm64/include/generated",
    "include",
    "include/generated",
    "arch/include/generated/uapi",
    "arch/arm64/include/uapi",
    "arch/arm64/include/generated/uapi",
    "include/uapi",
];

lazy_static! {
    pub(crate) static ref BUILD_FLAGS: Vec<&'static str> = {
        let mut flags = vec![
            "-D__BPF_TRACING__",
            "-D__KERNEL__",
            "-Wall",
            "-Werror",
            "-Wunused",
            "-Wno-unused-value",
            "-Wno-pointer-sign",
            "-Wno-compare-distinct-pointer-types",
            "-Wno-unused-parameter",
            "-Wno-missing-field-initializers",
            "-Wno-initializer-overrides",
            "-Wno-unknown-pragmas",
            "-fno-stack-protector",
            "-Wno-unused-label",
            "-Wno-unused-variable",
            "-Wno-unused-function",
            "-Wno-address-of-packed-member",
            "-Wno-gnu-variable-sized-type-not-at-end",
        ];

        if cfg!(x86_64) {
            flags.push("-D__ASM_SYSREG_H");
        } else if cfg!(aarch64) {
            flags.push("-target");
            flags.push("aarch64");
        }

        flags
    };
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IOError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error::IOError(error)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            MissingManifest(p) => write!(f, "Could not find `Cargo.toml' in {:?}", p),
            NoPrograms => write!(f, "the package doesn't contain any eBPF programs"),
            Compile(p, Some(msg)) => write!(f, "failed to compile the `{}' program: {}", p, msg),
            Compile(p, None) => write!(f, "failed to compile the `{}' program", p),
            MissingBitcode(p) => write!(f, "failed to generate bitcode for the `{}' program", p),
            Link(p) => write!(f, "failed to generate bitcode for the `{}' program", p),
            NoOPT => write!(f, "no usable opt executable found, expecting version 9"),
            NoLLC => write!(f, "no usable llc executable found, expecting version 9"),
            IOError(e) => write!(f, "{}", e),
        }
    }
}

impl From<Error> for CommandError {
    fn from(error: Error) -> CommandError {
        CommandError(error.to_string())
    }
}

fn build_probe(cargo: &Path, package: &Path, target_dir: &Path, probe: &str) -> Result<(), Error> {
    let llc_args = ["-march=bpf", "-filetype=obj", "-o"];
    fs::create_dir_all(&target_dir)?;
    let target_dir = target_dir.canonicalize().unwrap().join("bpf");
    let artifacts_dir = target_dir.join("programs").join(probe);
    let _ = fs::remove_dir_all(&artifacts_dir);
    fs::create_dir_all(&artifacts_dir)?;

    let mut flags = String::new();
    if let Ok(rf) = std::env::var("RUSTFLAGS") {
        flags.push_str(&rf);
    }
    flags.push_str(" -C embed-bitcode=yes");

    if !Command::new(cargo)
        .current_dir(package)
        .env("RUSTFLAGS", flags)
        .args("rustc --release --features=probes".split(" "))
        .arg("--target-dir")
        .arg(target_dir.to_str().unwrap())
        .arg("--bin")
        .arg(probe)
        .arg("--")
        .args(
            "--emit=llvm-bc -C panic=abort -C lto -C link-arg=-nostartfiles -C opt-level=3"
                .split(" "),
        )
        .arg("-o")
        .arg(artifacts_dir.join(probe).to_str().unwrap())
        .status()?
        .success()
    {
        return Err(Error::Compile(probe.to_string(), None));
    }

    let mut bc_files: Vec<PathBuf> = fs::read_dir(artifacts_dir.clone())?
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .path()
                .extension()
                .map(|ext| ext == "bc")
                .unwrap_or(false)
        })
        .map(|e| e.as_ref().unwrap().path())
        .collect();
    if bc_files.len() != 1 {
        return Err(Error::MissingBitcode(probe.to_string()));
    }

    let bc_file = bc_files.drain(..).next().unwrap();
    let processed_bc_file = bc_file.with_extension("bc.proc");
    let opt_bc_file = bc_file.with_extension("bc.opt");

    process_ir(&bc_file, &processed_bc_file).map_err(|msg| {
        Error::Compile(
            probe.into(),
            Some(format!("couldn't process IR file: {}", msg)),
        )
    })?;
    println!(
        "IR processed before: {:?}, after: {:?}",
        bc_file, processed_bc_file
    );

    let opt = get_opt_executable()?;
    if !Command::new(opt)
        .args(&[
            "-march=bpf",
            "-O3",
            "--loop-unroll",
            &format!("--unroll-threshold={}", std::u32::MAX), // unroll at any cost
            "--unroll-max-upperbound=500", // the max loop iteration count to unroll
            // enable upperbound unrolling when the exact trip count can't be computed
            "--passes=always-inline,function(unroll<upperbound>)",
            "-o",
            opt_bc_file.to_str().unwrap(),
        ])
        .arg(processed_bc_file.to_str().unwrap())
        .status()?
        .success()
    {
        return Err(Error::Link(probe.to_string()));
    }
    println!("IR optimised: {:?}", opt_bc_file);

    let elf_target = artifacts_dir.join(format!("{}.elf", probe));
    let llc = get_llc_executable()?;
    if !Command::new(llc)
        .args(&llc_args)
        .arg(&elf_target)
        .arg(opt_bc_file.to_str().unwrap())
        .status()?
        .success()
    {
        return Err(Error::Link(probe.to_string()));
    }

    Ok(())
}

pub fn build(
    cargo: &Path,
    package: &Path,
    target_dir: &Path,
    mut probes: Vec<String>,
) -> Result<(), Error> {
    let path = package.join("Cargo.toml");
    if !path.exists() {
        return Err(Error::MissingManifest(path.clone()));
    }

    if probes.is_empty() {
        let doc = load_package(package)?;
        probes = probe_names(&doc)?
    };

    for probe in probes {
        build_probe(cargo, package, &target_dir, &probe)?;
    }

    Ok(())
}

pub fn cmd_build(programs: Vec<String>, target_dir: PathBuf) -> Result<(), CommandError> {
    let current_dir = std::env::current_dir().unwrap();
    let ret = build(Path::new("cargo"), &current_dir, &target_dir, programs)?;
    Ok(ret)
}

pub fn probe_files(package: &Path) -> Result<Vec<String>, Error> {
    let doc = load_package(package)?;
    let probes = probe_names(&doc)?;
    Ok(probes
        .iter()
        .map(|probe| {
            package
                .join("src")
                .join(probe)
                .join("main.rs")
                .to_string_lossy()
                .into()
        })
        .collect())
}

fn load_package(package: &Path) -> Result<Document, Error> {
    let path = package.join("Cargo.toml");
    if !path.exists() {
        return Err(Error::MissingManifest(path.clone()));
    }

    let data = fs::read_to_string(path).unwrap();
    Ok(data.parse::<Document>().unwrap())
}

fn probe_names(doc: &Document) -> Result<Vec<String>, Error> {
    match &doc["bin"] {
        Item::ArrayOfTables(array) => Ok(array
            .iter()
            .map(|t| t["name"].as_str().unwrap().into())
            .collect()),
        _ => return Err(Error::NoPrograms),
    }
}

fn get_opt_executable() -> Result<String, Error> {
    for llc in vec!["opt".into(), env::var("OPT").unwrap_or("opt-9".into())].drain(..) {
        if let Ok(out) = Command::new(&llc).arg("--version").output() {
            match String::from_utf8(out.stdout) {
                Ok(out) => {
                    if out.contains("LLVM version 9.") {
                        return Ok(llc);
                    }
                }
                Err(_) => continue,
            }
        }
    }

    return Err(Error::NoOPT);
}

pub(crate) fn get_llc_executable() -> Result<String, Error> {
    for llc in vec!["llc".into(), env::var("LLC").unwrap_or("llc-9".into())].drain(..) {
        if let Ok(out) = Command::new(&llc).arg("--version").output() {
            match String::from_utf8(out.stdout) {
                Ok(out) => {
                    if out.contains("LLVM version 9.") {
                        return Ok(llc);
                    }
                }
                Err(_) => continue,
            }
        }
    }

    return Err(Error::NoLLC);
}

pub(crate) fn kernel_headers() -> Result<Vec<String>, ()> {
    prefix_kernel_headers(&KERNEL_HEADERS).ok_or(())
}
