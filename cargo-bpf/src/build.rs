// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use libc;
use std::convert::From;
use std::env;
use std::fmt::{self, Display};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::slice;
use std::str;
use toml_edit;

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

pub fn build_program(
    cargo: &Path,
    package: &Path,
    out_dir: &Path,
    program: &str,
) -> Result<(), Error> {
    let llc_args = ["-march=bpf", "-filetype=obj", "-o"];
    let elf_target = out_dir.join(format!("{}.elf", program));

    let current_dir = env::current_dir().unwrap();
    let out_dir = current_dir.join(out_dir);
    let _ = fs::remove_dir_all(&out_dir); // ignore error
    fs::create_dir_all(&out_dir)?;

    if !Command::new(cargo)
        .current_dir(package)
        .args("rustc --release --features=probes".split(" "))
        .arg("--bin")
        .arg(program)
        .arg("--")
        .args(
            "--emit=llvm-bc -C panic=abort -C lto -C link-arg=-nostartfiles -C opt-level=3"
                .split(" "),
        )
        .args(format!("-o {}/{}", out_dir.to_str().unwrap(), program).split(" "))
        .status()?
        .success()
    {
        return Err(Error::Compile(program.to_string(), None));
    }

    let mut bc_files: Vec<PathBuf> = fs::read_dir(out_dir)?
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
        return Err(Error::MissingBitcode(program.to_string()));
    }

    let bc_file = bc_files.drain(..).next().unwrap();
    let processed_bc_file = bc_file.with_extension("bc.proc");
    let opt_bc_file = bc_file.with_extension("bc.opt");

    process_ir(&bc_file, &processed_bc_file).map_err(|msg| {
        Error::Compile(program.into(), Some(format!("couldn't process IR file: {}", msg)))
    })?;
    println!("IR processed before: {:?}, after: {:?}", bc_file, processed_bc_file);

    let opt = get_opt_executable()?;
    if !Command::new(opt)
        .args(&["-march=bpf", "-O3", "-o", opt_bc_file.to_str().unwrap()])
        .arg(processed_bc_file.to_str().unwrap())
        .status()?
        .success()
    {
        return Err(Error::Link(program.to_string()));
    }
    println!("IR optimised: {:?}", opt_bc_file);

    let llc = get_llc_executable()?;
    if !Command::new(llc)
        .args(&llc_args)
        .arg(&elf_target)
        .arg(opt_bc_file.to_str().unwrap())
        .status()?
        .success()
    {
        return Err(Error::Link(program.to_string()));
    }

    Ok(())
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

fn get_llc_executable() -> Result<String, Error> {
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

pub fn build(
    cargo: &Path,
    package: &Path,
    out_dir: &Path,
    programs: Vec<String>,
) -> Result<(), Error> {
    use toml_edit::{Document, Item};

    let path = package.join("Cargo.toml");
    if !path.exists() {
        return Err(Error::MissingManifest(path.clone()));
    }

    let targets = if !programs.is_empty() {
        programs
    } else {
        let data = fs::read_to_string(path).unwrap();
        let config = data.parse::<Document>().unwrap();
        let targets: Vec<String> = match &config["bin"] {
            Item::ArrayOfTables(array) => array
                .iter()
                .map(|t| t["name"].as_str().unwrap().into())
                .collect(),
            _ => return Err(Error::NoPrograms),
        };
        targets
    };

    for program in targets {
        build_program(cargo, package, &out_dir.join(program.clone()), &program)?;
    }

    Ok(())
}

pub fn cmd_build(programs: Vec<String>) -> Result<(), CommandError> {
    let current_dir = std::env::current_dir().unwrap();
    // FIXME: parse --target-dir etc
    let out_dir = PathBuf::from("target/release/bpf-programs");
    let ret = build(Path::new("cargo"), &current_dir, &out_dir, programs)?;
    Ok(ret)
}
