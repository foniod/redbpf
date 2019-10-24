use std::convert::From;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use toml_edit;

use crate::commands::CommandError;

pub enum Error {
    MissingManifest(PathBuf),
    NoPrograms,
    Compile(String),
    MissingBitcode(String),
    Link(String),
    IOError(io::Error)
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error::IOError(error)
    }
}

impl From<Error> for CommandError {
    fn from(error: Error) -> CommandError {
        use Error::*;
        let msg = match error {
            MissingManifest(p) =>  format!("Could not find `Cargo.toml' in {:?}", p),
            NoPrograms => String::from("the package doesn't contain any eBPF programs"),
            Compile(p) => format!("failed to compile the `{}' program", p),
            MissingBitcode(p) => format!("failed to generate bitcode for the `{}' program", p),
            Link(p) => format!("failed to generate bitcode for the `{}' program", p),
            IOError(e) => return e.into()
        };

        CommandError(msg)
    }
}

pub fn build_program(cargo: &str, out_dir: &Path, program: &str) -> Result<(), Error> {
    let llc_args = ["-march=bpf", "-filetype=obj", "-o"];
    let elf_target = out_dir.join(format!("{}.elf", program));

    fs::create_dir_all(out_dir.clone())?;

    if !Command::new(cargo)
        .args("rustc --release --features=probes".split(" "))
        .arg("--bin")
        .arg(program)
        .arg("--")
        .args("--emit=llvm-bc -C panic=abort -C link-arg=-nostartfiles -C opt-level=3".split(" "))
        .args(format!("-o {}/{}", out_dir.to_str().unwrap(), program).split(" "))
        .status()?
        .success()
    {
        return Err(Error::Compile(program.to_string()));
    }

    let bc_files: Vec<PathBuf> = fs::read_dir(out_dir)?
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

    let bc_file = &bc_files[0];

    if !Command::new("llc-9")
        .args(&llc_args)
        .arg(&elf_target)
        .arg(bc_file.to_str().unwrap())
        .status()?
        .success()
    {
        return Err(Error::Link(program.to_string()));
    }

    Ok(())
}

pub fn build(cargo: &str, package: &PathBuf, out_dir: &PathBuf, programs: Vec<String>) -> Result<(), Error> {
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
            Item::ArrayOfTables(array) => array.iter().map(|t| t["name"].as_str().unwrap().into()).collect(),
            _ => return Err(Error::NoPrograms)
        };
        targets
    };

    for program in targets {
        build_program(cargo, &out_dir.join(program.clone()), &program)?;
    }

    Ok(())
}

pub(crate) fn cmd_build(programs: Vec<String>) -> Result<(), CommandError> {
    let current_dir = std::env::current_dir().unwrap();
    // FIXME: parse --target-dir etc
    let out_dir = PathBuf::from("target/release/bpf-programs");
    let ret = build("cargo", &current_dir, &out_dir, programs)?;
    Ok(ret)
}