use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use toml_edit;

use crate::commands::CommandError;

pub fn build_program(cargo: &str, out_dir: &Path, program: &str) -> Result<(), CommandError> {
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
        return Err(CommandError(format!("failed to compile the `{}' program", program)));
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
        return Err(CommandError(format!("failed to generate bitcode for the `{}' program", program)));
    }

    let bc_file = &bc_files[0];

    if !Command::new("llc-9")
        .args(&llc_args)
        .arg(&elf_target)
        .arg(bc_file.to_str().unwrap())
        .status()?
        .success()
    {
        return Err(CommandError(format!("failed to link the `{}' program", program)));
    }

    Ok(())
}

pub fn build_programs(names: Vec<String>) -> Result<(), CommandError> {
    use toml_edit::{Document, Item};

    let current_dir = std::env::current_dir().unwrap();
    let path = Path::new("Cargo.toml");
    if !path.exists() {
        return Err(CommandError(format!(
            "Could not find `Cargo.toml' in {:?}",
            current_dir
        )));
    }

    let targets = if !names.is_empty() {
        names
    } else {
        let data = fs::read_to_string(path).unwrap();
        let config = data.parse::<Document>().unwrap();
        let targets: Vec<String> = match &config["bin"] {
            Item::ArrayOfTables(array) => array.iter().map(|t| t["name"].as_str().unwrap().into()).collect(),
            _ => return Err(CommandError("the package doesn't contain any eBPF programs".to_string()))
        };
        targets
    };

    // FIXME: parse --target-dir etc
    let out_dir = PathBuf::from("target/release/bpf-programs");
    for program in targets {
        build_program("cargo", &out_dir.join(program.clone()), &program)?;
    }

    Ok(())
}
