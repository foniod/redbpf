// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use std::path::{Path, PathBuf};

use crate::build::Error;
use crate::build::{get_llc_executable, kernel_headers, BUILD_FLAGS};
use std::process::Command;

fn compile_target(out_dir: &Path, source: &Path) -> Option<PathBuf> {
    let basename = source.file_stem()?;
    let target_name = format!("{}.obj", basename.to_str()?);
    Some(out_dir.join(Path::new(&target_name)))
}

fn link_target(out_dir: &Path, source: &Path) -> Option<PathBuf> {
    let basename = source.file_stem()?;
    let target_name = format!("{}.elf", basename.to_str()?);
    Some(out_dir.join(Path::new(&target_name)))
}

pub fn build_c(out_dir: &Path, source: &Path) -> Result<PathBuf, Error> {
    let llc_args = ["-march=bpf", "-filetype=obj", "-o"];
    let cc_target = compile_target(out_dir, source).unwrap();
    let elf_target = link_target(out_dir, source).unwrap();

    let kernel_headers = kernel_headers().expect("couldn't find kernel headers");
    let mut flags: Vec<String> = kernel_headers
        .iter()
        .map(|dir| format!("-I{}", dir))
        .collect();
    flags.extend(BUILD_FLAGS.iter().map(|f| f.to_string()));
    flags.push("-O2".to_string());
    flags.push("-c".to_string());
    flags.push("-emit-llvm".to_string());

    if !Command::new("clang")
        .args(flags)
        .arg("-o")
        .arg(&cc_target)
        .arg(source)
        .status()?
        .success()
    {
        return Err(Error::Compile(source.to_string_lossy().into_owned(), None));
    }

    let llc = get_llc_executable()?;
    if !Command::new(llc)
        .args(&llc_args)
        .arg(&elf_target)
        .arg(&cc_target)
        .status()?
        .success()
    {
        return Err(Error::Link(source.to_string_lossy().into_owned()));
    }

    Ok(elf_target)
}
