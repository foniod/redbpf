// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[derive(Debug)]
pub enum Error {
    StringConversion,
    BPF,
    Map,
    Section(String),
    Parse(::goblin::error::Error),
    KernelRelease(String),
    IO(::std::io::Error),
    Uname,
    Reloc,
    LibraryNotFound(String),
    SymbolNotFound(String),
    ProgramAlreadyLoaded,
    ProgramNotLoaded,
    ProgramAlreadyLinked,
    ElfError,
    BTF(String),
}

pub type Result<T> = ::std::result::Result<T, Error>;

impl From<::goblin::error::Error> for Error {
    fn from(e: ::goblin::error::Error) -> Error {
        Error::Parse(e)
    }
}

impl From<::std::ffi::NulError> for Error {
    fn from(_e: ::std::ffi::NulError) -> Error {
        Error::StringConversion
    }
}

impl From<::std::io::Error> for Error {
    fn from(e: ::std::io::Error) -> Error {
        Error::IO(e)
    }
}
