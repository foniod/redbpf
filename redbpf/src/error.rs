// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[derive(Debug)]
pub enum LoadError {
    StringConversion,
    BPF,
    Map,
    Section(String),
    Parse(::goblin::error::Error),
    KernelRelease(String),
    IO(::std::io::Error),
    Uname,
    Reloc,
}

pub type Result<T> = ::std::result::Result<T, LoadError>;

impl From<::goblin::error::Error> for LoadError {
    fn from(e: ::goblin::error::Error) -> LoadError {
        LoadError::Parse(e)
    }
}

impl From<::std::ffi::NulError> for LoadError {
    fn from(_e: ::std::ffi::NulError) -> LoadError {
        LoadError::StringConversion
    }
}

impl From<::std::io::Error> for LoadError {
    fn from(e: ::std::io::Error) -> LoadError {
        LoadError::IO(e)
    }
}
