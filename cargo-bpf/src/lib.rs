// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
/*!
This supports API that is behind `cargo-bpf` command.

It would be better using `cargo-bpf` instead of this backend API.  Please see
[RedBPF Tutorial](https://github.com/foniod/redbpf/blob/main/TUTORIAL.md) to
learn how to use `cargo-bpf`.

*/
mod build_constants;

#[cfg(feature = "bindings")]
mod accessors;
#[cfg(feature = "bindings")]
pub mod bindgen;

#[cfg(feature = "build")]
mod build;
#[cfg(feature = "build-c")]
mod build_c;
#[cfg(feature = "build")]
mod llvm;

#[cfg(feature = "command-line")]
mod load;
#[cfg(feature = "command-line")]
mod new;
#[cfg(feature = "command-line")]
mod new_program;

pub struct CommandError(pub String);

impl std::convert::From<std::io::Error> for CommandError {
    fn from(e: std::io::Error) -> CommandError {
        CommandError(format!("{}", e))
    }
}

#[cfg(feature = "build")]
pub use build::*;
#[cfg(feature = "build-c")]
pub use build_c::*;
#[cfg(feature = "command-line")]
pub use load::load;
#[cfg(feature = "command-line")]
pub use new::new;
#[cfg(feature = "command-line")]
pub use new_program::new_program;
