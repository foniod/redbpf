// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

mod bindgen;
mod build;
mod llvm;
mod load;
mod new;
mod new_program;

pub struct CommandError(pub String);

impl std::convert::From<std::io::Error> for CommandError {
    fn from(e: std::io::Error) -> CommandError {
        CommandError(format!("{}", e))
    }
}

pub use self::bindgen::cmd_bindgen as bindgen;
pub use build::{build, cmd_build};
pub use load::load;
pub use new::new;
pub use new_program::new_program;
