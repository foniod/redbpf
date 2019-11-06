mod bindgen;
mod build;
mod ebpf_io;
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
