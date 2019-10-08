mod new;
mod new_program;
mod bindgen;
mod build_programs;

pub struct CommandError(pub String);

impl std::convert::From<std::io::Error> for CommandError {
    fn from(e: std::io::Error) -> CommandError {
        CommandError(format!("{}", e))
    }
}

pub use new::new;
pub use new_program::new_program;
pub use self::bindgen::cmd_bindgen as bindgen;
pub use build_programs::build_programs;