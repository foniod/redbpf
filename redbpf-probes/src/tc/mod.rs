use crate::socket::SocketError;

/// Possible actions in tc programs
pub enum TcAction {
    /// Terminate the packet processing pipeline and allows the packet to proceed
    Ok,
    /// Terminate the packet processing pipeline and drops the packet
    Shot,
    /// Use the default action configured from `tc`
    Unspec,
    /// Iterate to the next action, if available
    Pipe,
    /// Terminate the packet processing pipeline and
    /// start classification from the beginning
    Reclassify,
}

/// Result type for tc action programs.
pub type TcActionResult = Result<TcAction, SocketError>;

pub mod prelude {
    pub use super::*;

    pub use crate::bindings::*;
    pub use crate::helpers::*;
    pub use crate::maps::*;
    pub use crate::socket::*;
    pub use redbpf_macros::{program, tc_action};
}
