pub mod prelude;
use crate::socket::SocketError;

pub enum StreamParserAction {
    MessageLength(u32),
    MoreDataWanted,
    SendToUserspace,
}

pub type StreamParserResult = Result<StreamParserAction, SocketError>;
