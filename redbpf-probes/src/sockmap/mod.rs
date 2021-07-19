// Copyright 2021 Junyeong Jeong <rhdxmr@gmail.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
/*!
Sockmap for socket redirection with stream parser and verdict
*/
pub mod prelude;
use crate::socket::SocketError;

pub enum StreamParserAction {
    MessageLength(u32),
    MoreDataWanted,
    SendToUserspace,
}

pub type StreamParserResult = Result<StreamParserAction, SocketError>;
