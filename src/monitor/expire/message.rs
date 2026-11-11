// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, ErrorContext, Parseable,
};

use crate::{UserExpire, UserExpireBuffer};
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct ExpireMessage {
    pub expire: UserExpire,
}

impl Emitable for ExpireMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.expire.emit(out)?;
        Ok(())
    }
}

impl Parseable<[u8]> for ExpireMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let expire = UserExpire::parse(&buf[..size_of::<UserExpireBuffer>()])
            .context("failed to parse monitor expire message info")?;
        Ok(Self { expire })
    }
}
