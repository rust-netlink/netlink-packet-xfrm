// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, ErrorContext, Parseable,
};

use crate::{UserMapping, UserMappingBuffer};
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct MappingMessage {
    pub map: UserMapping,
}

impl Emitable for MappingMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.map.emit(out)?;
        Ok(())
    }
}

impl Parseable<[u8]> for MappingMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let map = UserMapping::parse(&buf[..size_of::<UserMappingBuffer>()])
            .context("failed to parse monitor mapping message info")?;
        Ok(Self { map })
    }
}
