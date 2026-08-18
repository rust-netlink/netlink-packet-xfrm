// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable, ErrorContext, Parseable};

use crate::{UserMapping, UserMappingBuffer};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct MappingMessage {
    pub map: UserMapping,
}

impl Emitable for MappingMessage {
    fn buffer_len(&self) -> usize {
        self.map.buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.map.emit(buffer);
    }
}

impl Parseable<[u8]> for MappingMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let map = UserMapping::parse(&buf[..size_of::<UserMappingBuffer>()])
            .context("failed to parse monitor mapping message info")?;
        Ok(Self { map })
    }
}
