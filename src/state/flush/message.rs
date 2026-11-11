// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, Emitable, EncodeError, Parseable};
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct FlushMessage {
    pub protocol: u8,
}

impl Emitable for FlushMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        out.push(self.protocol);
        Ok(())
    }
}

impl Parseable<[u8]> for FlushMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.is_empty() {
            return Err(DecodeError::buffer_too_small(buf.len(), 1));
        }
        Ok(Self { protocol: buf[0] })
    }
}
