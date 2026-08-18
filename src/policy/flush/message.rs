// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, Emitable, ErrorContext, Parseable};

use crate::{nlas::VecXfrmAttrs, XfrmAttrs};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct FlushMessage {
    pub nlas: Vec<XfrmAttrs>,
}

impl Emitable for FlushMessage {
    fn buffer_len(&self) -> usize {
        self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.nlas.as_slice().emit(&mut buffer[0..]);
    }
}

impl Parseable<[u8]> for FlushMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            nlas: VecXfrmAttrs::parse(buf)
                .context("failed to parse policy flush message NLAs")?
                .0,
        })
    }
}
