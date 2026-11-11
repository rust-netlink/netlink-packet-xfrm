// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, ErrorContext, Parseable,
};

use crate::{nlas::VecXfrmAttrs, XfrmAttrs};
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct FlushMessage {
    pub nlas: Vec<XfrmAttrs>,
}

impl Emitable for FlushMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.nlas.as_slice().emit(out)?;
        Ok(())
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
