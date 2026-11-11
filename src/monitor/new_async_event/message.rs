// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, ErrorContext, Parseable,
};

use crate::{nlas::VecXfrmAttrs, AsyncEventId, AsyncEventIdBuffer, XfrmAttrs};
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct NewAsyncEventMessage {
    pub id: AsyncEventId,
    pub nlas: Vec<XfrmAttrs>,
}

impl Emitable for NewAsyncEventMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.id.emit(out)?;
        self.nlas.as_slice().emit(out)?;
        Ok(())
    }
}

impl Parseable<[u8]> for NewAsyncEventMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let id = AsyncEventId::parse(&buf[..size_of::<AsyncEventIdBuffer>()])
            .context("failed to parse monitor new async event id")?;
        Ok(Self {
            id,
            nlas: VecXfrmAttrs::parse(&buf[size_of::<AsyncEventIdBuffer>()..])
                .context(
                    "failed to parse monitor new async event message NLAs",
                )?
                .0,
        })
    }
}
