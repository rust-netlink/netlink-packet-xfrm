// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable, ErrorContext, Parseable};

use crate::{AsyncEventId, AsyncEventIdBuffer};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct GetAsyncEventMessage {
    pub id: AsyncEventId,
}

impl Emitable for GetAsyncEventMessage {
    fn buffer_len(&self) -> usize {
        self.id.buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.id.emit(buffer);
    }
}

impl Parseable<[u8]> for GetAsyncEventMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let id = AsyncEventId::parse(&buf[..size_of::<AsyncEventIdBuffer>()])
            .context("failed to parse monitor get async event id")?;
        Ok(Self { id })
    }
}
