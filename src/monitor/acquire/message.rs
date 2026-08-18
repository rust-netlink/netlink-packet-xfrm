// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable, ErrorContext, Parseable};

use crate::{nlas::VecXfrmAttrs, UserAcquire, UserAcquireBuffer, XfrmAttrs};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct AcquireMessage {
    pub acquire: UserAcquire,
    pub nlas: Vec<XfrmAttrs>,
}

impl Emitable for AcquireMessage {
    fn buffer_len(&self) -> usize {
        self.acquire.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.acquire.emit(buffer);
        self.nlas
            .as_slice()
            .emit(&mut buffer[self.acquire.buffer_len()..]);
    }
}

impl Parseable<[u8]> for AcquireMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let acquire =
            UserAcquire::parse(&buf[..size_of::<UserAcquireBuffer>()])
                .context("failed to parse monitor acquire message info")?;
        Ok(Self {
            acquire,
            nlas: VecXfrmAttrs::parse(&buf[size_of::<UserAcquireBuffer>()..])
                .context("failed to parse monitor acquire message NLAs")?
                .0,
        })
    }
}
