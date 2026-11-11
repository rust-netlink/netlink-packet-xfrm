// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, ErrorContext, Parseable,
};

use crate::{nlas::VecXfrmAttrs, UserAcquire, UserAcquireBuffer, XfrmAttrs};
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct AcquireMessage {
    pub acquire: UserAcquire,
    pub nlas: Vec<XfrmAttrs>,
}

impl Emitable for AcquireMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.acquire.emit(out)?;
        self.nlas.as_slice().emit(out)?;
        Ok(())
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
