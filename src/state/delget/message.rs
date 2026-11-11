// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, ErrorContext, Parseable,
};

use crate::{nlas::VecXfrmAttrs, UserSaId, UserSaIdBuffer, XfrmAttrs};
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct DelGetMessage {
    pub user_sa_id: UserSaId,
    pub nlas: Vec<XfrmAttrs>,
}

impl Emitable for DelGetMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.user_sa_id.emit(out)?;
        self.nlas.as_slice().emit(out)?;
        Ok(())
    }
}

impl Parseable<[u8]> for DelGetMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let user_sa_id =
            UserSaId::parse(&buf[..size_of::<UserSaIdBuffer>()])
                .context("failed to parse state delget message user sa id")?;
        Ok(Self {
            user_sa_id,
            nlas: VecXfrmAttrs::parse(&buf[size_of::<UserSaIdBuffer>()..])
                .context("failed to parse state delget message NLAs")?
                .0,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct GetDumpMessage {
    pub nlas: Vec<XfrmAttrs>,
}

impl Emitable for GetDumpMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.nlas.as_slice().emit(out)?;
        Ok(())
    }
}

impl Parseable<[u8]> for GetDumpMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            nlas: VecXfrmAttrs::parse(buf)
                .context("failed to parse state delget message NLAs")?
                .0,
        })
    }
}
