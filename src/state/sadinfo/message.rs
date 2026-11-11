// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{
    append_u32, parse_u32, DecodeError, Emitable, EncodeError, ErrorContext,
    Parseable,
};

use crate::state::sadinfo::{nlas::VecSadInfoAttrs, SadInfoAttrs};
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct NewSadInfoMessage {
    pub flags: u32,
    pub nlas: Vec<SadInfoAttrs>,
}

impl Emitable for NewSadInfoMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_u32(out, self.flags);
        self.nlas.as_slice().emit(out)?;
        Ok(())
    }
}

impl Parseable<[u8]> for NewSadInfoMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let flags = parse_u32(&buf[..size_of::<u32>()])
            .context("failed to parse state new SAD info message flags")?;
        Ok(Self {
            flags,
            nlas: VecSadInfoAttrs::parse(&buf[size_of::<u32>()..])
                .context("failed to parse state new SAD info message NLAs")?
                .0,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct GetSadInfoMessage {
    pub flags: u32,
}

impl Emitable for GetSadInfoMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_u32(out, self.flags);
        Ok(())
    }
}

impl Parseable<[u8]> for GetSadInfoMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            flags: parse_u32(&buf[..size_of::<u32>()])
                .context("failed to parse state get SAD info message flags")?,
        })
    }
}
