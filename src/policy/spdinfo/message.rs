// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{
    append_u32, parse_u32, DecodeError, Emitable, EncodeError, ErrorContext,
    Parseable,
};

use crate::policy::spdinfo::{nlas::VecSpdInfoAttrs, SpdInfoAttrs};
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct NewSpdInfoMessage {
    pub flags: u32,
    pub nlas: Vec<SpdInfoAttrs>,
}

impl Emitable for NewSpdInfoMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_u32(out, self.flags);
        self.nlas.as_slice().emit(out)?;
        Ok(())
    }
}

impl Parseable<[u8]> for NewSpdInfoMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let flags = parse_u32(&buf[..size_of::<u32>()])
            .context("failed to parse policy new SPD info message flags")?;
        Ok(Self {
            flags,
            nlas: VecSpdInfoAttrs::parse(&buf[size_of::<u32>()..])
                .context("failed to parse policy new SPD info message NLAs")?
                .0,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct GetSpdInfoMessage {
    pub flags: u32,
}

impl Emitable for GetSpdInfoMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_u32(out, self.flags);
        Ok(())
    }
}

impl Parseable<[u8]> for GetSpdInfoMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            flags: parse_u32(&buf[..size_of::<u32>()])
                .context("failed to parse policy get SPD info message flags")?,
        })
    }
}
