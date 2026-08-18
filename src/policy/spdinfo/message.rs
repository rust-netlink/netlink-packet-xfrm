// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{
    emit_u32, parse_u32, DecodeError, Emitable, ErrorContext, Parseable,
};

use crate::policy::spdinfo::{nlas::VecSpdInfoAttrs, SpdInfoAttrs};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct NewSpdInfoMessage {
    pub flags: u32,
    pub nlas: Vec<SpdInfoAttrs>,
}

impl Emitable for NewSpdInfoMessage {
    fn buffer_len(&self) -> usize {
        size_of::<u32>() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        emit_u32(&mut buffer[..size_of::<u32>()], self.flags).unwrap();
        self.nlas.as_slice().emit(&mut buffer[size_of::<u32>()..]);
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
    fn buffer_len(&self) -> usize {
        size_of::<u32>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        emit_u32(&mut buffer[..size_of::<u32>()], self.flags).unwrap();
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
