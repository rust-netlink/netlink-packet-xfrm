// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{
    emit_u32, parse_u32, DecodeError, Emitable, ErrorContext, Parseable,
};

use crate::state::sadinfo::{nlas::VecSadInfoAttrs, SadInfoAttrs};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct NewSadInfoMessage {
    pub flags: u32,
    pub nlas: Vec<SadInfoAttrs>,
}

impl Emitable for NewSadInfoMessage {
    fn buffer_len(&self) -> usize {
        size_of::<u32>() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        emit_u32(&mut buffer[..size_of::<u32>()], self.flags).unwrap();
        self.nlas.as_slice().emit(&mut buffer[size_of::<u32>()..]);
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
    fn buffer_len(&self) -> usize {
        size_of::<u32>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        emit_u32(&mut buffer[..size_of::<u32>()], self.flags).unwrap();
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
