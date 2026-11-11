// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, ErrorContext, Parseable,
};

use crate::{nlas::VecXfrmAttrs, UserSpiInfo, UserSpiInfoBuffer, XfrmAttrs};
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct AllocSpiMessage {
    pub spi_info: UserSpiInfo,
    pub nlas: Vec<XfrmAttrs>,
}

impl Emitable for AllocSpiMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.spi_info.emit(out)?;
        self.nlas.as_slice().emit(out)?;
        Ok(())
    }
}

impl Parseable<[u8]> for AllocSpiMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let spi_info =
            UserSpiInfo::parse(&buf[..size_of::<UserSpiInfoBuffer>()])
                .context("failed to parse state allocspi message spi info")?;
        Ok(Self {
            spi_info,
            nlas: VecXfrmAttrs::parse(&buf[size_of::<UserSpiInfoBuffer>()..])
                .context("failed to parse state delget message NLAs")?
                .0,
        })
    }
}
