// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable, ErrorContext, Parseable};

use crate::{nlas::VecXfrmAttrs, UserSaInfo, UserSaInfoBuffer, XfrmAttrs};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct ModifyMessage {
    pub user_sa_info: UserSaInfo,
    pub nlas: Vec<XfrmAttrs>,
}

impl Emitable for ModifyMessage {
    fn buffer_len(&self) -> usize {
        self.user_sa_info.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.user_sa_info.emit(buffer);
        self.nlas
            .as_slice()
            .emit(&mut buffer[self.user_sa_info.buffer_len()..]);
    }
}

impl Parseable<[u8]> for ModifyMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let user_sa_info =
            UserSaInfo::parse(&buf[..size_of::<UserSaInfoBuffer>()])
                .context("failed to parse state modify message user sa info")?;
        Ok(Self {
            user_sa_info,
            nlas: VecXfrmAttrs::parse(&buf[size_of::<UserSaInfoBuffer>()..])
                .context("failed to parse state modify message NLAs")?
                .0,
        })
    }
}
