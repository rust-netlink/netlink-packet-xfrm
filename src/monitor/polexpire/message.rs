// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable, ErrorContext, Parseable};

use crate::{
    nlas::VecXfrmAttrs, UserPolicyExpire, UserPolicyExpireBuffer, XfrmAttrs,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct PolicyExpireMessage {
    pub expire: UserPolicyExpire,
    pub nlas: Vec<XfrmAttrs>,
}

impl Emitable for PolicyExpireMessage {
    fn buffer_len(&self) -> usize {
        self.expire.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.expire.emit(buffer);
        self.nlas
            .as_slice()
            .emit(&mut buffer[self.expire.buffer_len()..]);
    }
}

impl Parseable<[u8]> for PolicyExpireMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let expire = UserPolicyExpire::parse(
            &buf[..size_of::<UserPolicyExpireBuffer>()],
        )
        .context("failed to parse monitor policy expire message info")?;
        Ok(Self {
            expire,
            nlas: VecXfrmAttrs::parse(
                &buf[size_of::<UserPolicyExpireBuffer>()..],
            )
            .context("failed to parse monitor policy expire message NLAs")?
            .0,
        })
    }
}
