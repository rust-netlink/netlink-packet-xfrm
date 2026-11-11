// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, ErrorContext, Parseable,
};

use crate::{
    nlas::VecXfrmAttrs, UserPolicyExpire, UserPolicyExpireBuffer, XfrmAttrs,
};
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct PolicyExpireMessage {
    pub expire: UserPolicyExpire,
    pub nlas: Vec<XfrmAttrs>,
}

impl Emitable for PolicyExpireMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.expire.emit(out)?;
        self.nlas.as_slice().emit(out)?;
        Ok(())
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
