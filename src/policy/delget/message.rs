// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, ErrorContext, Parseable,
};

use crate::{nlas::VecXfrmAttrs, UserPolicyId, UserPolicyIdBuffer, XfrmAttrs};
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct DelGetMessage {
    pub user_policy_id: UserPolicyId,
    pub nlas: Vec<XfrmAttrs>,
}

impl Emitable for DelGetMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.user_policy_id.emit(out)?;
        self.nlas.as_slice().emit(out)?;
        Ok(())
    }
}

impl Parseable<[u8]> for DelGetMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let user_policy_id =
            UserPolicyId::parse(&buf[..size_of::<UserPolicyIdBuffer>()])
                .context(
                    "failed to parse policy delget message user policy id",
                )?;
        Ok(Self {
            user_policy_id,
            nlas: VecXfrmAttrs::parse(&buf[size_of::<UserPolicyIdBuffer>()..])
                .context("failed to parse policy delget message NLAs")?
                .0,
        })
    }
}
