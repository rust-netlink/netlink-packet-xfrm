// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, ErrorContext, Parseable,
};

use crate::{
    nlas::VecXfrmAttrs, UserPolicyInfo, UserPolicyInfoBuffer, XfrmAttrs,
};
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct ModifyMessage {
    pub user_policy_info: UserPolicyInfo,
    pub nlas: Vec<XfrmAttrs>,
}

impl Emitable for ModifyMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.user_policy_info.emit(out)?;
        self.nlas.as_slice().emit(out)?;
        Ok(())
    }
}

impl Parseable<[u8]> for ModifyMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let user_policy_info =
            UserPolicyInfo::parse(&buf[..size_of::<UserPolicyInfoBuffer>()])
                .context(
                    "failed to parse policy modify message user policy info",
                )?;
        Ok(Self {
            user_policy_info,
            nlas: VecXfrmAttrs::parse(
                &buf[size_of::<UserPolicyInfoBuffer>()..],
            )
            .context("failed to parse policy modify message NLAs")?
            .0,
        })
    }
}
