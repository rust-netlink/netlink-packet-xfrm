// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, ErrorContext, Parseable,
};

use crate::{UserPolicyDefault, UserPolicyDefaultBuffer};
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct DefaultMessage {
    pub user_policy: UserPolicyDefault,
}

impl Emitable for DefaultMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.user_policy.emit(out)?;
        Ok(())
    }
}

impl Parseable<[u8]> for DefaultMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let user_policy = UserPolicyDefault::parse(
            &buf[..size_of::<UserPolicyDefaultBuffer>()],
        )
        .context("failed to parse policy default message user policy")?;
        Ok(Self { user_policy })
    }
}
