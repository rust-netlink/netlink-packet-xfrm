// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable, ErrorContext, Parseable};

use crate::{UserPolicyDefault, UserPolicyDefaultBuffer};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct DefaultMessage {
    pub user_policy: UserPolicyDefault,
}

impl Emitable for DefaultMessage {
    fn buffer_len(&self) -> usize {
        size_of::<UserPolicyDefaultBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.user_policy.emit(buffer);
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
