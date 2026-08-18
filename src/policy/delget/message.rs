// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable, ErrorContext, Parseable};

use crate::{nlas::VecXfrmAttrs, UserPolicyId, UserPolicyIdBuffer, XfrmAttrs};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct DelGetMessage {
    pub user_policy_id: UserPolicyId,
    pub nlas: Vec<XfrmAttrs>,
}

impl Emitable for DelGetMessage {
    fn buffer_len(&self) -> usize {
        self.user_policy_id.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.user_policy_id.emit(buffer);
        self.nlas
            .as_slice()
            .emit(&mut buffer[self.user_policy_id.buffer_len()..]);
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
