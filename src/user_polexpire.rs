// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable, ErrorContext};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{UserPolicyInfo, UserPolicyInfoBuffer, XFRM_USER_POLICY_INFO_LEN};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserPolicyExpire {
    pub pol: UserPolicyInfo,
    pub hard: u8,
}

pub const XFRM_USER_POLICY_EXPIRE_LEN: usize = 176;

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub struct UserPolicyExpireBuffer {
    pol: [u8; XFRM_USER_POLICY_INFO_LEN],
    hard: u8,
    padding: [u8; 7],
}

impl UserPolicyExpire {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) = UserPolicyExpireBuffer::ref_from_prefix(payload)
            .map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<UserPolicyExpireBuffer>(),
                )
            })?;
        let pol = UserPolicyInfo::parse(&raw.pol[..])
            .context("failed to parse user policy info")?;
        Ok(Self {
            pol,
            hard: raw.hard,
        })
    }
}

impl From<&UserPolicyExpire> for UserPolicyExpireBuffer {
    fn from(value: &UserPolicyExpire) -> Self {
        let mut pol = [0u8; XFRM_USER_POLICY_INFO_LEN];
        pol.copy_from_slice(UserPolicyInfoBuffer::from(&value.pol).as_bytes());
        Self {
            pol,
            hard: value.hard,
            padding: [0; 7],
        }
    }
}

impl Emitable for UserPolicyExpire {
    fn buffer_len(&self) -> usize {
        size_of::<UserPolicyExpireBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = UserPolicyExpireBuffer::from(self);
        buffer[..size_of::<UserPolicyExpireBuffer>()]
            .copy_from_slice(raw.as_bytes());
    }
}
