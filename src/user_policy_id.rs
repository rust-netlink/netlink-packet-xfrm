// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable, ErrorContext};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{Selector, SelectorBuffer, XFRM_SELECTOR_LEN};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserPolicyId {
    pub selector: Selector,
    pub index: u32,
    pub direction: u8,
}

pub const XFRM_USER_POLICY_ID_LEN: usize = 64;

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
pub struct UserPolicyIdBuffer {
    selector: [u8; XFRM_SELECTOR_LEN],
    index: u32,
    direction: u8,
    padding: [u8; 3],
}

impl UserPolicyId {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            UserPolicyIdBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<UserPolicyIdBuffer>(),
                )
            })?;
        let selector = Selector::parse(&raw.selector[..])
            .context("failed to parse selector")?;
        Ok(Self {
            selector,
            index: raw.index,
            direction: raw.direction,
        })
    }
}

impl From<&UserPolicyId> for UserPolicyIdBuffer {
    fn from(value: &UserPolicyId) -> Self {
        let mut selector = [0u8; XFRM_SELECTOR_LEN];
        selector
            .copy_from_slice(SelectorBuffer::from(&value.selector).as_bytes());
        Self {
            selector,
            index: value.index,
            direction: value.direction,
            padding: [0; 3],
        }
    }
}

impl Emitable for UserPolicyId {
    fn buffer_len(&self) -> usize {
        size_of::<UserPolicyIdBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = UserPolicyIdBuffer::from(self);
        buffer[..size_of::<UserPolicyIdBuffer>()]
            .copy_from_slice(raw.as_bytes());
    }
}
