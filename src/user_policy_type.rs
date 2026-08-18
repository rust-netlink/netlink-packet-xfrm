// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserPolicyType {
    pub ptype: u8,
    pub reserved1: u16,
    pub reserved2: u8,
}

pub const XFRM_USER_POLICY_TYPE_LEN: usize = 6;

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
pub struct UserPolicyTypeBuffer {
    ptype: u8,
    padding1: [u8; 1],
    reserved1: u16,
    reserved2: u8,
    padding2: [u8; 1],
}

impl UserPolicyType {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            UserPolicyTypeBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<UserPolicyTypeBuffer>(),
                )
            })?;
        Ok(Self {
            ptype: raw.ptype,
            reserved1: raw.reserved1,
            reserved2: raw.reserved2,
        })
    }
}

impl From<&UserPolicyType> for UserPolicyTypeBuffer {
    fn from(value: &UserPolicyType) -> Self {
        Self {
            ptype: value.ptype,
            padding1: [0; 1],
            reserved1: value.reserved1,
            reserved2: value.reserved2,
            padding2: [0; 1],
        }
    }
}

impl Emitable for UserPolicyType {
    fn buffer_len(&self) -> usize {
        size_of::<UserPolicyTypeBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = UserPolicyTypeBuffer::from(self);
        buffer[..size_of::<UserPolicyTypeBuffer>()]
            .copy_from_slice(raw.as_bytes());
    }
}
