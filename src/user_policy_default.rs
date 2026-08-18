// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserPolicyDefault {
    pub input: u8,
    pub forward: u8,
    pub output: u8,
}

pub const XFRM_USER_POLICY_DEFAULT_LEN: usize = 3;

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
pub struct UserPolicyDefaultBuffer {
    input: u8,
    forward: u8,
    output: u8,
}

impl UserPolicyDefault {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) = UserPolicyDefaultBuffer::ref_from_prefix(payload)
            .map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<UserPolicyDefaultBuffer>(),
                )
            })?;
        Ok(Self {
            input: raw.input,
            forward: raw.forward,
            output: raw.output,
        })
    }
}

impl From<&UserPolicyDefault> for UserPolicyDefaultBuffer {
    fn from(value: &UserPolicyDefault) -> Self {
        Self {
            input: value.input,
            forward: value.forward,
            output: value.output,
        }
    }
}

impl Emitable for UserPolicyDefault {
    fn buffer_len(&self) -> usize {
        size_of::<UserPolicyDefaultBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = UserPolicyDefaultBuffer::from(self);
        buffer[..size_of::<UserPolicyDefaultBuffer>()]
            .copy_from_slice(raw.as_bytes());
    }
}
