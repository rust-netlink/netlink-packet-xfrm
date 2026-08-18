// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable, ErrorContext};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{UserSaInfo, UserSaInfoBuffer, XFRM_USER_SA_INFO_LEN};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserExpire {
    pub state: UserSaInfo,
    pub hard: u8,
}

pub const XFRM_USER_EXPIRE_LEN: usize = 232;

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
pub struct UserExpireBuffer {
    state: [u8; XFRM_USER_SA_INFO_LEN],
    hard: u8,
    padding: [u8; 7],
}

impl UserExpire {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            UserExpireBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<UserExpireBuffer>(),
                )
            })?;
        let state = UserSaInfo::parse(&raw.state[..])
            .context("failed to parse user sa info")?;
        Ok(Self {
            state,
            hard: raw.hard,
        })
    }
}

impl From<&UserExpire> for UserExpireBuffer {
    fn from(value: &UserExpire) -> Self {
        let mut state = [0u8; XFRM_USER_SA_INFO_LEN];
        state.copy_from_slice(UserSaInfoBuffer::from(&value.state).as_bytes());
        Self {
            state,
            hard: value.hard,
            padding: [0; 7],
        }
    }
}

impl Emitable for UserExpire {
    fn buffer_len(&self) -> usize {
        size_of::<UserExpireBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = UserExpireBuffer::from(self);
        buffer[..size_of::<UserExpireBuffer>()].copy_from_slice(raw.as_bytes());
    }
}
