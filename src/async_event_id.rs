// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable, ErrorContext};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    Address, AddressBuffer, UserSaId, UserSaIdBuffer, XFRM_ADDRESS_LEN,
    XFRM_USER_SA_ID_LEN,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct AsyncEventId {
    pub sa_id: UserSaId,
    pub saddr: Address,
    pub flags: u32,
    pub reqid: u32,
}

pub const XFRM_ASYNC_EVENT_ID_LEN: usize = 48;

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
pub struct AsyncEventIdBuffer {
    sa_id: [u8; XFRM_USER_SA_ID_LEN],
    saddr: [u8; XFRM_ADDRESS_LEN],
    flags: u32,
    reqid: u32,
}

impl AsyncEventId {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            AsyncEventIdBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<AsyncEventIdBuffer>(),
                )
            })?;
        let sa_id =
            UserSaId::parse(&raw.sa_id[..]).context("failed to parse sa_id")?;
        let saddr =
            Address::parse(&raw.saddr[..]).context("failed to parse saddr")?;
        Ok(Self {
            sa_id,
            saddr,
            flags: raw.flags,
            reqid: raw.reqid,
        })
    }
}

impl From<&AsyncEventId> for AsyncEventIdBuffer {
    fn from(value: &AsyncEventId) -> Self {
        let mut sa_id = [0u8; XFRM_USER_SA_ID_LEN];
        sa_id.copy_from_slice(UserSaIdBuffer::from(&value.sa_id).as_bytes());
        let mut saddr = [0u8; XFRM_ADDRESS_LEN];
        saddr.copy_from_slice(AddressBuffer::from(&value.saddr).as_bytes());
        Self {
            sa_id,
            saddr,
            flags: value.flags,
            reqid: value.reqid,
        }
    }
}

impl Emitable for AsyncEventId {
    fn buffer_len(&self) -> usize {
        size_of::<AsyncEventIdBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = AsyncEventIdBuffer::from(self);
        buffer[..size_of::<AsyncEventIdBuffer>()]
            .copy_from_slice(raw.as_bytes());
    }
}
