// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable, ErrorContext};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    Address, AddressBuffer, UserSaId, UserSaIdBuffer, XFRM_ADDRESS_LEN,
    XFRM_USER_SA_ID_LEN,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserMapping {
    pub id: UserSaId,
    pub reqid: u32,
    pub old_saddr: Address,
    pub new_saddr: Address,
    pub old_sport: u16, // big-endian
    pub new_sport: u16, // big-endian
}

pub const XFRM_USER_MAPPING_LEN: usize = 64;

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
pub struct UserMappingBuffer {
    id: [u8; XFRM_USER_SA_ID_LEN],
    reqid: u32,
    old_saddr: [u8; XFRM_ADDRESS_LEN],
    new_saddr: [u8; XFRM_ADDRESS_LEN],
    old_sport: u16,
    new_sport: u16,
}

impl UserMapping {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            UserMappingBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<UserMappingBuffer>(),
                )
            })?;
        let id = UserSaId::parse(&raw.id[..])
            .context("failed to parse user sa id")?;
        let old_saddr = Address::parse(&raw.old_saddr[..])
            .context("failed to parse old saddr")?;
        let new_saddr = Address::parse(&raw.new_saddr[..])
            .context("failed to parse new saddr")?;
        Ok(Self {
            id,
            reqid: raw.reqid,
            old_saddr,
            new_saddr,
            old_sport: u16::from_be(raw.old_sport),
            new_sport: u16::from_be(raw.new_sport),
        })
    }
}

impl From<&UserMapping> for UserMappingBuffer {
    fn from(value: &UserMapping) -> Self {
        let mut id = [0u8; XFRM_USER_SA_ID_LEN];
        id.copy_from_slice(UserSaIdBuffer::from(&value.id).as_bytes());
        let mut old_saddr = [0u8; XFRM_ADDRESS_LEN];
        old_saddr
            .copy_from_slice(AddressBuffer::from(&value.old_saddr).as_bytes());
        let mut new_saddr = [0u8; XFRM_ADDRESS_LEN];
        new_saddr
            .copy_from_slice(AddressBuffer::from(&value.new_saddr).as_bytes());
        Self {
            id,
            reqid: value.reqid,
            old_saddr,
            new_saddr,
            old_sport: value.old_sport.to_be(),
            new_sport: value.new_sport.to_be(),
        }
    }
}

impl Emitable for UserMapping {
    fn buffer_len(&self) -> usize {
        size_of::<UserMappingBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = UserMappingBuffer::from(self);
        buffer[..size_of::<UserMappingBuffer>()]
            .copy_from_slice(raw.as_bytes());
    }
}
