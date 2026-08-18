// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable, ErrorContext};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{Address, AddressBuffer, XFRM_ADDRESS_LEN};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserMigrate {
    pub old_daddr: Address,
    pub old_saddr: Address,
    pub new_daddr: Address,
    pub new_saddr: Address,
    pub proto: u8,
    pub mode: u8,
    pub reserved: u16,
    pub reqid: u32,
    pub old_family: u16,
    pub new_family: u16,
}

pub const XFRM_USER_MIGRATE_LEN: usize = 76;

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
pub struct UserMigrateBuffer {
    old_daddr: [u8; XFRM_ADDRESS_LEN],
    old_saddr: [u8; XFRM_ADDRESS_LEN],
    new_daddr: [u8; XFRM_ADDRESS_LEN],
    new_saddr: [u8; XFRM_ADDRESS_LEN],
    proto: u8,
    mode: u8,
    reserved: u16,
    reqid: u32,
    old_family: u16,
    new_family: u16,
}

impl UserMigrate {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            UserMigrateBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<UserMigrateBuffer>(),
                )
            })?;
        let old_daddr = Address::parse(&raw.old_daddr[..])
            .context("failed to parse old_daddr address")?;
        let old_saddr = Address::parse(&raw.old_saddr[..])
            .context("failed to parse old_saddr address")?;
        let new_daddr = Address::parse(&raw.new_daddr[..])
            .context("failed to parse new_daddr address")?;
        let new_saddr = Address::parse(&raw.new_saddr[..])
            .context("failed to parse new_saddr address")?;
        Ok(Self {
            old_daddr,
            old_saddr,
            new_daddr,
            new_saddr,
            proto: raw.proto,
            mode: raw.mode,
            reserved: raw.reserved,
            reqid: raw.reqid,
            old_family: raw.old_family,
            new_family: raw.new_family,
        })
    }
}

impl From<&UserMigrate> for UserMigrateBuffer {
    fn from(value: &UserMigrate) -> Self {
        let mut old_daddr = [0u8; XFRM_ADDRESS_LEN];
        old_daddr
            .copy_from_slice(AddressBuffer::from(&value.old_daddr).as_bytes());
        let mut old_saddr = [0u8; XFRM_ADDRESS_LEN];
        old_saddr
            .copy_from_slice(AddressBuffer::from(&value.old_saddr).as_bytes());
        let mut new_daddr = [0u8; XFRM_ADDRESS_LEN];
        new_daddr
            .copy_from_slice(AddressBuffer::from(&value.new_daddr).as_bytes());
        let mut new_saddr = [0u8; XFRM_ADDRESS_LEN];
        new_saddr
            .copy_from_slice(AddressBuffer::from(&value.new_saddr).as_bytes());
        Self {
            old_daddr,
            old_saddr,
            new_daddr,
            new_saddr,
            proto: value.proto,
            mode: value.mode,
            reserved: value.reserved,
            reqid: value.reqid,
            old_family: value.old_family,
            new_family: value.new_family,
        }
    }
}

impl Emitable for UserMigrate {
    fn buffer_len(&self) -> usize {
        size_of::<UserMigrateBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = UserMigrateBuffer::from(self);
        buffer[..size_of::<UserMigrateBuffer>()]
            .copy_from_slice(raw.as_bytes());
    }
}
