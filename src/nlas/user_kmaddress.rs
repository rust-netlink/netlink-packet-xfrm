// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable, ErrorContext};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{Address, AddressBuffer, XFRM_ADDRESS_LEN};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserKmAddress {
    pub local: Address,
    pub remote: Address,
    pub reserved: u32,
    pub family: u16,
}

pub const XFRM_USER_KMADDRESS_LEN: usize = 40;

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
pub struct UserKmAddressBuffer {
    local: [u8; XFRM_ADDRESS_LEN],
    remote: [u8; XFRM_ADDRESS_LEN],
    reserved: u32,
    family: u16,
    padding: [u8; 2],
}

impl UserKmAddress {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            UserKmAddressBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<UserKmAddressBuffer>(),
                )
            })?;
        let local = Address::parse(&raw.local[..])
            .context("failed to parse local address")?;
        let remote = Address::parse(&raw.remote[..])
            .context("failed to parse remote address")?;
        Ok(Self {
            local,
            remote,
            reserved: raw.reserved,
            family: raw.family,
        })
    }
}

impl From<&UserKmAddress> for UserKmAddressBuffer {
    fn from(value: &UserKmAddress) -> Self {
        let mut local = [0u8; XFRM_ADDRESS_LEN];
        local.copy_from_slice(AddressBuffer::from(&value.local).as_bytes());
        let mut remote = [0u8; XFRM_ADDRESS_LEN];
        remote.copy_from_slice(AddressBuffer::from(&value.remote).as_bytes());
        Self {
            local,
            remote,
            reserved: value.reserved,
            family: value.family,
            padding: [0; 2],
        }
    }
}

impl Emitable for UserKmAddress {
    fn buffer_len(&self) -> usize {
        size_of::<UserKmAddressBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = UserKmAddressBuffer::from(self);
        buffer[..size_of::<UserKmAddressBuffer>()]
            .copy_from_slice(raw.as_bytes());
    }
}
