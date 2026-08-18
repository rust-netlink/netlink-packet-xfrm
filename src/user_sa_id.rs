// SPDX-License-Identifier: MIT

use std::{mem::size_of, net::IpAddr};

use netlink_packet_core::{DecodeError, Emitable, ErrorContext};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    constants::{AF_INET, AF_INET6},
    Address, XFRM_ADDRESS_LEN,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserSaId {
    pub daddr: Address,
    pub spi: u32, // big-endian
    pub family: u16,
    pub proto: u8,
}

pub const XFRM_USER_SA_ID_LEN: usize = 24;

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
pub struct UserSaIdBuffer {
    daddr: [u8; XFRM_ADDRESS_LEN],
    spi: u32,
    family: u16,
    proto: u8,
    padding: [u8; 1],
}

impl UserSaId {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            UserSaIdBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<UserSaIdBuffer>(),
                )
            })?;
        let daddr =
            Address::parse(&raw.daddr[..]).context("failed to parse daddr")?;
        Ok(Self {
            daddr,
            spi: u32::from_be(raw.spi),
            family: raw.family,
            proto: raw.proto,
        })
    }
}

impl From<&UserSaId> for UserSaIdBuffer {
    fn from(value: &UserSaId) -> Self {
        Self {
            daddr: value.daddr.addr,
            spi: value.spi.to_be(),
            family: value.family,
            proto: value.proto,
            padding: [0; 1],
        }
    }
}

impl Emitable for UserSaId {
    fn buffer_len(&self) -> usize {
        size_of::<UserSaIdBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = UserSaIdBuffer::from(self);
        buffer[..size_of::<UserSaIdBuffer>()].copy_from_slice(raw.as_bytes());
    }
}

impl UserSaId {
    fn family(&mut self, addr: &IpAddr) {
        if addr.is_ipv4() {
            self.family = AF_INET;
        } else if addr.is_ipv6() {
            self.family = AF_INET6;
        }
    }
    pub fn destination(&mut self, addr: &IpAddr) {
        self.daddr = Address::from_ip(addr);
        self.family(addr);
    }
}
