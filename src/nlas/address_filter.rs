// SPDX-License-Identifier: MIT

use std::{mem::size_of, net::IpAddr};

use netlink_packet_core::{DecodeError, Emitable, ErrorContext};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    constants::{AF_INET, AF_INET6},
    Address, AddressBuffer, XFRM_ADDRESS_LEN,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct AddressFilter {
    pub saddr: Address,
    pub daddr: Address,
    pub family: u16,
    pub splen: u8,
    pub dplen: u8,
}

pub const XFRM_ADDRESS_FILTER_LEN: usize = 36;

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
pub struct AddressFilterBuffer {
    saddr: [u8; XFRM_ADDRESS_LEN],
    daddr: [u8; XFRM_ADDRESS_LEN],
    family: u16,
    splen: u8,
    dplen: u8,
}

impl AddressFilter {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            AddressFilterBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<AddressFilterBuffer>(),
                )
            })?;
        let saddr = Address::parse(&raw.saddr[..])
            .context("failed to parse saddr address")?;
        let daddr = Address::parse(&raw.daddr[..])
            .context("failed to parse daddr address")?;
        Ok(Self {
            saddr,
            daddr,
            family: raw.family,
            splen: raw.splen,
            dplen: raw.dplen,
        })
    }
}

impl From<&AddressFilter> for AddressFilterBuffer {
    fn from(value: &AddressFilter) -> Self {
        let mut saddr = [0u8; XFRM_ADDRESS_LEN];
        saddr.copy_from_slice(AddressBuffer::from(&value.saddr).as_bytes());
        let mut daddr = [0u8; XFRM_ADDRESS_LEN];
        daddr.copy_from_slice(AddressBuffer::from(&value.daddr).as_bytes());
        Self {
            saddr,
            daddr,
            family: value.family,
            splen: value.splen,
            dplen: value.dplen,
        }
    }
}

impl Emitable for AddressFilter {
    fn buffer_len(&self) -> usize {
        size_of::<AddressFilterBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = AddressFilterBuffer::from(self);
        buffer[..size_of::<AddressFilterBuffer>()]
            .copy_from_slice(raw.as_bytes());
    }
}

impl AddressFilter {
    fn family(&mut self, addr: &IpAddr) {
        if addr.is_ipv4() {
            self.family = AF_INET;
        } else if addr.is_ipv6() {
            self.family = AF_INET6;
        }
    }

    pub fn source_prefix(&mut self, addr: &IpAddr, prefixlen: u8) {
        self.saddr = Address::from_ip(addr);

        if addr.is_unspecified() {
            self.splen = 0;
        } else {
            self.splen = prefixlen;
        }
        self.family(addr);
    }

    pub fn destination_prefix(&mut self, addr: &IpAddr, prefixlen: u8) {
        self.daddr = Address::from_ip(addr);

        if addr.is_unspecified() {
            self.dplen = 0;
        } else {
            self.dplen = prefixlen;
        }
        self.family(addr);
    }
}
