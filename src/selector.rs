// SPDX-License-Identifier: MIT

use std::{mem::size_of, net::IpAddr};

use netlink_packet_core::{DecodeError, Emitable, ErrorContext};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    constants::{AF_INET, AF_INET6},
    Address, XFRM_ADDRESS_LEN,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct Selector {
    pub daddr: Address,
    pub saddr: Address,
    pub dport: u16,      // big-endian
    pub dport_mask: u16, // big-endian
    pub sport: u16,      // big-endian
    pub sport_mask: u16, // big-endian
    pub family: u16,
    pub prefixlen_d: u8,
    pub prefixlen_s: u8,
    pub proto: u8,
    pub ifindex: i32, // "int" in iproute2
    pub user: u32,    // "__kernel_uid32_t" in iproute2
}

pub const XFRM_SELECTOR_LEN: usize = 56;

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
pub struct SelectorBuffer {
    daddr: [u8; XFRM_ADDRESS_LEN],
    saddr: [u8; XFRM_ADDRESS_LEN],
    dport: u16,
    dport_mask: u16,
    sport: u16,
    sport_mask: u16,
    family: u16,
    prefixlen_d: u8,
    prefixlen_s: u8,
    proto: u8,
    padding: [u8; 3],
    ifindex: i32,
    user: u32,
}

impl Selector {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            SelectorBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<SelectorBuffer>(),
                )
            })?;
        let daddr =
            Address::parse(&raw.daddr[..]).context("failed to parse daddr")?;
        let saddr =
            Address::parse(&raw.saddr[..]).context("failed to parse saddr")?;
        Ok(Self {
            daddr,
            saddr,
            dport: u16::from_be(raw.dport),
            dport_mask: u16::from_be(raw.dport_mask),
            sport: u16::from_be(raw.sport),
            sport_mask: u16::from_be(raw.sport_mask),
            family: raw.family,
            prefixlen_d: raw.prefixlen_d,
            prefixlen_s: raw.prefixlen_s,
            proto: raw.proto,
            ifindex: raw.ifindex,
            user: raw.user,
        })
    }
}

impl From<&Selector> for SelectorBuffer {
    fn from(value: &Selector) -> Self {
        Self {
            daddr: value.daddr.addr,
            saddr: value.saddr.addr,
            dport: value.dport.to_be(),
            dport_mask: value.dport_mask.to_be(),
            sport: value.sport.to_be(),
            sport_mask: value.sport_mask.to_be(),
            family: value.family,
            prefixlen_d: value.prefixlen_d,
            prefixlen_s: value.prefixlen_s,
            proto: value.proto,
            padding: [0; 3],
            ifindex: value.ifindex,
            user: value.user,
        }
    }
}

impl Emitable for Selector {
    fn buffer_len(&self) -> usize {
        size_of::<SelectorBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = SelectorBuffer::from(self);
        buffer[..size_of::<SelectorBuffer>()].copy_from_slice(raw.as_bytes());
    }
}

impl Selector {
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
            self.prefixlen_s = 0;
        } else {
            self.prefixlen_s = prefixlen;
        }
        self.family(addr);
    }

    pub fn destination_prefix(&mut self, addr: &IpAddr, prefixlen: u8) {
        self.daddr = Address::from_ip(addr);

        if addr.is_unspecified() {
            self.prefixlen_d = 0;
        } else {
            self.prefixlen_d = prefixlen;
        }
        self.family(addr);
    }
}
