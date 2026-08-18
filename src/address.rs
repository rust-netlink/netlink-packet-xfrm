// SPDX-License-Identifier: MIT

use std::{
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use netlink_packet_core::{DecodeError, Emitable};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub const XFRM_ADDRESS_LEN: usize = 16;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct Address {
    // Xfrm netlink API simply uses a 16 byte buffer for both IPv4 & IPv6
    // addresses and unfortunately doesn't always pair it with a family type.
    pub addr: [u8; XFRM_ADDRESS_LEN],
}

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
pub struct AddressBuffer {
    addr: [u8; XFRM_ADDRESS_LEN],
}

impl Address {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            AddressBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<AddressBuffer>(),
                )
            })?;
        Ok(Self { addr: raw.addr })
    }
}

impl From<&Address> for AddressBuffer {
    fn from(value: &Address) -> Self {
        Self { addr: value.addr }
    }
}

impl Emitable for Address {
    fn buffer_len(&self) -> usize {
        size_of::<AddressBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = AddressBuffer::from(self);
        buffer[..size_of::<AddressBuffer>()].copy_from_slice(raw.as_bytes());
    }
}

impl Address {
    pub fn to_ipv4(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.addr[0], self.addr[1], self.addr[2], self.addr[3])
    }

    pub fn to_ipv6(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.addr)
    }

    pub fn from_ipv4(ip: &Ipv4Addr) -> Address {
        let mut addr_bytes: [u8; XFRM_ADDRESS_LEN] = [0; XFRM_ADDRESS_LEN];
        addr_bytes[0] = ip.octets()[0];
        addr_bytes[1] = ip.octets()[1];
        addr_bytes[2] = ip.octets()[2];
        addr_bytes[3] = ip.octets()[3];
        Address { addr: addr_bytes }
    }

    pub fn from_ipv6(ip: &Ipv6Addr) -> Address {
        Address { addr: ip.octets() }
    }

    pub fn from_ip(ip: &IpAddr) -> Address {
        match ip {
            IpAddr::V4(v4) => Self::from_ipv4(v4),
            IpAddr::V6(v6) => Self::from_ipv6(v6),
        }
    }
}
