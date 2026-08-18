// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable, ErrorContext};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{Address, XFRM_ADDRESS_LEN};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct Id {
    pub daddr: Address,
    pub spi: u32, // big-endian
    pub proto: u8,
}

pub const XFRM_ID_LEN: usize = 24;

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
pub struct IdBuffer {
    daddr: [u8; XFRM_ADDRESS_LEN],
    spi: u32,
    proto: u8,
    padding: [u8; 3],
}

impl Id {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) = IdBuffer::ref_from_prefix(payload).map_err(|_| {
            DecodeError::buffer_too_small(payload.len(), size_of::<IdBuffer>())
        })?;
        let daddr = Address::parse(&raw.daddr[..])
            .context("failed to parse Address in Id")?;
        Ok(Self {
            daddr,
            spi: u32::from_be(raw.spi),
            proto: raw.proto,
        })
    }
}

impl From<&Id> for IdBuffer {
    fn from(value: &Id) -> Self {
        Self {
            daddr: value.daddr.addr,
            spi: value.spi.to_be(),
            proto: value.proto,
            padding: [0; 3],
        }
    }
}

impl Emitable for Id {
    fn buffer_len(&self) -> usize {
        size_of::<IdBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = IdBuffer::from(self);
        buffer[..size_of::<IdBuffer>()].copy_from_slice(raw.as_bytes());
    }
}
