// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable, ErrorContext};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{Address, AddressBuffer, XFRM_ADDRESS_LEN};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct EncapTmpl {
    pub encap_type: u16,
    pub encap_sport: u16, // big-endian
    pub encap_dport: u16, // big-endian
    pub encap_oa: Address,
}

pub const XFRM_ENCAP_TMPL_LEN: usize = 24;

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
pub struct EncapTmplBuffer {
    encap_type: u16,
    encap_sport: u16,
    encap_dport: u16,
    padding: [u8; 2],
    encap_oa: [u8; XFRM_ADDRESS_LEN],
}

impl EncapTmpl {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            EncapTmplBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<EncapTmplBuffer>(),
                )
            })?;
        let encap_oa = Address::parse(&raw.encap_oa[..])
            .context("failed to parse oa address")?;
        Ok(Self {
            encap_type: raw.encap_type,
            encap_sport: u16::from_be(raw.encap_sport),
            encap_dport: u16::from_be(raw.encap_dport),
            encap_oa,
        })
    }
}

impl From<&EncapTmpl> for EncapTmplBuffer {
    fn from(value: &EncapTmpl) -> Self {
        let mut encap_oa = [0u8; XFRM_ADDRESS_LEN];
        encap_oa
            .copy_from_slice(AddressBuffer::from(&value.encap_oa).as_bytes());
        Self {
            encap_type: value.encap_type,
            encap_sport: value.encap_sport.to_be(),
            encap_dport: value.encap_dport.to_be(),
            padding: [0; 2],
            encap_oa,
        }
    }
}

impl Emitable for EncapTmpl {
    fn buffer_len(&self) -> usize {
        size_of::<EncapTmplBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = EncapTmplBuffer::from(self);
        buffer[..size_of::<EncapTmplBuffer>()].copy_from_slice(raw.as_bytes());
    }
}
