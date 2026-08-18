// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct SadHInfo {
    pub sadhcnt: u32,
    pub sadhmcnt: u32,
}

pub const XFRM_SAD_HINFO_LEN: usize = 8;

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
pub struct SadHInfoBuffer {
    sadhcnt: u32,
    sadhmcnt: u32,
}

impl SadHInfo {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            SadHInfoBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<SadHInfoBuffer>(),
                )
            })?;
        Ok(Self {
            sadhcnt: raw.sadhcnt,
            sadhmcnt: raw.sadhmcnt,
        })
    }
}

impl From<&SadHInfo> for SadHInfoBuffer {
    fn from(value: &SadHInfo) -> Self {
        Self {
            sadhcnt: value.sadhcnt,
            sadhmcnt: value.sadhmcnt,
        }
    }
}

impl Emitable for SadHInfo {
    fn buffer_len(&self) -> usize {
        size_of::<SadHInfoBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = SadHInfoBuffer::from(self);
        buffer[..size_of::<SadHInfoBuffer>()].copy_from_slice(raw.as_bytes());
    }
}
