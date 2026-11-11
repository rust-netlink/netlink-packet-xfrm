// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{append_bytes, DecodeError, Emitable, EncodeError};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct Mark {
    pub value: u32,
    pub mask: u32,
}

pub const XFRM_MARK_LEN: usize = 8;

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
pub struct MarkBuffer {
    value: u32,
    mask: u32,
}

impl Mark {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) = MarkBuffer::ref_from_prefix(payload).map_err(|_| {
            DecodeError::buffer_too_small(
                payload.len(),
                size_of::<MarkBuffer>(),
            )
        })?;
        Ok(Self {
            value: raw.value,
            mask: raw.mask,
        })
    }
}

impl From<&Mark> for MarkBuffer {
    fn from(value: &Mark) -> Self {
        Self {
            value: value.value,
            mask: value.mask,
        }
    }
}

impl Emitable for Mark {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let raw = MarkBuffer::from(self);
        append_bytes(out, raw.as_bytes());
        Ok(())
    }
}
