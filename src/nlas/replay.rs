// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{append_bytes, DecodeError, Emitable, EncodeError};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct Replay {
    pub oseq: u32,
    pub seq: u32,
    pub bitmap: u32,
}

pub const XFRM_REPLAY_LEN: usize = 12;

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
pub struct ReplayBuffer {
    oseq: u32,
    seq: u32,
    bitmap: u32,
}

impl Replay {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            ReplayBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<ReplayBuffer>(),
                )
            })?;
        Ok(Self {
            oseq: raw.oseq,
            seq: raw.seq,
            bitmap: raw.bitmap,
        })
    }
}

impl From<&Replay> for ReplayBuffer {
    fn from(value: &Replay) -> Self {
        Self {
            oseq: value.oseq,
            seq: value.seq,
            bitmap: value.bitmap,
        }
    }
}

impl Emitable for Replay {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let raw = ReplayBuffer::from(self);
        append_bytes(out, raw.as_bytes());
        Ok(())
    }
}
