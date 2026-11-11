// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{append_bytes, DecodeError, Emitable, EncodeError};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct Stats {
    pub replay_window: u32,
    pub replay: u32,
    pub integrity_failed: u32,
}

pub const XFRM_STATS_LEN: usize = 12;

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
pub struct StatsBuffer {
    replay_window: u32,
    replay: u32,
    integrity_failed: u32,
}

impl Stats {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) = StatsBuffer::ref_from_prefix(payload).map_err(|_| {
            DecodeError::buffer_too_small(
                payload.len(),
                size_of::<StatsBuffer>(),
            )
        })?;
        Ok(Self {
            replay_window: raw.replay_window,
            replay: raw.replay,
            integrity_failed: raw.integrity_failed,
        })
    }
}

impl From<&Stats> for StatsBuffer {
    fn from(value: &Stats) -> Self {
        Self {
            replay_window: value.replay_window,
            replay: value.replay,
            integrity_failed: value.integrity_failed,
        }
    }
}

impl Emitable for Stats {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let raw = StatsBuffer::from(self);
        append_bytes(out, raw.as_bytes());
        Ok(())
    }
}
