// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{
    append_bytes, append_u32, parse_u32, DecodeError, Emitable, EncodeError,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};
pub const XFRM_REPLAY_ESN_LEN: usize = 24;

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct ReplayEsn {
    pub bmp_len: u32,
    pub oseq: u32,
    pub seq: u32,
    pub oseq_hi: u32,
    pub seq_hi: u32,
    pub replay_window: u32,
    pub bmp: Vec<u32>,
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
pub struct ReplayEsnBuffer {
    bmp_len: u32,
    oseq: u32,
    seq: u32,
    oseq_hi: u32,
    seq_hi: u32,
    replay_window: u32,
}

impl ReplayEsn {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, bmp) =
            ReplayEsnBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<ReplayEsnBuffer>(),
                )
            })?;
        if !bmp.len().is_multiple_of(4) {
            return Err(DecodeError::from("invalid ReplayEsnBuffer bmp"));
        }
        let bmp = bmp.chunks(4).map(|v| parse_u32(v).unwrap()).collect();

        Ok(Self {
            bmp_len: raw.bmp_len,
            oseq: raw.oseq,
            seq: raw.seq,
            oseq_hi: raw.oseq_hi,
            seq_hi: raw.seq_hi,
            replay_window: raw.replay_window,
            bmp,
        })
    }
}

impl From<&ReplayEsn> for ReplayEsnBuffer {
    fn from(value: &ReplayEsn) -> Self {
        Self {
            bmp_len: value.bmp_len,
            oseq: value.oseq,
            seq: value.seq,
            oseq_hi: value.oseq_hi,
            seq_hi: value.seq_hi,
            replay_window: value.replay_window,
        }
    }
}

impl Emitable for ReplayEsn {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let raw = ReplayEsnBuffer::from(self);
        let _header_len = size_of::<ReplayEsnBuffer>();
        append_bytes(out, raw.as_bytes());
        for v in self.bmp.iter() {
            append_u32(out, *v);
        }
        Ok(())
    }
}
