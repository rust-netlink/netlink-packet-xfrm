// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub const XFRM_ALG_NAME_LEN: usize = 64;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Alg {
    pub alg_name: [u8; XFRM_ALG_NAME_LEN],
    pub alg_key_len: u32,
    pub alg_key: Vec<u8>,
}

pub const XFRM_ALG_HEADER_LEN: usize = XFRM_ALG_NAME_LEN + 4;

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
pub struct AlgBuffer {
    alg_name: [u8; XFRM_ALG_NAME_LEN],
    alg_key_len: u32,
}

impl Alg {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, alg_key) =
            AlgBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<AlgBuffer>(),
                )
            })?;
        Ok(Self {
            alg_name: raw.alg_name,
            alg_key_len: raw.alg_key_len,
            alg_key: alg_key.to_vec(),
        })
    }
}

impl From<&Alg> for AlgBuffer {
    fn from(value: &Alg) -> Self {
        Self {
            alg_name: value.alg_name,
            alg_key_len: value.alg_key_len,
        }
    }
}

impl Emitable for Alg {
    fn buffer_len(&self) -> usize {
        size_of::<AlgBuffer>() + self.alg_key.len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = AlgBuffer::from(self);
        let header_len = size_of::<AlgBuffer>();
        buffer[..header_len].copy_from_slice(raw.as_bytes());
        buffer[header_len..].copy_from_slice(&self.alg_key);
    }
}
