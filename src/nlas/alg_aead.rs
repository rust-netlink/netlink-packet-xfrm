// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{append_bytes, DecodeError, Emitable, EncodeError};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};
pub const XFRM_ALG_AEAD_NAME_LEN: usize = 64;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AlgAead {
    pub alg_name: [u8; XFRM_ALG_AEAD_NAME_LEN],
    pub alg_key_len: u32,
    pub alg_icv_len: u32,
    pub alg_key: Vec<u8>,
}

pub const XFRM_ALG_AEAD_HEADER_LEN: usize = XFRM_ALG_AEAD_NAME_LEN + 4 + 4;

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
pub struct AlgAeadBuffer {
    alg_name: [u8; XFRM_ALG_AEAD_NAME_LEN],
    alg_key_len: u32,
    alg_icv_len: u32,
}

impl AlgAead {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, alg_key) =
            AlgAeadBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<AlgAeadBuffer>(),
                )
            })?;
        Ok(Self {
            alg_name: raw.alg_name,
            alg_key_len: raw.alg_key_len,
            alg_icv_len: raw.alg_icv_len,
            alg_key: alg_key.to_vec(),
        })
    }
}

impl From<&AlgAead> for AlgAeadBuffer {
    fn from(value: &AlgAead) -> Self {
        Self {
            alg_name: value.alg_name,
            alg_key_len: value.alg_key_len,
            alg_icv_len: value.alg_icv_len,
        }
    }
}

impl Emitable for AlgAead {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let raw = AlgAeadBuffer::from(self);
        let _header_len = size_of::<AlgAeadBuffer>();
        append_bytes(out, raw.as_bytes());
        append_bytes(out, &self.alg_key);
        Ok(())
    }
}
