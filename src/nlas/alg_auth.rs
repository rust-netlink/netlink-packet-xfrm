// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{append_bytes, DecodeError, Emitable, EncodeError};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};
pub const XFRM_ALG_AUTH_NAME_LEN: usize = 64;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AlgAuth {
    pub alg_name: [u8; XFRM_ALG_AUTH_NAME_LEN],
    pub alg_key_len: u32,
    pub alg_trunc_len: u32,
    pub alg_key: Vec<u8>,
}

pub const XFRM_ALG_AUTH_HEADER_LEN: usize = XFRM_ALG_AUTH_NAME_LEN + 4 + 4;

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
pub struct AlgAuthBuffer {
    alg_name: [u8; XFRM_ALG_AUTH_NAME_LEN],
    alg_key_len: u32,
    alg_trunc_len: u32,
}

impl AlgAuth {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, alg_key) =
            AlgAuthBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<AlgAuthBuffer>(),
                )
            })?;
        Ok(Self {
            alg_name: raw.alg_name,
            alg_key_len: raw.alg_key_len,
            alg_trunc_len: raw.alg_trunc_len,
            alg_key: alg_key.to_vec(),
        })
    }
}

impl From<&AlgAuth> for AlgAuthBuffer {
    fn from(value: &AlgAuth) -> Self {
        Self {
            alg_name: value.alg_name,
            alg_key_len: value.alg_key_len,
            alg_trunc_len: value.alg_trunc_len,
        }
    }
}

impl Emitable for AlgAuth {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let raw = AlgAuthBuffer::from(self);
        let _header_len = size_of::<AlgAuthBuffer>();
        append_bytes(out, raw.as_bytes());
        append_bytes(out, &self.alg_key);
        Ok(())
    }
}
