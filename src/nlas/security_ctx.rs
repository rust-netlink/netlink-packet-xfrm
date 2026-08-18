// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::constants::*;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SecurityCtx {
    pub len: u16,
    pub exttype: u16,
    pub ctx_alg: u8,
    pub ctx_doi: u8,
    pub ctx_len: u16,
    pub ctx_str: Vec<u8>,
}

pub const XFRM_SEC_CTX_HEADER_LEN: usize = 8;

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
pub struct SecurityCtxBuffer {
    len: u16,
    exttype: u16,
    ctx_alg: u8,
    ctx_doi: u8,
    ctx_len: u16,
}

impl Default for SecurityCtx {
    fn default() -> Self {
        SecurityCtx {
            len: XFRM_SEC_CTX_HEADER_LEN as u16,
            exttype: XFRMA_SEC_CTX,
            ctx_alg: XFRM_SC_ALG_SELINUX,
            ctx_doi: XFRM_SC_DOI_LSM,
            ctx_len: 0,
            ctx_str: Vec::default(),
        }
    }
}

impl SecurityCtx {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, ctx_str) = SecurityCtxBuffer::ref_from_prefix(payload)
            .map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<SecurityCtxBuffer>(),
                )
            })?;
        Ok(Self {
            len: raw.len,
            exttype: raw.exttype,
            ctx_alg: raw.ctx_alg,
            ctx_doi: raw.ctx_doi,
            ctx_len: raw.ctx_len,
            ctx_str: ctx_str.to_vec(),
        })
    }
}

impl From<&SecurityCtx> for SecurityCtxBuffer {
    fn from(value: &SecurityCtx) -> Self {
        Self {
            len: value.len,
            exttype: value.exttype,
            ctx_alg: value.ctx_alg,
            ctx_doi: value.ctx_doi,
            ctx_len: value.ctx_len,
        }
    }
}

impl Emitable for SecurityCtx {
    fn buffer_len(&self) -> usize {
        size_of::<SecurityCtxBuffer>() + self.ctx_str.len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = SecurityCtxBuffer::from(self);
        let header_len = size_of::<SecurityCtxBuffer>();
        buffer[..header_len].copy_from_slice(raw.as_bytes());
        buffer[header_len..].copy_from_slice(&self.ctx_str);
    }
}

impl SecurityCtx {
    pub fn context(&mut self, secctx: &[u8]) {
        // The kernel limits the length of the security context
        // string to the page size, which is commonly 4096.
        // iproute2 limits it to 256 when parsing from the cli.
        // Keeping it at 256 should be plenty, but if it needs to
        // be a little more generous, it can be raised.
        let mut ctx_str = secctx.to_vec();
        ctx_str.truncate(256);
        self.ctx_len = ctx_str.len() as u16;
        self.ctx_str = ctx_str;
        self.len = XFRM_SEC_CTX_HEADER_LEN as u16 + self.ctx_len;
    }
}
