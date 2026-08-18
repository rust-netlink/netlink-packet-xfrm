// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct SpdInfo {
    pub incnt: u32,
    pub outcnt: u32,
    pub fwdcnt: u32,
    pub inscnt: u32,
    pub outscnt: u32,
    pub fwdscnt: u32,
}

pub const XFRM_SPD_INFO_LEN: usize = 24;

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
pub struct SpdInfoBuffer {
    incnt: u32,
    outcnt: u32,
    fwdcnt: u32,
    inscnt: u32,
    outscnt: u32,
    fwdscnt: u32,
}

impl SpdInfo {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            SpdInfoBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<SpdInfoBuffer>(),
                )
            })?;
        Ok(Self {
            incnt: raw.incnt,
            outcnt: raw.outcnt,
            fwdcnt: raw.fwdcnt,
            inscnt: raw.inscnt,
            outscnt: raw.outscnt,
            fwdscnt: raw.fwdscnt,
        })
    }
}

impl From<&SpdInfo> for SpdInfoBuffer {
    fn from(value: &SpdInfo) -> Self {
        Self {
            incnt: value.incnt,
            outcnt: value.outcnt,
            fwdcnt: value.fwdcnt,
            inscnt: value.inscnt,
            outscnt: value.outscnt,
            fwdscnt: value.fwdscnt,
        }
    }
}

impl Emitable for SpdInfo {
    fn buffer_len(&self) -> usize {
        size_of::<SpdInfoBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = SpdInfoBuffer::from(self);
        buffer[..size_of::<SpdInfoBuffer>()].copy_from_slice(raw.as_bytes());
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct SpdHInfo {
    pub spdhcnt: u32,
    pub spdhmcnt: u32,
}

pub const XFRM_SPD_HINFO_LEN: usize = 8;

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
pub struct SpdHInfoBuffer {
    spdhcnt: u32,
    spdhmcnt: u32,
}

impl SpdHInfo {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            SpdHInfoBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<SpdHInfoBuffer>(),
                )
            })?;
        Ok(Self {
            spdhcnt: raw.spdhcnt,
            spdhmcnt: raw.spdhmcnt,
        })
    }
}

impl From<&SpdHInfo> for SpdHInfoBuffer {
    fn from(value: &SpdHInfo) -> Self {
        Self {
            spdhcnt: value.spdhcnt,
            spdhmcnt: value.spdhmcnt,
        }
    }
}

impl Emitable for SpdHInfo {
    fn buffer_len(&self) -> usize {
        size_of::<SpdHInfoBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = SpdHInfoBuffer::from(self);
        buffer[..size_of::<SpdHInfoBuffer>()].copy_from_slice(raw.as_bytes());
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct SpdHThresh {
    pub lbits: u8,
    pub rbits: u8,
}

pub const XFRM_SPD_HTHRESH_LEN: usize = 2;

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
pub struct SpdHThreshBuffer {
    lbits: u8,
    rbits: u8,
}

impl SpdHThresh {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            SpdHThreshBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<SpdHThreshBuffer>(),
                )
            })?;
        Ok(Self {
            lbits: raw.lbits,
            rbits: raw.rbits,
        })
    }
}

impl From<&SpdHThresh> for SpdHThreshBuffer {
    fn from(value: &SpdHThresh) -> Self {
        Self {
            lbits: value.lbits,
            rbits: value.rbits,
        }
    }
}

impl Emitable for SpdHThresh {
    fn buffer_len(&self) -> usize {
        size_of::<SpdHThreshBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = SpdHThreshBuffer::from(self);
        buffer[..size_of::<SpdHThreshBuffer>()].copy_from_slice(raw.as_bytes());
    }
}
