// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::XFRM_INF;

// Lifetime config

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct LifetimeConfig {
    pub soft_byte_limit: u64,
    pub hard_byte_limit: u64,
    pub soft_packet_limit: u64,
    pub hard_packet_limit: u64,
    pub soft_add_expires_seconds: u64,
    pub hard_add_expires_seconds: u64,
    pub soft_use_expires_seconds: u64,
    pub hard_use_expires_seconds: u64,
}

pub const XFRM_LIFETIME_CONFIG_LEN: usize = 64;

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
pub struct LifetimeConfigBuffer {
    soft_byte_limit: u64,
    hard_byte_limit: u64,
    soft_packet_limit: u64,
    hard_packet_limit: u64,
    soft_add_expires_seconds: u64,
    hard_add_expires_seconds: u64,
    soft_use_expires_seconds: u64,
    hard_use_expires_seconds: u64,
}

impl Default for LifetimeConfig {
    fn default() -> Self {
        LifetimeConfig {
            soft_byte_limit: XFRM_INF,
            hard_byte_limit: XFRM_INF,
            soft_packet_limit: XFRM_INF,
            hard_packet_limit: XFRM_INF,
            soft_add_expires_seconds: 0,
            hard_add_expires_seconds: 0,
            soft_use_expires_seconds: 0,
            hard_use_expires_seconds: 0,
        }
    }
}

impl LifetimeConfig {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            LifetimeConfigBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<LifetimeConfigBuffer>(),
                )
            })?;
        Ok(Self {
            soft_byte_limit: raw.soft_byte_limit,
            hard_byte_limit: raw.hard_byte_limit,
            soft_packet_limit: raw.soft_packet_limit,
            hard_packet_limit: raw.hard_packet_limit,
            soft_add_expires_seconds: raw.soft_add_expires_seconds,
            hard_add_expires_seconds: raw.hard_add_expires_seconds,
            soft_use_expires_seconds: raw.soft_use_expires_seconds,
            hard_use_expires_seconds: raw.hard_use_expires_seconds,
        })
    }
}

impl From<&LifetimeConfig> for LifetimeConfigBuffer {
    fn from(value: &LifetimeConfig) -> Self {
        Self {
            soft_byte_limit: value.soft_byte_limit,
            hard_byte_limit: value.hard_byte_limit,
            soft_packet_limit: value.soft_packet_limit,
            hard_packet_limit: value.hard_packet_limit,
            soft_add_expires_seconds: value.soft_add_expires_seconds,
            hard_add_expires_seconds: value.hard_add_expires_seconds,
            soft_use_expires_seconds: value.soft_use_expires_seconds,
            hard_use_expires_seconds: value.hard_use_expires_seconds,
        }
    }
}

impl Emitable for LifetimeConfig {
    fn buffer_len(&self) -> usize {
        size_of::<LifetimeConfigBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = LifetimeConfigBuffer::from(self);
        buffer[..size_of::<LifetimeConfigBuffer>()]
            .copy_from_slice(raw.as_bytes());
    }
}

// Lifetime curent

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct Lifetime {
    pub bytes: u64,
    pub packets: u64,
    pub add_time: u64,
    pub use_time: u64,
}

pub const XFRM_LIFETIME_LEN: usize = 32;

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
pub struct LifetimeBuffer {
    bytes: u64,
    packets: u64,
    add_time: u64,
    use_time: u64,
}

impl Lifetime {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            LifetimeBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<LifetimeBuffer>(),
                )
            })?;
        Ok(Self {
            bytes: raw.bytes,
            packets: raw.packets,
            add_time: raw.add_time,
            use_time: raw.use_time,
        })
    }
}

impl From<&Lifetime> for LifetimeBuffer {
    fn from(value: &Lifetime) -> Self {
        Self {
            bytes: value.bytes,
            packets: value.packets,
            add_time: value.add_time,
            use_time: value.use_time,
        }
    }
}

impl Emitable for Lifetime {
    fn buffer_len(&self) -> usize {
        size_of::<LifetimeBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = LifetimeBuffer::from(self);
        buffer[..size_of::<LifetimeBuffer>()].copy_from_slice(raw.as_bytes());
    }
}
