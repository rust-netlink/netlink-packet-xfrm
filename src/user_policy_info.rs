// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable, ErrorContext};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    Lifetime, LifetimeBuffer, LifetimeConfig, LifetimeConfigBuffer, Selector,
    SelectorBuffer, XFRM_LIFETIME_CONFIG_LEN, XFRM_LIFETIME_LEN,
    XFRM_SELECTOR_LEN,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserPolicyInfo {
    pub selector: Selector,
    pub lifetime_cfg: LifetimeConfig,
    pub lifetime_cur: Lifetime,
    pub priority: u32,
    pub index: u32,
    pub direction: u8,
    pub action: u8,
    pub flags: u8,
    pub share: u8,
}

pub const XFRM_USER_POLICY_INFO_LEN: usize = 168;

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
pub struct UserPolicyInfoBuffer {
    selector: [u8; XFRM_SELECTOR_LEN],
    lifetime_cfg: [u8; XFRM_LIFETIME_CONFIG_LEN],
    lifetime_cur: [u8; XFRM_LIFETIME_LEN],
    priority: u32,
    index: u32,
    direction: u8,
    action: u8,
    flags: u8,
    share: u8,
    padding: [u8; 4],
}

impl UserPolicyInfo {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            UserPolicyInfoBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<UserPolicyInfoBuffer>(),
                )
            })?;
        let selector = Selector::parse(&raw.selector[..])
            .context("failed to parse selector")?;
        let lifetime_cfg = LifetimeConfig::parse(&raw.lifetime_cfg[..])
            .context("failed to parse lifetime config")?;
        let lifetime_cur = Lifetime::parse(&raw.lifetime_cur[..])
            .context("failed to parse lifetime current")?;
        Ok(Self {
            selector,
            lifetime_cfg,
            lifetime_cur,
            priority: raw.priority,
            index: raw.index,
            direction: raw.direction,
            action: raw.action,
            flags: raw.flags,
            share: raw.share,
        })
    }
}

impl From<&UserPolicyInfo> for UserPolicyInfoBuffer {
    fn from(value: &UserPolicyInfo) -> Self {
        let mut selector = [0u8; XFRM_SELECTOR_LEN];
        selector
            .copy_from_slice(SelectorBuffer::from(&value.selector).as_bytes());
        let mut lifetime_cfg = [0u8; XFRM_LIFETIME_CONFIG_LEN];
        lifetime_cfg.copy_from_slice(
            LifetimeConfigBuffer::from(&value.lifetime_cfg).as_bytes(),
        );
        let mut lifetime_cur = [0u8; XFRM_LIFETIME_LEN];
        lifetime_cur.copy_from_slice(
            LifetimeBuffer::from(&value.lifetime_cur).as_bytes(),
        );
        Self {
            selector,
            lifetime_cfg,
            lifetime_cur,
            priority: value.priority,
            index: value.index,
            direction: value.direction,
            action: value.action,
            flags: value.flags,
            share: value.share,
            padding: [0; 4],
        }
    }
}

impl Emitable for UserPolicyInfo {
    fn buffer_len(&self) -> usize {
        size_of::<UserPolicyInfoBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = UserPolicyInfoBuffer::from(self);
        buffer[..size_of::<UserPolicyInfoBuffer>()]
            .copy_from_slice(raw.as_bytes());
    }
}
