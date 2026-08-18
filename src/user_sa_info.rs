// SPDX-License-Identifier: MIT

use std::{mem::size_of, net::IpAddr};

use netlink_packet_core::{DecodeError, Emitable, ErrorContext};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    constants::{AF_INET, AF_INET6},
    Address, AddressBuffer, Id, IdBuffer, Lifetime, LifetimeBuffer,
    LifetimeConfig, LifetimeConfigBuffer, Selector, SelectorBuffer, Stats,
    StatsBuffer, XFRM_ADDRESS_LEN, XFRM_ID_LEN, XFRM_LIFETIME_CONFIG_LEN,
    XFRM_LIFETIME_LEN, XFRM_SELECTOR_LEN, XFRM_STATS_LEN,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserSaInfo {
    pub selector: Selector,
    pub id: Id,
    pub saddr: Address,
    pub lifetime_cfg: LifetimeConfig,
    pub lifetime_cur: Lifetime,
    pub stats: Stats,
    pub seq: u32,
    pub reqid: u32,
    pub family: u16,
    pub mode: u8,
    pub replay_window: u8,
    pub flags: u8,
}

pub const XFRM_USER_SA_INFO_LEN: usize = 224;

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
pub struct UserSaInfoBuffer {
    selector: [u8; XFRM_SELECTOR_LEN],
    id: [u8; XFRM_ID_LEN],
    saddr: [u8; XFRM_ADDRESS_LEN],
    lifetime_cfg: [u8; XFRM_LIFETIME_CONFIG_LEN],
    lifetime_cur: [u8; XFRM_LIFETIME_LEN],
    stats: [u8; XFRM_STATS_LEN],
    seq: u32,
    reqid: u32,
    family: u16,
    mode: u8,
    replay_window: u8,
    flags: u8,
    padding: [u8; 7],
}

impl UserSaInfo {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            UserSaInfoBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<UserSaInfoBuffer>(),
                )
            })?;
        let selector = Selector::parse(&raw.selector[..])
            .context("failed to parse selector")?;
        let id = Id::parse(&raw.id[..]).context("failed to parse id")?;
        let saddr =
            Address::parse(&raw.saddr[..]).context("failed to parse saddr")?;
        let lifetime_cfg = LifetimeConfig::parse(&raw.lifetime_cfg[..])
            .context("failed to parse lifetime config")?;
        let lifetime_cur = Lifetime::parse(&raw.lifetime_cur[..])
            .context("failed to parse lifetime current")?;
        let stats =
            Stats::parse(&raw.stats[..]).context("failed to parse stats")?;
        Ok(Self {
            selector,
            id,
            saddr,
            lifetime_cfg,
            lifetime_cur,
            stats,
            seq: raw.seq,
            reqid: raw.reqid,
            family: raw.family,
            mode: raw.mode,
            replay_window: raw.replay_window,
            flags: raw.flags,
        })
    }
}

impl From<&UserSaInfo> for UserSaInfoBuffer {
    fn from(value: &UserSaInfo) -> Self {
        let mut selector = [0u8; XFRM_SELECTOR_LEN];
        selector
            .copy_from_slice(SelectorBuffer::from(&value.selector).as_bytes());
        let mut id = [0u8; XFRM_ID_LEN];
        id.copy_from_slice(IdBuffer::from(&value.id).as_bytes());
        let mut saddr = [0u8; XFRM_ADDRESS_LEN];
        saddr.copy_from_slice(AddressBuffer::from(&value.saddr).as_bytes());
        let mut lifetime_cfg = [0u8; XFRM_LIFETIME_CONFIG_LEN];
        lifetime_cfg.copy_from_slice(
            LifetimeConfigBuffer::from(&value.lifetime_cfg).as_bytes(),
        );
        let mut lifetime_cur = [0u8; XFRM_LIFETIME_LEN];
        lifetime_cur.copy_from_slice(
            LifetimeBuffer::from(&value.lifetime_cur).as_bytes(),
        );
        let mut stats = [0u8; XFRM_STATS_LEN];
        stats.copy_from_slice(StatsBuffer::from(&value.stats).as_bytes());
        Self {
            selector,
            id,
            saddr,
            lifetime_cfg,
            lifetime_cur,
            stats,
            seq: value.seq,
            reqid: value.reqid,
            family: value.family,
            mode: value.mode,
            replay_window: value.replay_window,
            flags: value.flags,
            padding: [0; 7],
        }
    }
}

impl Emitable for UserSaInfo {
    fn buffer_len(&self) -> usize {
        size_of::<UserSaInfoBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = UserSaInfoBuffer::from(self);
        buffer[..size_of::<UserSaInfoBuffer>()].copy_from_slice(raw.as_bytes());
    }
}

impl UserSaInfo {
    fn family(&mut self, addr: &IpAddr) {
        if addr.is_ipv4() {
            self.family = AF_INET;
        } else if addr.is_ipv6() {
            self.family = AF_INET6;
        }
    }
    pub fn source(&mut self, addr: &IpAddr) {
        self.saddr = Address::from_ip(addr);
        self.family(addr);
    }
    pub fn destination(&mut self, addr: &IpAddr) {
        self.id.daddr = Address::from_ip(addr);
        self.family(addr);
    }
}
