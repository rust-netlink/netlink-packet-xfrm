// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable, ErrorContext};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    Address, AddressBuffer, Id, IdBuffer, Selector, SelectorBuffer,
    UserPolicyInfo, UserPolicyInfoBuffer, XFRM_ADDRESS_LEN, XFRM_ID_LEN,
    XFRM_SELECTOR_LEN, XFRM_USER_POLICY_INFO_LEN,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserAcquire {
    pub id: Id,
    pub saddr: Address,
    pub selector: Selector,
    pub policy: UserPolicyInfo,
    pub aalgos: u32,
    pub ealgos: u32,
    pub calgos: u32,
    pub seq: u32,
}

pub const XFRM_USER_ACQUIRE_LEN: usize = 280;

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
pub struct UserAcquireBuffer {
    id: [u8; XFRM_ID_LEN],
    saddr: [u8; XFRM_ADDRESS_LEN],
    selector: [u8; XFRM_SELECTOR_LEN],
    policy: [u8; XFRM_USER_POLICY_INFO_LEN],
    aalgos: u32,
    ealgos: u32,
    calgos: u32,
    seq: u32,
}

impl UserAcquire {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            UserAcquireBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<UserAcquireBuffer>(),
                )
            })?;
        let id = Id::parse(&raw.id[..]).context("failed to parse id")?;
        let saddr =
            Address::parse(&raw.saddr[..]).context("failed to parse saddr")?;
        let selector = Selector::parse(&raw.selector[..])
            .context("failed to parse selector")?;
        let policy = UserPolicyInfo::parse(&raw.policy[..])
            .context("failed to parse policy")?;
        Ok(Self {
            id,
            saddr,
            selector,
            policy,
            aalgos: raw.aalgos,
            ealgos: raw.ealgos,
            calgos: raw.calgos,
            seq: raw.seq,
        })
    }
}

impl From<&UserAcquire> for UserAcquireBuffer {
    fn from(value: &UserAcquire) -> Self {
        let mut id = [0u8; XFRM_ID_LEN];
        id.copy_from_slice(IdBuffer::from(&value.id).as_bytes());
        let mut saddr = [0u8; XFRM_ADDRESS_LEN];
        saddr.copy_from_slice(AddressBuffer::from(&value.saddr).as_bytes());
        let mut selector = [0u8; XFRM_SELECTOR_LEN];
        selector
            .copy_from_slice(SelectorBuffer::from(&value.selector).as_bytes());
        let mut policy = [0u8; XFRM_USER_POLICY_INFO_LEN];
        policy.copy_from_slice(
            UserPolicyInfoBuffer::from(&value.policy).as_bytes(),
        );
        Self {
            id,
            saddr,
            selector,
            policy,
            aalgos: value.aalgos,
            ealgos: value.ealgos,
            calgos: value.calgos,
            seq: value.seq,
        }
    }
}

impl Emitable for UserAcquire {
    fn buffer_len(&self) -> usize {
        size_of::<UserAcquireBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = UserAcquireBuffer::from(self);
        buffer[..size_of::<UserAcquireBuffer>()]
            .copy_from_slice(raw.as_bytes());
    }
}
