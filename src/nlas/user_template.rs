// SPDX-License-Identifier: MIT

use std::{mem::size_of, net::IpAddr};

use netlink_packet_core::{DecodeError, Emitable, ErrorContext};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    constants::{AF_INET, AF_INET6},
    Address, AddressBuffer, Id, IdBuffer, XFRM_ADDRESS_LEN, XFRM_ID_LEN,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct UserTemplate {
    pub id: Id,
    pub family: u16,
    pub saddr: Address,
    pub reqid: u32,
    pub mode: u8,
    pub share: u8,
    pub optional: u8,
    pub aalgos: u32,
    pub ealgos: u32,
    pub calgos: u32,
}

pub const XFRM_USER_TEMPLATE_LEN: usize = 64;

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
pub struct UserTemplateBuffer {
    id: [u8; XFRM_ID_LEN],
    family: u16,
    padding1: [u8; 2],
    saddr: [u8; XFRM_ADDRESS_LEN],
    reqid: u32,
    mode: u8,
    share: u8,
    optional: u8,
    padding2: [u8; 1],
    aalgos: u32,
    ealgos: u32,
    calgos: u32,
}

impl Default for UserTemplate {
    fn default() -> Self {
        UserTemplate {
            id: Id::default(),
            family: 0,
            saddr: Address::default(),
            reqid: 0,
            mode: 0,
            share: 0,
            optional: 0,
            aalgos: u32::MAX,
            ealgos: u32::MAX,
            calgos: u32::MAX,
        }
    }
}

impl UserTemplate {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            UserTemplateBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<UserTemplateBuffer>(),
                )
            })?;
        let id = Id::parse(&raw.id[..])
            .context("failed to parse Id in UserTemplate")?;
        let saddr = Address::parse(&raw.saddr[..])
            .context("failed to parse Address in UserTemplate")?;
        Ok(Self {
            id,
            family: raw.family,
            saddr,
            reqid: raw.reqid,
            mode: raw.mode,
            share: raw.share,
            optional: raw.optional,
            aalgos: raw.aalgos,
            ealgos: raw.ealgos,
            calgos: raw.calgos,
        })
    }
}

impl From<&UserTemplate> for UserTemplateBuffer {
    fn from(value: &UserTemplate) -> Self {
        let mut id = [0u8; XFRM_ID_LEN];
        id.copy_from_slice(IdBuffer::from(&value.id).as_bytes());
        let mut saddr = [0u8; XFRM_ADDRESS_LEN];
        saddr.copy_from_slice(AddressBuffer::from(&value.saddr).as_bytes());
        Self {
            id,
            family: value.family,
            padding1: [0; 2],
            saddr,
            reqid: value.reqid,
            mode: value.mode,
            share: value.share,
            optional: value.optional,
            padding2: [0; 1],
            aalgos: value.aalgos,
            ealgos: value.ealgos,
            calgos: value.calgos,
        }
    }
}

impl Emitable for UserTemplate {
    fn buffer_len(&self) -> usize {
        size_of::<UserTemplateBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = UserTemplateBuffer::from(self);
        buffer[..size_of::<UserTemplateBuffer>()]
            .copy_from_slice(raw.as_bytes());
    }
}

impl UserTemplate {
    fn family(&mut self, addr: &IpAddr) {
        if addr.is_ipv4() {
            self.family = AF_INET;
        } else if addr.is_ipv6() {
            self.family = AF_INET6;
        }
    }

    /// Sets the source address. Automatically sets the
    /// family to AF_INET or AF_INET6 depending on the type of
    /// the address. The source and destination addresses
    /// should be the same type.
    pub fn source(&mut self, addr: &IpAddr) {
        self.saddr = Address::from_ip(addr);
        self.family(addr);
    }

    /// Sets the destination address. Automatically sets the
    /// family to AF_INET or AF_INET6 depending on the type of
    /// the address. The source and destination addresses
    /// should be the same type.
    pub fn destination(&mut self, addr: &IpAddr) {
        self.id.daddr = Address::from_ip(addr);
        self.family(addr);
    }

    /// Sets the transform protocol. Should be one of:
    ///   IPPROTO_ESP (50)
    ///   IPPROTO_AH (51)
    ///   PPROTO_COMP (108)
    ///   IPPROTO_ROUTING (43)
    ///   IPPROTO_DSTOPTS (60)
    ///   IPSEC_PROTO_ANY (255)
    pub fn protocol(&mut self, proto: u8) {
        self.id.proto = proto;
    }

    /// Sets the transform mode. Should be one of:
    ///   XFRM_MODE_TRANSPORT (0)
    ///   XFRM_MODE_TUNNEL (1)
    ///   XFRM_MODE_ROUTEOPTIMIZATION (2)
    ///   XFRM_MODE_IN_TRIGGER (3)
    ///   XFRM_MODE_BEET (4)
    pub fn mode(&mut self, mode: u8) {
        self.mode = mode;
    }

    /// Sets the SPI.
    pub fn spi(&mut self, spi: u32) {
        self.id.spi = spi;
    }

    /// Set true to make the use of this template optional.
    /// The default is false (required).
    pub fn optional(&mut self, optional: bool) {
        self.optional = if optional { 1 } else { 0 };
    }

    pub fn reqid(&mut self, reqid: u32) {
        self.reqid = reqid;
    }
}
