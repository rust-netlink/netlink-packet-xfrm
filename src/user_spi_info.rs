// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable, ErrorContext};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    constants::IPPROTO_COMP, UserSaInfo, UserSaInfoBuffer,
    XFRM_USER_SA_INFO_LEN,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct UserSpiInfo {
    pub info: UserSaInfo,
    pub min: u32,
    pub max: u32,
}

pub const XFRM_USER_SPI_INFO_LEN: usize = 232;

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
pub struct UserSpiInfoBuffer {
    info: [u8; XFRM_USER_SA_INFO_LEN],
    min: u32,
    max: u32,
}

impl Default for UserSpiInfo {
    // Set the same default ranges as iproute2
    fn default() -> Self {
        UserSpiInfo {
            info: UserSaInfo::default(),
            min: 0x100,
            max: 0x0fffffff,
        }
    }
}

impl UserSpiInfo {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            UserSpiInfoBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<UserSpiInfoBuffer>(),
                )
            })?;
        let info = UserSaInfo::parse(&raw.info[..])
            .context("failed to parse user sa info")?;
        Ok(Self {
            info,
            min: raw.min,
            max: raw.max,
        })
    }
}

impl From<&UserSpiInfo> for UserSpiInfoBuffer {
    fn from(value: &UserSpiInfo) -> Self {
        let mut info = [0u8; XFRM_USER_SA_INFO_LEN];
        info.copy_from_slice(UserSaInfoBuffer::from(&value.info).as_bytes());
        Self {
            info,
            min: value.min,
            max: value.max,
        }
    }
}

impl Emitable for UserSpiInfo {
    fn buffer_len(&self) -> usize {
        size_of::<UserSpiInfoBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = UserSpiInfoBuffer::from(self);
        buffer[..size_of::<UserSpiInfoBuffer>()]
            .copy_from_slice(raw.as_bytes());
    }
}

impl UserSpiInfo {
    pub fn protocol(&mut self, protocol: u8) {
        self.info.id.proto = protocol;
        // IPPROTO_COMP spi is 16-bit
        if (protocol == IPPROTO_COMP) && (self.max > 0xffff) {
            self.max = 0xffff;
        }
    }
    pub fn spi_range(&mut self, spi_min: u32, spi_max: u32) {
        self.min = spi_min;
        if (self.info.id.proto == IPPROTO_COMP) && (spi_max > 0xffff) {
            self.max = 0xffff;
        } else {
            self.max = spi_max;
        }
    }
}
