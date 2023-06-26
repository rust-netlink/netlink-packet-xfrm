// SPDX-License-Identifier: MIT

use anyhow::Context;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use core::ops::Range;

use crate::{
    constants::IPPROTO_COMP, UserSaInfo, UserSaInfoBuffer,
    XFRM_USER_SA_INFO_LEN,
};

use netlink_packet_utils::{buffer, traits::*, DecodeError};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UserSpiInfo {
    pub info: UserSaInfo,
    pub min: u32,
    pub max: u32,
}

const INFO_FIELD: Range<usize> = 0..XFRM_USER_SA_INFO_LEN;
const MIN_FIELD: Range<usize> = INFO_FIELD.end..(INFO_FIELD.end + 4);
const MAX_FIELD: Range<usize> = MIN_FIELD.end..(MIN_FIELD.end + 4);

pub const XFRM_USER_SPI_INFO_LEN: usize = (MAX_FIELD.end + 7) & !7; // 232

buffer!(UserSpiInfoBuffer(XFRM_USER_SPI_INFO_LEN) {
    info: (slice, INFO_FIELD),
    min: (u32, MIN_FIELD),
    max: (u32, MAX_FIELD)
});

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

impl<T: AsRef<[u8]> + ?Sized> Parseable<UserSpiInfoBuffer<&T>> for UserSpiInfo {
    fn parse(buf: &UserSpiInfoBuffer<&T>) -> Result<Self, DecodeError> {
        let info = UserSaInfo::parse(&UserSaInfoBuffer::new(&buf.info()))
            .context("failed to parse user sa info")?;
        Ok(UserSpiInfo {
            info,
            min: buf.min(),
            max: buf.max(),
        })
    }
}

impl Emitable for UserSpiInfo {
    fn buffer_len(&self) -> usize {
        XFRM_USER_SPI_INFO_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = UserSpiInfoBuffer::new(buffer);
        self.info.emit(buffer.info_mut());
        buffer.set_min(self.min);
        buffer.set_max(self.max);
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
