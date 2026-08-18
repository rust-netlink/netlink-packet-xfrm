// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable, ErrorContext, Parseable};

use crate::{UserExpire, UserExpireBuffer};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct ExpireMessage {
    pub expire: UserExpire,
}

impl Emitable for ExpireMessage {
    fn buffer_len(&self) -> usize {
        self.expire.buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.expire.emit(buffer);
    }
}

impl Parseable<[u8]> for ExpireMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let expire = UserExpire::parse(&buf[..size_of::<UserExpireBuffer>()])
            .context("failed to parse monitor expire message info")?;
        Ok(Self { expire })
    }
}
