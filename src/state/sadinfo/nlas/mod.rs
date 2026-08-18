// SPDX-License-Identifier: MIT

pub mod sad_info;
use std::mem::size_of;

use netlink_packet_core::{
    emit_u32, parse_u32, DecodeError, DefaultNla, Emitable, ErrorContext, Nla,
    NlaBuffer, NlasIterator, Parseable,
};
pub use sad_info::*;

use crate::constants::*;

pub(crate) struct VecSadInfoAttrs(pub(crate) Vec<SadInfoAttrs>);

impl Parseable<[u8]> for VecSadInfoAttrs {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in NlasIterator::new(buf) {
            nlas.push(SadInfoAttrs::parse(&nla_buf?)?);
        }
        Ok(Self(nlas))
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SadInfoAttrs {
    Unspec(Vec<u8>),
    SadCount(u32),
    SadHInfo(sad_info::SadHInfo),
    Other(DefaultNla),
}

impl Nla for SadInfoAttrs {
    #[rustfmt::skip]
    fn value_len(&self) -> usize {
        use self::SadInfoAttrs::*;
        match *self {
            Unspec(ref bytes) => bytes.len(),
            SadCount(_) => size_of::<u32>(),
            SadHInfo(ref v) => v.buffer_len(),
            Other(ref attr)  => attr.value_len(),
        }
    }

    #[rustfmt::skip]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::SadInfoAttrs::*;
        match *self {
            Unspec(ref bytes) => buffer.copy_from_slice(bytes.as_slice()),
            SadCount(ref value) => emit_u32(buffer, *value).unwrap(),
            SadHInfo(ref v) => v.emit(buffer),
            Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::SadInfoAttrs::*;
        match *self {
            Unspec(_) => XFRMA_SAD_UNSPEC,
            SadCount(_) => XFRMA_SAD_CNT,
            SadHInfo(_) => XFRMA_SAD_HINFO,
            Other(ref nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for SadInfoAttrs {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        use self::SadInfoAttrs::*;
        let payload = buf.value();
        Ok(match buf.kind() {
            XFRMA_SAD_UNSPEC => Unspec(payload.to_vec()),
            XFRMA_SAD_CNT => SadCount(
                parse_u32(payload).context("invalid XFRMA_SAD_CNT value")?,
            ),
            XFRMA_SAD_HINFO => SadHInfo(
                sad_info::SadHInfo::parse(payload)
                    .context("invalid XFRMA_SAD_HINFO")?,
            ),
            kind => Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}
