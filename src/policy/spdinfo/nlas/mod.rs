// SPDX-License-Identifier: MIT

pub mod spd_info;
use netlink_packet_core::{
    append_bytes, DecodeError, DefaultNla, Emitable, EncodeError, ErrorContext,
    Nla, NlaBuffer, NlasIterator, Parseable,
};
pub use spd_info::*;

use crate::constants::*;

pub(crate) struct VecSpdInfoAttrs(pub(crate) Vec<SpdInfoAttrs>);

impl Parseable<[u8]> for VecSpdInfoAttrs {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in NlasIterator::new(buf)? {
            nlas.push(SpdInfoAttrs::parse(&nla_buf)?);
        }
        Ok(Self(nlas))
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SpdInfoAttrs {
    Unspec(Vec<u8>),
    SpdInfo(spd_info::SpdInfo),
    SpdHInfo(spd_info::SpdHInfo),
    SpdIpv4HThresh(spd_info::SpdHThresh),
    SpdIpv6HThresh(spd_info::SpdHThresh),
    Other(DefaultNla),
}

impl Nla for SpdInfoAttrs {
    #[rustfmt::skip]
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        use self::SpdInfoAttrs::*;
        match *self {
            Unspec(ref bytes) => append_bytes(out, bytes.as_slice()),
            SpdInfo(ref v) => v.emit(out)?,
            SpdHInfo(ref v) => v.emit(out)?,
            SpdIpv4HThresh(ref v) => v.emit(out)?,
            SpdIpv6HThresh(ref v) => v.emit(out)?,
            Other(ref attr) => return attr.emit_value(out),
        }
        Ok(())

    }

    fn kind(&self) -> u16 {
        use self::SpdInfoAttrs::*;
        match *self {
            Unspec(_) => XFRMA_SPD_UNSPEC,
            SpdInfo(_) => XFRMA_SPD_INFO,
            SpdHInfo(_) => XFRMA_SPD_HINFO,
            SpdIpv4HThresh(_) => XFRMA_SPD_IPV4_HTHRESH,
            SpdIpv6HThresh(_) => XFRMA_SPD_IPV6_HTHRESH,
            Other(ref nla) => nla.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for SpdInfoAttrs {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        use self::SpdInfoAttrs::*;
        let payload = buf.value();
        Ok(match buf.kind() {
            XFRMA_SPD_UNSPEC => Unspec(payload.to_vec()),
            XFRMA_SPD_INFO => SpdInfo(
                spd_info::SpdInfo::parse(payload)
                    .context("invalid XFRMA_SPD_INFO")?,
            ),
            XFRMA_SPD_HINFO => SpdHInfo(
                spd_info::SpdHInfo::parse(payload)
                    .context("invalid XFRMA_SPD_HINFO")?,
            ),
            XFRMA_SPD_IPV4_HTHRESH => SpdIpv4HThresh(
                spd_info::SpdHThresh::parse(payload)
                    .context("invalid XFRMA_SPD_IPV4_HTHRESH")?,
            ),
            XFRMA_SPD_IPV6_HTHRESH => SpdIpv6HThresh(
                spd_info::SpdHThresh::parse(payload)
                    .context("invalid XFRMA_SPD_IPV6_HTHRESH")?,
            ),
            kind => Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}
