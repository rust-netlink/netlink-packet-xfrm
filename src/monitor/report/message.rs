// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, ErrorContext, Parseable,
};

use crate::{nlas::VecXfrmAttrs, UserReport, UserReportBuffer, XfrmAttrs};
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct ReportMessage {
    pub report: UserReport,
    pub nlas: Vec<XfrmAttrs>,
}

impl Emitable for ReportMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.report.emit(out)?;
        self.nlas.as_slice().emit(out)?;
        Ok(())
    }
}

impl Parseable<[u8]> for ReportMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let report = UserReport::parse(&buf[..size_of::<UserReportBuffer>()])
            .context("failed to parse monitor acquire message info")?;
        Ok(Self {
            report,
            nlas: VecXfrmAttrs::parse(&buf[size_of::<UserReportBuffer>()..])
                .context("failed to parse monitor report message NLAs")?
                .0,
        })
    }
}
