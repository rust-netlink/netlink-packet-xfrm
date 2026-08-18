// SPDX-License-Identifier: MIT

use core::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable, ErrorContext, Parseable};

use crate::{nlas::VecXfrmAttrs, UserReport, UserReportBuffer, XfrmAttrs};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct ReportMessage {
    pub report: UserReport,
    pub nlas: Vec<XfrmAttrs>,
}

impl Emitable for ReportMessage {
    fn buffer_len(&self) -> usize {
        self.report.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.report.emit(buffer);
        self.nlas
            .as_slice()
            .emit(&mut buffer[self.report.buffer_len()..]);
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
