// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable, ErrorContext};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{Selector, SelectorBuffer, XFRM_SELECTOR_LEN};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserReport {
    pub proto: u8,
    pub selector: Selector,
}

pub const XFRM_USER_REPORT_LEN: usize = 60;

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
pub struct UserReportBuffer {
    proto: u8,
    padding: [u8; 3],
    selector: [u8; XFRM_SELECTOR_LEN],
}

impl UserReport {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            UserReportBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<UserReportBuffer>(),
                )
            })?;
        let selector = Selector::parse(&raw.selector[..])
            .context("failed to parse selector")?;
        Ok(Self {
            proto: raw.proto,
            selector,
        })
    }
}

impl From<&UserReport> for UserReportBuffer {
    fn from(value: &UserReport) -> Self {
        let mut selector = [0u8; XFRM_SELECTOR_LEN];
        selector
            .copy_from_slice(SelectorBuffer::from(&value.selector).as_bytes());
        Self {
            proto: value.proto,
            padding: [0; 3],
            selector,
        }
    }
}

impl Emitable for UserReport {
    fn buffer_len(&self) -> usize {
        size_of::<UserReportBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = UserReportBuffer::from(self);
        buffer[..size_of::<UserReportBuffer>()].copy_from_slice(raw.as_bytes());
    }
}
