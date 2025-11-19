// SPDX-License-Identifier: MIT

use netlink_packet_core::{buffer, DecodeError, NlaBuffer, NlasIterator};

use crate::XFRM_ASYNC_EVENT_ID_LEN;

pub const MONITOR_NEW_ASYNC_EVENT_HEADER_LEN: usize = XFRM_ASYNC_EVENT_ID_LEN;

buffer!(NewAsyncEventMessageBuffer(MONITOR_NEW_ASYNC_EVENT_HEADER_LEN) {
    id: (slice, 0..MONITOR_NEW_ASYNC_EVENT_HEADER_LEN),
    attributes: (slice, MONITOR_NEW_ASYNC_EVENT_HEADER_LEN..)
});

impl<'a, T: AsRef<[u8]> + ?Sized> NewAsyncEventMessageBuffer<&'a T> {
    pub fn nlas(
        &self,
    ) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.attributes())
    }
}
