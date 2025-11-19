// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, NlaBuffer, NlasIterator};

use crate::XFRM_USER_ACQUIRE_LEN;

pub const MONITOR_ACQUIRE_HEADER_LEN: usize = XFRM_USER_ACQUIRE_LEN;

buffer!(AcquireMessageBuffer(MONITOR_ACQUIRE_HEADER_LEN) {
    acquire: (slice, 0..MONITOR_ACQUIRE_HEADER_LEN),
    attributes: (slice, MONITOR_ACQUIRE_HEADER_LEN..)
});

impl<'a, T: AsRef<[u8]> + ?Sized> AcquireMessageBuffer<&'a T> {
    pub fn nlas(
        &self,
    ) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.attributes())
    }
}
