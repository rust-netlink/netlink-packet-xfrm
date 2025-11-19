// SPDX-License-Identifier: MIT

use netlink_packet_core::{buffer, DecodeError, NlaBuffer, NlasIterator};

use crate::XFRM_USER_POLICY_ID_LEN;

// Same buffer handles policy delete and get messages

pub const POLICY_DELGET_HEADER_LEN: usize = XFRM_USER_POLICY_ID_LEN;

buffer!(DelGetMessageBuffer(POLICY_DELGET_HEADER_LEN) {
    user_policy_id: (slice, 0..POLICY_DELGET_HEADER_LEN),
    attributes: (slice, POLICY_DELGET_HEADER_LEN..)
});

impl<'a, T: AsRef<[u8]> + ?Sized> DelGetMessageBuffer<&'a T> {
    pub fn nlas(
        &self,
    ) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.attributes())
    }
}
