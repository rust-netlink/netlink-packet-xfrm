// SPDX-License-Identifier: MIT

use netlink_packet_core::buffer;

use crate::XFRM_USER_MAPPING_LEN;

pub const MONITOR_MAPPING_HEADER_LEN: usize = XFRM_USER_MAPPING_LEN;

buffer!(MappingMessageBuffer(MONITOR_MAPPING_HEADER_LEN) {
    map: (slice, 0..MONITOR_MAPPING_HEADER_LEN)
});
