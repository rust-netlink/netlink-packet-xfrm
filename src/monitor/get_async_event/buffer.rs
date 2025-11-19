// SPDX-License-Identifier: MIT

use netlink_packet_core::buffer;

use crate::XFRM_ASYNC_EVENT_ID_LEN;

pub const MONITOR_GET_ASYNC_EVENT_HEADER_LEN: usize = XFRM_ASYNC_EVENT_ID_LEN;

buffer!(GetAsyncEventMessageBuffer(MONITOR_GET_ASYNC_EVENT_HEADER_LEN) {
    id: (slice, 0..MONITOR_GET_ASYNC_EVENT_HEADER_LEN)
});
