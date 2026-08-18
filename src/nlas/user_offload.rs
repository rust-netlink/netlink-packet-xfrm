// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserOffloadDev {
    pub ifindex: i32, /* "int" in iproute2 */
    pub flags: u8,
}

pub const XFRM_USER_OFFLOAD_DEV_LEN: usize = 8;

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
pub struct UserOffloadDevBuffer {
    ifindex: i32,
    flags: u8,
    padding: [u8; 3],
}

impl UserOffloadDev {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            UserOffloadDevBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<UserOffloadDevBuffer>(),
                )
            })?;
        Ok(Self {
            ifindex: raw.ifindex,
            flags: raw.flags,
        })
    }
}

impl From<&UserOffloadDev> for UserOffloadDevBuffer {
    fn from(value: &UserOffloadDev) -> Self {
        Self {
            ifindex: value.ifindex,
            flags: value.flags,
            padding: [0; 3],
        }
    }
}

impl Emitable for UserOffloadDev {
    fn buffer_len(&self) -> usize {
        size_of::<UserOffloadDevBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = UserOffloadDevBuffer::from(self);
        buffer[..size_of::<UserOffloadDevBuffer>()]
            .copy_from_slice(raw.as_bytes());
    }
}
