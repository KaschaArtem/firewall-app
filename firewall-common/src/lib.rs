#![no_std]

mod mode;
mod event;

pub use mode::{
    MODE_ALL_DROP, MODE_ALL_PASS, MODE_DEFAULT_DROP, MODE_DEFAULT_PASS,
};
pub use event::{
    PacketDecisionEvent, ACTION_DROP, ACTION_PASS, DIRECTION_EGRESS, DIRECTION_INGRESS,
    FAMILY_IPV4, FAMILY_IPV6, REASON_ALL_DROP, REASON_ALL_PASS, REASON_BLACKLIST,
    REASON_DEFAULT, REASON_NON_IP, REASON_WHITELIST,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub struct IpAddress {
    pub family: u8,
    pub addr: [u8; 16],
}

impl IpAddress {
    pub const fn ipv4(octets: [u8; 4]) -> Self {
        Self {
            family: 4,
            addr: [
                octets[0], octets[1], octets[2], octets[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        }
    }

    pub const fn ipv6(octets: [u8; 16]) -> Self {
        Self {
            family: 6,
            addr: octets,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for IpAddress {}
