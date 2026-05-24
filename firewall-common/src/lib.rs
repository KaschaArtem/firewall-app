#![no_std]

pub const MODE_ALL_PASS: u32 = 0;
pub const MODE_ALL_DROP: u32 = 1;
pub const MODE_DEFAULT_PASS: u32 = 2;
pub const MODE_DEFAULT_DROP: u32 = 3;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PacketDecisionEvent {
    pub ts_ns: u64,
    pub action: u8,
    pub family: u8,
    pub reason: u8,
    pub direction: u8,
    /// IANA IP protocol number (6 = TCP, 17 = UDP, 1 = ICMP, …); 0 if unknown.
    pub protocol: u8,
    pub _pad: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub src: [u8; 16],
    pub dst: [u8; 16],
}

pub const ACTION_PASS: u8 = 0;
pub const ACTION_DROP: u8 = 1;

pub const DIRECTION_INGRESS: u8 = 0;
pub const DIRECTION_EGRESS: u8 = 1;

/// LPM trie value: which packet directions this list entry applies to.
pub const LIST_DIR_INGRESS: u8 = 1 << DIRECTION_INGRESS;
pub const LIST_DIR_EGRESS: u8 = 1 << DIRECTION_EGRESS;
pub const LIST_DIR_BOTH: u8 = LIST_DIR_INGRESS | LIST_DIR_EGRESS;

#[inline(always)]
pub const fn list_applies_to_direction(list_dirs: u8, packet_direction: u8) -> bool {
    list_dirs & (1 << packet_direction) != 0
}

pub const REASON_ALL_PASS: u8 = 0;
pub const REASON_ALL_DROP: u8 = 1;
pub const REASON_BLACKLIST: u8 = 2;
pub const REASON_WHITELIST: u8 = 3;
pub const REASON_DEFAULT: u8 = 4;
pub const REASON_NON_IP: u8 = 5;

pub const FAMILY_IPV4: u8 = 4;
pub const FAMILY_IPV6: u8 = 6;

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketDecisionEvent {}

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
