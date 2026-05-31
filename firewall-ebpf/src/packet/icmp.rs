//! ICMP and ICMPv6 type parsing and classification.

use firewall_common::{
    ICMP_CLASS_CONTROL, ICMP_CLASS_ECHO, ICMP_CLASS_NONE, ICMP_CLASS_OTHER,
    ICMP_CLASS_TRACEROUTE,
};

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;

#[inline(always)]
fn classify_icmpv4(typ: u8, code: u8) -> u8 {
    match typ {
        0 | 8 => ICMP_CLASS_ECHO,
        11 => ICMP_CLASS_TRACEROUTE,
        3 => match code {
            3 | 4 => ICMP_CLASS_TRACEROUTE,
            _ => ICMP_CLASS_CONTROL,
        },
        5 | 9 | 10 | 12 | 13 | 14 | 15 | 17 | 18 => ICMP_CLASS_CONTROL,
        _ => ICMP_CLASS_OTHER,
    }
}

#[inline(always)]
fn classify_icmpv6(typ: u8, code: u8) -> u8 {
    match typ {
        128 | 129 => ICMP_CLASS_ECHO,
        3 => ICMP_CLASS_TRACEROUTE,
        1 => match code {
            4 => ICMP_CLASS_TRACEROUTE,
            _ => ICMP_CLASS_CONTROL,
        },
        2 | 4 => ICMP_CLASS_CONTROL,
        _ => ICMP_CLASS_OTHER,
    }
}

#[inline(always)]
pub fn classify_icmp(proto: u8, typ: u8, code: u8) -> u8 {
    match proto {
        IPPROTO_ICMP => classify_icmpv4(typ, code),
        IPPROTO_ICMPV6 => classify_icmpv6(typ, code),
        _ => ICMP_CLASS_NONE,
    }
}
