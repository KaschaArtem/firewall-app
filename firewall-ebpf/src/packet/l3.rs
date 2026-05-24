//! L3 parsing: Ethernet demux, IPv4/IPv6 headers, and a unified `L3Packet` view.

use aya_ebpf::programs::TcContext;
use firewall_common::{FAMILY_IPV4, FAMILY_IPV6};
use network_types::{
    eth::EthHdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
};

use super::{ptr_at, PacketData, PortReader};

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;

/// L4 parse lives in this module (same compilation unit as L3) so the verifier keeps packet bounds.

#[derive(Clone, Copy, Default)]
pub struct L4Info {
    pub protocol: u8,
    pub src_port: u16,
    pub dst_port: u16,
}

/// Result of L3 demux + sanity checks.
#[derive(Clone, Copy)]
pub enum L3ParseOutcome {
    Packet(L3Packet),
    /// Not IPv4/IPv6 (or unknown L3 on TC).
    NotIp,
    /// Failed version, length, or IPv4 header checksum checks.
    Invalid { family: u8 },
}

const IPV4_HDR_LEN: usize = 20;
const IPV6_HDR_LEN: usize = 40;
const IPV4_MAX_HDR_LEN: usize = 60;
/// Max IPv4 header words for checksum loop (verifier needs a fixed bound).
const IPV4_MAX_HDR_WORDS: usize = IPV4_MAX_HDR_LEN / 2;

#[inline(always)]
fn packet_span<C: PacketData>(ctx: &C) -> usize {
    ctx.data_end().saturating_sub(ctx.data())
}

#[inline(always)]
fn ipv4_checksum_ok<C: PortReader>(ctx: &C, l3_offset: usize, ihl: usize) -> bool {
    if ihl < IPV4_HDR_LEN || ihl > IPV4_MAX_HDR_LEN || (ihl & 3) != 0 {
        return false;
    }

    let mut sum: u32 = 0;
    let mut word = 0usize;
    while word < IPV4_MAX_HDR_WORDS {
        let off = word * 2;
        if off >= ihl {
            break;
        }
        let Some(w) = ctx.read_u16_be(l3_offset + off) else {
            return false;
        };
        sum = sum.wrapping_add(u32::from(w));
        word += 1;
    }

    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    sum == 0xffff
}

#[inline(always)]
fn validate_ipv4_header<C: PacketData + PortReader>(ctx: &C, l3_offset: usize) -> bool {
    let Some(vihl) = ctx.read_u8(l3_offset) else {
        return false;
    };
    let version = vihl >> 4;
    let ihl_words = (vihl & 0x0f) as usize;
    if version != 4 || ihl_words < 5 || ihl_words > 15 {
        return false;
    }
    let ihl = ihl_words * 4;

    let Some(total_len) = ctx.read_u16_be(l3_offset + 2) else {
        return false;
    };
    let total_len = total_len as usize;
    if total_len < ihl {
        return false;
    }

    let end = ctx.data_end();
    if l3_offset.saturating_add(total_len) > end {
        return false;
    }

    // `total_len` must fit in the captured buffer starting at L3.
    let span = packet_span(ctx);
    if l3_offset >= span || total_len > span.saturating_sub(l3_offset) {
        return false;
    }

    if l3_offset.saturating_add(ihl) > end {
        return false;
    }

    // Offset 10: header checksum. Zero is common with RX checksum offload — skip verify then.
    let hdr_csum = ctx.read_u16_be(l3_offset + 10).unwrap_or(0);
    if hdr_csum == 0 {
        return true;
    }

    ipv4_checksum_ok(ctx, l3_offset, ihl)
}

#[inline(always)]
fn validate_ipv6_header<C: PacketData + PortReader>(ctx: &C, l3_offset: usize) -> bool {
    let Some(first) = ctx.read_u8(l3_offset) else {
        return false;
    };
    if first >> 4 != 6 {
        return false;
    }

    let Some(payload_len) = ctx.read_u16_be(l3_offset + 4) else {
        return false;
    };
    let payload_len = payload_len as usize;
    let total_len = IPV6_HDR_LEN.saturating_add(payload_len);

    let end = ctx.data_end();
    if l3_offset.saturating_add(total_len) > end {
        return false;
    }

    let span = packet_span(ctx);
    if l3_offset >= span || total_len > span.saturating_sub(l3_offset) {
        return false;
    }

    true
}

#[inline(always)]
fn read_l4<C: PacketData + PortReader>(ctx: &C, l4_offset: usize, proto: u8) -> L4Info {
    if !ctx.uses_skb_load() && !l4_fits(ctx, l4_offset, proto) {
        return L4Info {
            protocol: proto,
            src_port: 0,
            dst_port: 0,
        };
    }

    match proto {
        IPPROTO_TCP | IPPROTO_UDP => L4Info {
            protocol: proto,
            src_port: ctx.read_u16_be(l4_offset).unwrap_or(0),
            dst_port: ctx.read_u16_be(l4_offset + 2).unwrap_or(0),
        },
        IPPROTO_ICMP | IPPROTO_ICMPV6 => L4Info {
            protocol: proto,
            src_port: ctx.read_u8(l4_offset).unwrap_or(0) as u16,
            dst_port: ctx.read_u8(l4_offset + 1).unwrap_or(0) as u16,
        },
        _ => L4Info {
            protocol: proto,
            src_port: 0,
            dst_port: 0,
        },
    }
}

#[inline(always)]
fn l4_need_bytes(proto: u8) -> usize {
    match proto {
        IPPROTO_TCP | IPPROTO_UDP => 4,
        IPPROTO_ICMP | IPPROTO_ICMPV6 => 2,
        _ => 0,
    }
}

#[inline(always)]
fn l4_fits<C: PacketData>(ctx: &C, l4_offset: usize, proto: u8) -> bool {
    let need = l4_need_bytes(proto);
    if need == 0 {
        return true;
    }
    let start = ctx.data();
    let end = ctx.data_end();
    start.saturating_add(l4_offset).saturating_add(need) <= end
}

/// Parsed IPv4 header — extend here for TTL, DSCP, fragmentation checks, etc.
#[derive(Clone, Copy)]
pub struct Ipv4Packet {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub l4: L4Info,
}


impl Ipv4Packet {
    #[inline(always)]
    pub fn family(&self) -> u8 {
        FAMILY_IPV4
    }

    /// Parse IPv4 at `l3_offset` (start of the IPv4 header).
    #[inline(always)]
    pub fn parse_at<C: PacketData + PortReader>(
        ctx: &C,
        l3_offset: usize,
    ) -> Result<Option<Self>, u32> {
        let _ = unsafe { ptr_at::<_, Ipv4Hdr>(ctx, l3_offset)? };
        if !validate_ipv4_header(ctx, l3_offset) {
            return Ok(None);
        }

        let ip_hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_offset)? };

        let src = u32::from_be(unsafe { (*ip_hdr).src_addr }).to_be_bytes();
        let dst = u32::from_be(unsafe { (*ip_hdr).dst_addr }).to_be_bytes();

        let ihl = ipv4_header_len(ctx, l3_offset);
        let l4_offset = l3_offset.saturating_add(ihl);
        let proto = ctx.read_u8(l3_offset.saturating_add(9)).unwrap_or(0);
        let l4 = read_l4(ctx, l4_offset, proto);

        Ok(Some(Self { src, dst, l4 }))
    }
}

/// Parsed IPv6 header — extend here for flow label, hop limit, extension headers, etc.
#[derive(Clone, Copy)]
pub struct Ipv6Packet {
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub l4: L4Info,
}

impl Ipv6Packet {
    #[inline(always)]
    pub fn family(&self) -> u8 {
        FAMILY_IPV6
    }

    #[inline(always)]
    pub fn parse_at<C: PacketData + PortReader>(
        ctx: &C,
        l3_offset: usize,
    ) -> Result<Option<Self>, u32> {
        let _ = unsafe { ptr_at::<_, Ipv6Hdr>(ctx, l3_offset)? };
        if !validate_ipv6_header(ctx, l3_offset) {
            return Ok(None);
        }

        let ip_hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_offset)? };

        let src = unsafe { (*ip_hdr).src_addr.in6_u.u6_addr8 };
        let dst = unsafe { (*ip_hdr).dst_addr.in6_u.u6_addr8 };

        let l4_offset = l3_offset.saturating_add(Ipv6Hdr::LEN);
        let next_header = ctx.read_u8(l3_offset.saturating_add(6)).unwrap_or(0);
        let l4 = read_l4(ctx, l4_offset, next_header);

        Ok(Some(Self { src, dst, l4 }))
    }
}

/// Unified L3 view for policy and logging.
#[derive(Clone, Copy)]
pub enum L3Packet {
    V4(Ipv4Packet),
    V6(Ipv6Packet),
}


/// Where the L3 header starts on a TC skb (Ethernet-present or L3-only).
#[derive(Clone, Copy)]
pub enum TcL3Hint {
    Ipv4(usize),
    Ipv6(usize),
    Unknown,
}

/// Demux Ethernet and parse the inner L3 header.
#[inline(always)]
pub fn parse_from_ethernet<C: PacketData + PortReader>(
    ctx: &C,
) -> Result<L3ParseOutcome, u32> {
    const ETH_P_IP: u16 = 0x0800;
    const ETH_P_IPV6: u16 = 0x86DD;

    // Bounds-check Ethernet header; read ethertype by offset (verifier-friendly).
    let _ = unsafe { ptr_at::<_, EthHdr>(ctx, 0)? };
    let l3_offset = EthHdr::LEN;

    let hi = ctx.read_u8(12).unwrap_or(0);
    let lo = ctx.read_u8(13).unwrap_or(0);
    let ether_type = (u16::from(hi) << 8) | u16::from(lo);

    match ether_type {
        ETH_P_IP => match Ipv4Packet::parse_at(ctx, l3_offset)? {
            Some(p) => Ok(L3ParseOutcome::Packet(L3Packet::V4(p))),
            None => Ok(L3ParseOutcome::Invalid {
                family: FAMILY_IPV4,
            }),
        },
        ETH_P_IPV6 => match Ipv6Packet::parse_at(ctx, l3_offset)? {
            Some(p) => Ok(L3ParseOutcome::Packet(L3Packet::V6(p))),
            None => Ok(L3ParseOutcome::Invalid {
                family: FAMILY_IPV6,
            }),
        },
        _ => Ok(L3ParseOutcome::NotIp),
    }
}

/// Detect L3 offset on TC (Ethernet header may be present or stripped).
#[inline(always)]
pub fn detect_tc_l3(ctx: &TcContext) -> TcL3Hint {
    const ETH_P_IP: u16 = 0x0800;
    const ETH_P_IPV6: u16 = 0x86DD;

    if let (Ok(b12), Ok(b13)) = (ctx.load::<u8>(12), ctx.load::<u8>(13)) {
        let et = (u16::from(b12) << 8) | u16::from(b13);
        match et {
            ETH_P_IP => return TcL3Hint::Ipv4(EthHdr::LEN),
            ETH_P_IPV6 => return TcL3Hint::Ipv6(EthHdr::LEN),
            _ => {}
        }
    }

    if let Ok(b0) = ctx.load::<u8>(0) {
        return match b0 >> 4 {
            4 => TcL3Hint::Ipv4(0),
            6 => TcL3Hint::Ipv6(0),
            _ => TcL3Hint::Unknown,
        };
    }

    TcL3Hint::Unknown
}

/// Parse L3 from a TC hint; returns `None` on parse failure (pass-through upstream).
#[inline(always)]
pub fn parse_from_tc_hint<C: PacketData + PortReader>(
    ctx: &C,
    hint: TcL3Hint,
) -> L3ParseOutcome {
    match hint {
        TcL3Hint::Ipv4(off) => match Ipv4Packet::parse_at(ctx, off) {
            Ok(Some(p)) => L3ParseOutcome::Packet(L3Packet::V4(p)),
            Ok(None) => L3ParseOutcome::Invalid {
                family: FAMILY_IPV4,
            },
            Err(_) => L3ParseOutcome::Invalid {
                family: FAMILY_IPV4,
            },
        },
        TcL3Hint::Ipv6(off) => match Ipv6Packet::parse_at(ctx, off) {
            Ok(Some(p)) => L3ParseOutcome::Packet(L3Packet::V6(p)),
            Ok(None) => L3ParseOutcome::Invalid {
                family: FAMILY_IPV6,
            },
            Err(_) => L3ParseOutcome::Invalid {
                family: FAMILY_IPV6,
            },
        },
        TcL3Hint::Unknown => L3ParseOutcome::NotIp,
    }
}

#[inline(always)]
fn ipv4_header_len<C: PortReader>(ctx: &C, l3_offset: usize) -> usize {
    ctx.read_u8(l3_offset)
        .map(|b| ((b & 0x0f) as usize).saturating_mul(4))
        .unwrap_or(20)
}
