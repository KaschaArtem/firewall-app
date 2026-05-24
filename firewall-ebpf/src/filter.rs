use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    maps::lpm_trie::Key,
    programs::{TcContext, XdpContext},
    EbpfContext,
};
use firewall_common::{
    list_applies_to_direction, PacketDecisionEvent, ACTION_DROP, DIRECTION_EGRESS,
    DIRECTION_INGRESS, FAMILY_IPV4, FAMILY_IPV6, MODE_ALL_DROP, MODE_ALL_PASS,
    MODE_DEFAULT_DROP, MODE_DEFAULT_PASS, REASON_ALL_DROP, REASON_ALL_PASS, REASON_BLACKLIST,
    REASON_DEFAULT,
};
use aya_ebpf::maps::LpmTrie;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, Ipv6Hdr},
};

use crate::maps::{
    BLACKLIST_V4, BLACKLIST_V6, DECISIONS, STAT_DROPS, STAT_PASSES, STATS, WHITELIST_V4,
    WHITELIST_V6,
};

// --- packet access ---

trait PacketData {
    fn data(&self) -> usize;
    fn data_end(&self) -> usize;
}

impl PacketData for XdpContext {
    fn data(&self) -> usize {
        self.data()
    }

    fn data_end(&self) -> usize {
        self.data_end()
    }
}

impl PacketData for TcContext {
    fn data(&self) -> usize {
        self.data()
    }

    fn data_end(&self) -> usize {
        self.data_end()
    }
}

#[inline(always)]
unsafe fn ptr_at<C: PacketData, T>(ctx: &C, offset: usize) -> Result<*const T, u32> {
    use core::mem;

    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(xdp_action::XDP_ABORTED);
    }

    Ok((start + offset) as *const T)
}

/// Read packet bytes: `bpf_skb_load_bytes` on TC, direct access on XDP.
trait PortReader {
    fn read_u8(&self, offset: usize) -> Option<u8>;
    fn read_u16_be(&self, offset: usize) -> Option<u16>;
    /// TC: `data`/`data_end` are unreliable for L4; use load and skip bounds pre-check.
    fn uses_skb_load(&self) -> bool;
}

impl PortReader for XdpContext {
    fn uses_skb_load(&self) -> bool {
        false
    }

    fn read_u8(&self, offset: usize) -> Option<u8> {
        unsafe { ptr_at::<_, u8>(self, offset).ok().map(|p| *p) }
    }

    fn read_u16_be(&self, offset: usize) -> Option<u16> {
        let hi = self.read_u8(offset)?;
        let lo = self.read_u8(offset + 1)?;
        Some((u16::from(hi) << 8) | u16::from(lo))
    }
}

impl PortReader for TcContext {
    fn uses_skb_load(&self) -> bool {
        true
    }

    fn read_u8(&self, offset: usize) -> Option<u8> {
        self.load::<u8>(offset).ok()
    }

    fn read_u16_be(&self, offset: usize) -> Option<u16> {
        let hi = self.read_u8(offset)?;
        let lo = self.read_u8(offset + 1)?;
        Some((u16::from(hi) << 8) | u16::from(lo))
    }
}

// --- counters ---

#[inline(always)]
fn count_drop() {
    bump(STAT_DROPS);
}

#[inline(always)]
fn count_pass() {
    bump(STAT_PASSES);
}

#[inline(always)]
fn bump(index: u32) {
    if let Some(n) = STATS.get(index) {
        let _ = STATS.set(index, n.wrapping_add(1), 0);
    }
}

// --- decision ringbuf ---

#[inline(always)]
fn should_record(direction: u8, action: u8, reason: u8) -> bool {
    if action != ACTION_DROP {
        return false;
    }
    if reason == REASON_ALL_PASS || reason == REASON_ALL_DROP {
        return false;
    }
    if reason == REASON_DEFAULT && direction == DIRECTION_INGRESS {
        return false;
    }
    true
}

struct L4Info {
    protocol: u8,
    src_port: u16,
    dst_port: u16,
}

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;

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

/// IPv4 IHL from the first byte (works with TC `load` and XDP packet access).
#[inline(always)]
fn ipv4_header_len<C: PortReader>(ctx: &C, l3_offset: usize) -> usize {
    ctx.read_u8(l3_offset)
        .map(|b| ((b & 0x0f) as usize).saturating_mul(4))
        .unwrap_or(20)
}

/// Must run before any map lookup — verifier drops packet bounds after bpf_map_lookup_elem.
fn parse_l4<C: PacketData + PortReader>(ctx: &C, l4_offset: usize, proto: u8) -> L4Info {
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

fn record_decision(
    direction: u8,
    action: u8,
    reason: u8,
    family: u8,
    src: [u8; 16],
    dst: [u8; 16],
    l4: L4Info,
) {
    if !should_record(direction, action, reason) {
        return;
    }

    let event = PacketDecisionEvent {
        ts_ns: unsafe { bpf_ktime_get_ns() },
        action,
        family,
        reason,
        direction,
        protocol: l4.protocol,
        _pad: 0,
        src_port: l4.src_port,
        dst_port: l4.dst_port,
        src,
        dst,
    };

    if let Some(mut entry) = DECISIONS.reserve::<PacketDecisionEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }
}

fn record_ipv4(
    direction: u8,
    action: u8,
    reason: u8,
    src: u32,
    dst: u32,
    l4: L4Info,
) {
    let mut src_addr = [0u8; 16];
    let mut dst_addr = [0u8; 16];
    src_addr[..4].copy_from_slice(&src.to_be_bytes());
    dst_addr[..4].copy_from_slice(&dst.to_be_bytes());
    record_decision(direction, action, reason, FAMILY_IPV4, src_addr, dst_addr, l4);
}

fn record_ipv6(
    direction: u8,
    action: u8,
    reason: u8,
    src: [u8; 16],
    dst: [u8; 16],
    l4: L4Info,
) {
    record_decision(direction, action, reason, FAMILY_IPV6, src, dst, l4);
}

// --- filter ---

#[derive(PartialEq, Eq)]
enum FilterVerdict {
    Pass,
    Drop,
}

pub fn check_packet_xdp(ctx: &XdpContext, firewall_mode: u32) -> Result<u32, u32> {
    match filter_packet(ctx, firewall_mode, DIRECTION_INGRESS) {
        Ok(FilterVerdict::Pass) => Ok(xdp_action::XDP_PASS),
        Ok(FilterVerdict::Drop) => Ok(xdp_action::XDP_DROP),
        Err(code) => Err(code),
    }
}

pub fn check_packet_tc(ctx: &TcContext, firewall_mode: u32) -> i32 {
    use aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_SHOT};

    let len = ctx.len();
    if len > 0 {
        let _ = ctx.pull_data(len);
    } else {
        let _ = ctx.pull_data(0);
    }

    if firewall_mode == MODE_ALL_PASS {
        count_pass();
        return TC_ACT_OK as i32;
    }
    if firewall_mode == MODE_ALL_DROP {
        count_drop();
        return TC_ACT_SHOT as i32;
    }

    let result = match tc_l3_kind(ctx) {
        TcL3::Ipv4(off) => filter_ipv4(ctx, firewall_mode, DIRECTION_EGRESS, off),
        TcL3::Ipv6(off) => filter_ipv6(ctx, firewall_mode, DIRECTION_EGRESS, off),
        TcL3::Unknown => {
            count_pass();
            Ok(FilterVerdict::Pass)
        }
    };

    match result {
        Ok(FilterVerdict::Pass) => TC_ACT_OK as i32,
        Ok(FilterVerdict::Drop) => TC_ACT_SHOT as i32,
        Err(_) => TC_ACT_OK as i32,
    }
}

fn filter_packet<C>(ctx: &C, firewall_mode: u32, direction: u8) -> Result<FilterVerdict, u32>
where
    C: PacketData + PortReader + EbpfContext,
{
    if firewall_mode == MODE_ALL_PASS {
        count_pass();
        return Ok(FilterVerdict::Pass);
    }
    if firewall_mode == MODE_ALL_DROP {
        count_drop();
        return Ok(FilterVerdict::Drop);
    }

    filter_packet_eth(ctx, firewall_mode, direction)
}

enum TcL3 {
    Ipv4(usize),
    Ipv6(usize),
    Unknown,
}

#[inline(always)]
fn tc_l3_kind(ctx: &TcContext) -> TcL3 {
    const ETH_P_IP: u16 = 0x0800;
    const ETH_P_IPV6: u16 = 0x86DD;

    if let (Ok(b12), Ok(b13)) = (ctx.load::<u8>(12), ctx.load::<u8>(13)) {
        let et = (u16::from(b12) << 8) | u16::from(b13);
        match et {
            ETH_P_IP => return TcL3::Ipv4(EthHdr::LEN),
            ETH_P_IPV6 => return TcL3::Ipv6(EthHdr::LEN),
            _ => {}
        }
    }

    if let Ok(b0) = ctx.load::<u8>(0) {
        return match b0 >> 4 {
            4 => TcL3::Ipv4(0),
            6 => TcL3::Ipv6(0),
            _ => TcL3::Unknown,
        };
    }

    TcL3::Unknown
}

fn filter_packet_eth<C>(ctx: &C, firewall_mode: u32, direction: u8) -> Result<FilterVerdict, u32>
where
    C: PacketData + PortReader + EbpfContext,
{
    let eth_hdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let l3_offset = EthHdr::LEN;

    match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv4 => filter_ipv4(ctx, firewall_mode, direction, l3_offset),
        EtherType::Ipv6 => filter_ipv6(ctx, firewall_mode, direction, l3_offset),
        _ => {
            count_pass();
            Ok(FilterVerdict::Pass)
        }
    }
}

#[inline(always)]
fn ipv4_in_list(map: &LpmTrie<[u8; 4], u8>, addr: [u8; 4], packet_direction: u8) -> bool {
    if let Some(dirs) = map.get(&Key::new(32, addr)) {
        return list_applies_to_direction(*dirs, packet_direction);
    }
    false
}

#[inline(always)]
fn ipv6_in_list(map: &LpmTrie<[u8; 16], u8>, addr: [u8; 16], packet_direction: u8) -> bool {
    if let Some(dirs) = map.get(&Key::new(128, addr)) {
        return list_applies_to_direction(*dirs, packet_direction);
    }
    false
}

#[inline(always)]
fn ipv4_whitelisted(src: [u8; 4], dst: [u8; 4], packet_direction: u8) -> bool {
    ipv4_in_list(&WHITELIST_V4, src, packet_direction)
        || ipv4_in_list(&WHITELIST_V4, dst, packet_direction)
}

#[inline(always)]
fn ipv4_blacklisted(src: [u8; 4], dst: [u8; 4], packet_direction: u8) -> bool {
    ipv4_in_list(&BLACKLIST_V4, src, packet_direction)
        || ipv4_in_list(&BLACKLIST_V4, dst, packet_direction)
}

fn filter_ipv4<C>(ctx: &C, firewall_mode: u32, direction: u8, l3_offset: usize) -> Result<FilterVerdict, u32>
where
    C: PacketData + PortReader + EbpfContext,
{
    let ip_hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_offset)? };

    let src_clean = u32::from_be(unsafe { (*ip_hdr).src_addr });
    let dst_clean = u32::from_be(unsafe { (*ip_hdr).dst_addr });
    let src_octets = src_clean.to_be_bytes();
    let dst_octets = dst_clean.to_be_bytes();

    let ihl = ipv4_header_len(ctx, l3_offset);
    let l4_offset = l3_offset.saturating_add(ihl);
    let proto = ctx.read_u8(l3_offset.saturating_add(9)).unwrap_or(0);
    let l4 = parse_l4(ctx, l4_offset, proto);

    match (firewall_mode, direction) {
        (MODE_DEFAULT_DROP, DIRECTION_INGRESS) => {
            if ipv4_whitelisted(src_octets, dst_octets, direction) {
                count_pass();
                return Ok(FilterVerdict::Pass);
            }
            count_drop();
            return Ok(FilterVerdict::Drop);
        }
        (MODE_DEFAULT_PASS, DIRECTION_INGRESS) | (MODE_DEFAULT_PASS, DIRECTION_EGRESS) => {
            if ipv4_blacklisted(src_octets, dst_octets, direction) {
                record_ipv4(
                    direction,
                    ACTION_DROP,
                    REASON_BLACKLIST,
                    src_clean,
                    dst_clean,
                    l4,
                );
                count_drop();
                return Ok(FilterVerdict::Drop);
            }
            count_pass();
            return Ok(FilterVerdict::Pass);
        }
        (MODE_DEFAULT_DROP, DIRECTION_EGRESS) => {
            if ipv4_blacklisted(src_octets, dst_octets, direction) {
                record_ipv4(
                    direction,
                    ACTION_DROP,
                    REASON_BLACKLIST,
                    src_clean,
                    dst_clean,
                    l4,
                );
                count_drop();
                return Ok(FilterVerdict::Drop);
            }
            if ipv4_whitelisted(src_octets, dst_octets, direction) {
                count_pass();
                return Ok(FilterVerdict::Pass);
            }
            record_ipv4(
                direction,
                ACTION_DROP,
                REASON_DEFAULT,
                src_clean,
                dst_clean,
                l4,
            );
            count_drop();
            return Ok(FilterVerdict::Drop);
        }
        _ => {}
    }

    count_pass();
    Ok(FilterVerdict::Pass)
}

#[inline(always)]
fn ipv6_whitelisted(src: [u8; 16], dst: [u8; 16], packet_direction: u8) -> bool {
    ipv6_in_list(&WHITELIST_V6, src, packet_direction)
        || ipv6_in_list(&WHITELIST_V6, dst, packet_direction)
}

#[inline(always)]
fn ipv6_blacklisted(src: [u8; 16], dst: [u8; 16], packet_direction: u8) -> bool {
    ipv6_in_list(&BLACKLIST_V6, src, packet_direction)
        || ipv6_in_list(&BLACKLIST_V6, dst, packet_direction)
}

fn filter_ipv6<C>(ctx: &C, firewall_mode: u32, direction: u8, l3_offset: usize) -> Result<FilterVerdict, u32>
where
    C: PacketData + PortReader + EbpfContext,
{
    let ip_hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_offset)? };

    let src = unsafe { (*ip_hdr).src_addr.in6_u.u6_addr8 };
    let dst = unsafe { (*ip_hdr).dst_addr.in6_u.u6_addr8 };

    let l4_offset = l3_offset.saturating_add(Ipv6Hdr::LEN);
    let proto = ctx.read_u8(l3_offset.saturating_add(6)).unwrap_or(0);
    let l4 = parse_l4(ctx, l4_offset, proto);

    match (firewall_mode, direction) {
        (MODE_DEFAULT_DROP, DIRECTION_INGRESS) => {
            if ipv6_whitelisted(src, dst, direction) {
                count_pass();
                return Ok(FilterVerdict::Pass);
            }
            count_drop();
            return Ok(FilterVerdict::Drop);
        }
        (MODE_DEFAULT_PASS, DIRECTION_INGRESS) | (MODE_DEFAULT_PASS, DIRECTION_EGRESS) => {
            if ipv6_blacklisted(src, dst, direction) {
                record_ipv6(
                    direction,
                    ACTION_DROP,
                    REASON_BLACKLIST,
                    src,
                    dst,
                    l4,
                );
                count_drop();
                return Ok(FilterVerdict::Drop);
            }
            count_pass();
            return Ok(FilterVerdict::Pass);
        }
        (MODE_DEFAULT_DROP, DIRECTION_EGRESS) => {
            if ipv6_blacklisted(src, dst, direction) {
                record_ipv6(
                    direction,
                    ACTION_DROP,
                    REASON_BLACKLIST,
                    src,
                    dst,
                    l4,
                );
                count_drop();
                return Ok(FilterVerdict::Drop);
            }
            if ipv6_whitelisted(src, dst, direction) {
                count_pass();
                return Ok(FilterVerdict::Pass);
            }
            record_ipv6(
                direction,
                ACTION_DROP,
                REASON_DEFAULT,
                src,
                dst,
                l4,
            );
            count_drop();
            return Ok(FilterVerdict::Drop);
        }
        _ => {}
    }

    count_pass();
    Ok(FilterVerdict::Pass)
}
