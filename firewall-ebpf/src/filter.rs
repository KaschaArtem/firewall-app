use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    maps::lpm_trie::Key,
    programs::{TcContext, XdpContext},
    EbpfContext,
};
use firewall_common::{
    PacketDecisionEvent, ACTION_DROP, DIRECTION_EGRESS, DIRECTION_INGRESS, FAMILY_IPV4,
    FAMILY_IPV6, MODE_ALL_DROP, MODE_ALL_PASS, MODE_DEFAULT_DROP, MODE_DEFAULT_PASS,
    REASON_ALL_DROP, REASON_ALL_PASS, REASON_BLACKLIST, REASON_DEFAULT,
};
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

fn record_decision(
    direction: u8,
    action: u8,
    reason: u8,
    family: u8,
    src: [u8; 16],
    dst: [u8; 16],
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
        src,
        dst,
    };

    if let Some(mut entry) = DECISIONS.reserve::<PacketDecisionEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }
}

fn record_ipv4(direction: u8, action: u8, reason: u8, src: u32, dst: u32) {
    let mut src_addr = [0u8; 16];
    let mut dst_addr = [0u8; 16];
    src_addr[..4].copy_from_slice(&src.to_be_bytes());
    dst_addr[..4].copy_from_slice(&dst.to_be_bytes());
    record_decision(direction, action, reason, FAMILY_IPV4, src_addr, dst_addr);
}

fn record_ipv6(direction: u8, action: u8, reason: u8, src: [u8; 16], dst: [u8; 16]) {
    record_decision(direction, action, reason, FAMILY_IPV6, src, dst);
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

    let _ = ctx.pull_data(0);

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
    C: PacketData + EbpfContext,
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
    C: PacketData + EbpfContext,
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
fn ipv4_whitelisted(src: [u8; 4], dst: [u8; 4]) -> bool {
    WHITELIST_V4.get(&Key::new(32, src)).is_some() || WHITELIST_V4.get(&Key::new(32, dst)).is_some()
}

#[inline(always)]
fn ipv4_blacklisted(src: [u8; 4], dst: [u8; 4]) -> bool {
    BLACKLIST_V4.get(&Key::new(32, src)).is_some() || BLACKLIST_V4.get(&Key::new(32, dst)).is_some()
}

fn filter_ipv4<C>(ctx: &C, firewall_mode: u32, direction: u8, l3_offset: usize) -> Result<FilterVerdict, u32>
where
    C: PacketData + EbpfContext,
{
    let ip_hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_offset)? };

    let src_clean = u32::from_be(unsafe { (*ip_hdr).src_addr });
    let dst_clean = u32::from_be(unsafe { (*ip_hdr).dst_addr });
    let src_octets = src_clean.to_be_bytes();
    let dst_octets = dst_clean.to_be_bytes();

    match (firewall_mode, direction) {
        (MODE_DEFAULT_DROP, DIRECTION_INGRESS) => {
            if ipv4_whitelisted(src_octets, dst_octets) {
                count_pass();
                return Ok(FilterVerdict::Pass);
            }
            count_drop();
            return Ok(FilterVerdict::Drop);
        }
        (MODE_DEFAULT_PASS, DIRECTION_INGRESS) | (MODE_DEFAULT_PASS, DIRECTION_EGRESS) => {
            if ipv4_blacklisted(src_octets, dst_octets) {
                record_ipv4(direction, ACTION_DROP, REASON_BLACKLIST, src_clean, dst_clean);
                count_drop();
                return Ok(FilterVerdict::Drop);
            }
            count_pass();
            return Ok(FilterVerdict::Pass);
        }
        (MODE_DEFAULT_DROP, DIRECTION_EGRESS) => {
            if ipv4_blacklisted(src_octets, dst_octets) {
                record_ipv4(direction, ACTION_DROP, REASON_BLACKLIST, src_clean, dst_clean);
                count_drop();
                return Ok(FilterVerdict::Drop);
            }
            if ipv4_whitelisted(src_octets, dst_octets) {
                count_pass();
                return Ok(FilterVerdict::Pass);
            }
            record_ipv4(direction, ACTION_DROP, REASON_DEFAULT, src_clean, dst_clean);
            count_drop();
            return Ok(FilterVerdict::Drop);
        }
        _ => {}
    }

    count_pass();
    Ok(FilterVerdict::Pass)
}

#[inline(always)]
fn ipv6_whitelisted(src: [u8; 16], dst: [u8; 16]) -> bool {
    WHITELIST_V6.get(&Key::new(128, src)).is_some() || WHITELIST_V6.get(&Key::new(128, dst)).is_some()
}

#[inline(always)]
fn ipv6_blacklisted(src: [u8; 16], dst: [u8; 16]) -> bool {
    BLACKLIST_V6.get(&Key::new(128, src)).is_some() || BLACKLIST_V6.get(&Key::new(128, dst)).is_some()
}

fn filter_ipv6<C>(ctx: &C, firewall_mode: u32, direction: u8, l3_offset: usize) -> Result<FilterVerdict, u32>
where
    C: PacketData + EbpfContext,
{
    let ip_hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_offset)? };

    let src = unsafe { (*ip_hdr).src_addr.in6_u.u6_addr8 };
    let dst = unsafe { (*ip_hdr).dst_addr.in6_u.u6_addr8 };

    match (firewall_mode, direction) {
        (MODE_DEFAULT_DROP, DIRECTION_INGRESS) => {
            if ipv6_whitelisted(src, dst) {
                count_pass();
                return Ok(FilterVerdict::Pass);
            }
            count_drop();
            return Ok(FilterVerdict::Drop);
        }
        (MODE_DEFAULT_PASS, DIRECTION_INGRESS) | (MODE_DEFAULT_PASS, DIRECTION_EGRESS) => {
            if ipv6_blacklisted(src, dst) {
                record_ipv6(direction, ACTION_DROP, REASON_BLACKLIST, src, dst);
                count_drop();
                return Ok(FilterVerdict::Drop);
            }
            count_pass();
            return Ok(FilterVerdict::Pass);
        }
        (MODE_DEFAULT_DROP, DIRECTION_EGRESS) => {
            if ipv6_blacklisted(src, dst) {
                record_ipv6(direction, ACTION_DROP, REASON_BLACKLIST, src, dst);
                count_drop();
                return Ok(FilterVerdict::Drop);
            }
            if ipv6_whitelisted(src, dst) {
                count_pass();
                return Ok(FilterVerdict::Pass);
            }
            record_ipv6(direction, ACTION_DROP, REASON_DEFAULT, src, dst);
            count_drop();
            return Ok(FilterVerdict::Drop);
        }
        _ => {}
    }

    count_pass();
    Ok(FilterVerdict::Pass)
}
