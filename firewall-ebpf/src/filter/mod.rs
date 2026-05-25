//! Firewall policy: list lookups and mode handling on parsed `L3Packet` values.

mod icmp;
mod ratelimit;
mod rpf;

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    maps::lpm_trie::Key,
    programs::{TcContext, XdpContext},
    EbpfContext,
};
use firewall_common::{
    list_applies_to_direction, PacketDecisionEvent, ACTION_DROP, DIRECTION_EGRESS,
    DIRECTION_INGRESS, MODE_ALL_DROP, MODE_ALL_PASS, MODE_DEFAULT_DROP, MODE_DEFAULT_PASS,
    REASON_ALL_DROP, REASON_ALL_PASS, REASON_BLACKLIST, REASON_DEFAULT, REASON_ICMP_FILTER,
    REASON_MALFORMED, REASON_RATE_LIMIT, REASON_RPF,
};
use aya_ebpf::maps::LpmTrie;

use crate::maps::{
    BLACKLIST_V4, BLACKLIST_V6, DECISIONS, STAT_DROPS, STAT_PASSES, STATS, WHITELIST_V4,
    WHITELIST_V6,
};
use crate::packet::{
    detect_tc_l3, parse_from_ethernet, parse_from_tc_hint, Ipv4Packet, Ipv6Packet, L3Packet,
    L3ParseOutcome, L4Info, PacketData, PortReader,
};

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
        icmp_type: l4.icmp_type,
        icmp_code: l4.icmp_code,
        icmp_class: l4.icmp_class,
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
    pkt: &Ipv4Packet,
) {
    let mut src_addr = [0u8; 16];
    let mut dst_addr = [0u8; 16];
    src_addr[..4].copy_from_slice(&pkt.src);
    dst_addr[..4].copy_from_slice(&pkt.dst);
    record_decision(
        direction,
        action,
        reason,
        pkt.family(),
        src_addr,
        dst_addr,
        pkt.l4,
    );
}

fn record_ipv6(direction: u8, action: u8, reason: u8, pkt: &Ipv6Packet) {
    record_decision(
        direction,
        action,
        reason,
        pkt.family(),
        pkt.src,
        pkt.dst,
        pkt.l4,
    );
}

// --- filter entry points ---

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

    let hint = detect_tc_l3(ctx);
    let result = apply_l3_outcome(
        firewall_mode,
        DIRECTION_EGRESS,
        parse_from_tc_hint(ctx, hint),
    );

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
    apply_l3_outcome(firewall_mode, direction, parse_from_ethernet(ctx)?)
}

#[inline(always)]
fn apply_l3_outcome(
    firewall_mode: u32,
    direction: u8,
    outcome: L3ParseOutcome,
) -> Result<FilterVerdict, u32> {
    match outcome {
        L3ParseOutcome::Packet(L3Packet::V4(pkt)) => {
            if rpf::ipv4_ingress_spoofed(direction, pkt.src) {
                record_ipv4(direction, ACTION_DROP, REASON_RPF, &pkt);
                count_drop();
                return Ok(FilterVerdict::Drop);
            }
            if icmp::should_drop(&pkt.l4) {
                record_ipv4(direction, ACTION_DROP, REASON_ICMP_FILTER, &pkt);
                count_drop();
                return Ok(FilterVerdict::Drop);
            }
            if ratelimit::ipv4_exceeded(pkt.src) {
                record_ipv4(direction, ACTION_DROP, REASON_RATE_LIMIT, &pkt);
                count_drop();
                return Ok(FilterVerdict::Drop);
            }
            apply_ipv4_mode(firewall_mode, direction, pkt)
        }
        L3ParseOutcome::Packet(L3Packet::V6(pkt)) => {
            if rpf::ipv6_ingress_spoofed(direction, pkt.src) {
                record_ipv6(direction, ACTION_DROP, REASON_RPF, &pkt);
                count_drop();
                return Ok(FilterVerdict::Drop);
            }
            if icmp::should_drop(&pkt.l4) {
                record_ipv6(direction, ACTION_DROP, REASON_ICMP_FILTER, &pkt);
                count_drop();
                return Ok(FilterVerdict::Drop);
            }
            if ratelimit::ipv6_exceeded(pkt.src) {
                record_ipv6(direction, ACTION_DROP, REASON_RATE_LIMIT, &pkt);
                count_drop();
                return Ok(FilterVerdict::Drop);
            }
            apply_ipv6_mode(firewall_mode, direction, pkt)
        }
        L3ParseOutcome::NotIp => {
            count_pass();
            Ok(FilterVerdict::Pass)
        }
        L3ParseOutcome::Invalid { family } => drop_malformed(direction, family),
    }
}

#[inline(always)]
fn drop_malformed(direction: u8, family: u8) -> Result<FilterVerdict, u32> {
    record_decision(
        direction,
        ACTION_DROP,
        REASON_MALFORMED,
        family,
        [0u8; 16],
        [0u8; 16],
        L4Info::default(),
    );
    count_drop();
    Ok(FilterVerdict::Drop)
}

// --- list lookups ---

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

// --- L3 policy (extend per-family logic here) ---

#[inline(always)]
fn apply_ipv4_mode(
    firewall_mode: u32,
    direction: u8,
    pkt: Ipv4Packet,
) -> Result<FilterVerdict, u32> {
    if firewall_mode == MODE_ALL_PASS {
        count_pass();
        return Ok(FilterVerdict::Pass);
    }
    if firewall_mode == MODE_ALL_DROP {
        count_drop();
        return Ok(FilterVerdict::Drop);
    }
    filter_ipv4_policy(firewall_mode, direction, pkt)
}

#[inline(always)]
fn apply_ipv6_mode(
    firewall_mode: u32,
    direction: u8,
    pkt: Ipv6Packet,
) -> Result<FilterVerdict, u32> {
    if firewall_mode == MODE_ALL_PASS {
        count_pass();
        return Ok(FilterVerdict::Pass);
    }
    if firewall_mode == MODE_ALL_DROP {
        count_drop();
        return Ok(FilterVerdict::Drop);
    }
    filter_ipv6_policy(firewall_mode, direction, pkt)
}

fn filter_ipv4_policy(
    firewall_mode: u32,
    direction: u8,
    pkt: Ipv4Packet,
) -> Result<FilterVerdict, u32> {
    let src = pkt.src;
    let dst = pkt.dst;

    match (firewall_mode, direction) {
        (MODE_DEFAULT_DROP, DIRECTION_INGRESS) => {
            if ipv4_whitelisted(src, dst, direction) {
                count_pass();
                return Ok(FilterVerdict::Pass);
            }
            count_drop();
            return Ok(FilterVerdict::Drop);
        }
        (MODE_DEFAULT_PASS, DIRECTION_INGRESS) | (MODE_DEFAULT_PASS, DIRECTION_EGRESS) => {
            if ipv4_blacklisted(src, dst, direction) {
                record_ipv4(direction, ACTION_DROP, REASON_BLACKLIST, &pkt);
                count_drop();
                return Ok(FilterVerdict::Drop);
            }
            count_pass();
            return Ok(FilterVerdict::Pass);
        }
        (MODE_DEFAULT_DROP, DIRECTION_EGRESS) => {
            if ipv4_blacklisted(src, dst, direction) {
                record_ipv4(direction, ACTION_DROP, REASON_BLACKLIST, &pkt);
                count_drop();
                return Ok(FilterVerdict::Drop);
            }
            if ipv4_whitelisted(src, dst, direction) {
                count_pass();
                return Ok(FilterVerdict::Pass);
            }
            record_ipv4(direction, ACTION_DROP, REASON_DEFAULT, &pkt);
            count_drop();
            return Ok(FilterVerdict::Drop);
        }
        _ => {}
    }

    count_pass();
    Ok(FilterVerdict::Pass)
}

fn filter_ipv6_policy(
    firewall_mode: u32,
    direction: u8,
    pkt: Ipv6Packet,
) -> Result<FilterVerdict, u32> {
    let src = pkt.src;
    let dst = pkt.dst;

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
                record_ipv6(direction, ACTION_DROP, REASON_BLACKLIST, &pkt);
                count_drop();
                return Ok(FilterVerdict::Drop);
            }
            count_pass();
            return Ok(FilterVerdict::Pass);
        }
        (MODE_DEFAULT_DROP, DIRECTION_EGRESS) => {
            if ipv6_blacklisted(src, dst, direction) {
                record_ipv6(direction, ACTION_DROP, REASON_BLACKLIST, &pkt);
                count_drop();
                return Ok(FilterVerdict::Drop);
            }
            if ipv6_whitelisted(src, dst, direction) {
                count_pass();
                return Ok(FilterVerdict::Pass);
            }
            record_ipv6(direction, ACTION_DROP, REASON_DEFAULT, &pkt);
            count_drop();
            return Ok(FilterVerdict::Drop);
        }
        _ => {}
    }

    count_pass();
    Ok(FilterVerdict::Pass)
}
