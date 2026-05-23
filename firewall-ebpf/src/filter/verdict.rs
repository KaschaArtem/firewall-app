use aya_ebpf::{
    bindings::xdp_action,
    maps::lpm_trie::Key,
    programs::{TcContext, XdpContext},
    EbpfContext,
};
use firewall_common::{
    MODE_ALL_DROP, MODE_ALL_PASS, MODE_DEFAULT_DROP, REASON_ALL_DROP, REASON_ALL_PASS,
    REASON_BLACKLIST, REASON_DEFAULT, REASON_NON_IP, REASON_WHITELIST, ACTION_DROP, ACTION_PASS,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, Ipv6Hdr},
};

use super::decision::{self, DIR_EGRESS, DIR_INGRESS};
use super::packet::{ptr_at, PacketData};
use crate::maps::{BLACKLIST_V4, BLACKLIST_V6, WHITELIST_V4, WHITELIST_V6};

#[derive(PartialEq, Eq)]
pub enum FilterVerdict {
    Pass,
    Drop,
}

pub fn check_packet_xdp(ctx: &XdpContext, firewall_mode: u32) -> Result<u32, u32> {
    match filter_packet(ctx, firewall_mode, DIR_INGRESS) {
        Ok(FilterVerdict::Pass) => Ok(xdp_action::XDP_PASS),
        Ok(FilterVerdict::Drop) => Ok(xdp_action::XDP_DROP),
        Err(code) => Err(code),
    }
}

pub fn check_packet_tc(ctx: &TcContext, firewall_mode: u32) -> i32 {
    use aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_SHOT};

    match filter_packet(ctx, firewall_mode, DIR_EGRESS) {
        Ok(FilterVerdict::Pass) => TC_ACT_OK as i32,
        Ok(FilterVerdict::Drop) => TC_ACT_SHOT as i32,
        Err(_) => TC_ACT_SHOT as i32,
    }
}

fn filter_packet<C>(ctx: &C, firewall_mode: u32, direction: u8) -> Result<FilterVerdict, u32>
where
    C: PacketData + EbpfContext,
{
    if firewall_mode == MODE_ALL_PASS {
        decision::record_decision(
            ctx,
            direction,
            ACTION_PASS,
            REASON_ALL_PASS,
            0,
            [0; 16],
            [0; 16],
        );
        return Ok(FilterVerdict::Pass);
    }
    if firewall_mode == MODE_ALL_DROP {
        decision::record_decision(
            ctx,
            direction,
            ACTION_DROP,
            REASON_ALL_DROP,
            0,
            [0; 16],
            [0; 16],
        );
        return Ok(FilterVerdict::Drop);
    }

    let eth_hdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };

    match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv4 => filter_ipv4(ctx, firewall_mode, direction),
        EtherType::Ipv6 => filter_ipv6(ctx, firewall_mode, direction),
        _ => {
            decision::record_decision(
                ctx,
                direction,
                ACTION_PASS,
                REASON_NON_IP,
                0,
                [0; 16],
                [0; 16],
            );
            Ok(FilterVerdict::Pass)
        }
    }
}

fn filter_ipv4<C>(ctx: &C, firewall_mode: u32, direction: u8) -> Result<FilterVerdict, u32>
where
    C: PacketData + EbpfContext,
{
    let ip_hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, EthHdr::LEN)? };

    let src = unsafe { (*ip_hdr).src_addr };
    let dst = unsafe { (*ip_hdr).dst_addr };

    let src_clean = u32::from_be(src);
    let dst_clean = u32::from_be(dst);
    let src_octets = src_clean.to_be_bytes();
    let dst_octets = dst_clean.to_be_bytes();

    let mut is_drop = false;
    let mut reason = REASON_DEFAULT;

    if BLACKLIST_V4.get(&Key::new(32, src_octets)).is_some() {
        is_drop = true;
        reason = REASON_BLACKLIST;
    } else if BLACKLIST_V4.get(&Key::new(32, dst_octets)).is_some() {
        is_drop = true;
        reason = REASON_BLACKLIST;
    } else if WHITELIST_V4.get(&Key::new(32, src_octets)).is_some() {
        is_drop = false;
        reason = REASON_WHITELIST;
    } else if WHITELIST_V4.get(&Key::new(32, dst_octets)).is_some() {
        is_drop = false;
        reason = REASON_WHITELIST;
    } else if firewall_mode == MODE_DEFAULT_DROP {
        is_drop = true;
        reason = REASON_DEFAULT;
    }

    if is_drop {
        decision::record_ipv4(ctx, direction, ACTION_DROP, reason, src_clean, dst_clean);
        return Ok(FilterVerdict::Drop);
    }

    decision::record_ipv4(ctx, direction, ACTION_PASS, reason, src_clean, dst_clean);
    Ok(FilterVerdict::Pass)
}

fn filter_ipv6<C>(ctx: &C, firewall_mode: u32, direction: u8) -> Result<FilterVerdict, u32>
where
    C: PacketData + EbpfContext,
{
    let ip_hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, EthHdr::LEN)? };

    let src = unsafe { (*ip_hdr).src_addr.in6_u.u6_addr8 };
    let dst = unsafe { (*ip_hdr).dst_addr.in6_u.u6_addr8 };

    let mut is_drop = false;
    let mut reason = REASON_DEFAULT;

    if BLACKLIST_V6.get(&Key::new(128, src)).is_some() {
        is_drop = true;
        reason = REASON_BLACKLIST;
    } else if BLACKLIST_V6.get(&Key::new(128, dst)).is_some() {
        is_drop = true;
        reason = REASON_BLACKLIST;
    } else if WHITELIST_V6.get(&Key::new(128, src)).is_some() {
        is_drop = false;
        reason = REASON_WHITELIST;
    } else if WHITELIST_V6.get(&Key::new(128, dst)).is_some() {
        is_drop = false;
        reason = REASON_WHITELIST;
    } else if firewall_mode == MODE_DEFAULT_DROP {
        is_drop = true;
        reason = REASON_DEFAULT;
    }

    if is_drop {
        decision::record_ipv6(ctx, direction, ACTION_DROP, reason, src, dst);
        return Ok(FilterVerdict::Drop);
    }

    decision::record_ipv6(ctx, direction, ACTION_PASS, reason, src, dst);
    Ok(FilterVerdict::Pass)
}
