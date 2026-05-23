use aya_ebpf::{helpers::bpf_ktime_get_ns, EbpfContext};
use firewall_common::{
    PacketDecisionEvent, DIRECTION_EGRESS, DIRECTION_INGRESS, FAMILY_IPV4, FAMILY_IPV6,
};

use crate::maps::DECISIONS;

pub fn record_decision<C: EbpfContext>(
    _ctx: &C,
    direction: u8,
    action: u8,
    reason: u8,
    family: u8,
    src: [u8; 16],
    dst: [u8; 16],
) {
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

pub fn record_ipv4<C: EbpfContext>(
    ctx: &C,
    direction: u8,
    action: u8,
    reason: u8,
    src: u32,
    dst: u32,
) {
    let mut src_addr = [0u8; 16];
    let mut dst_addr = [0u8; 16];
    src_addr[..4].copy_from_slice(&src.to_be_bytes());
    dst_addr[..4].copy_from_slice(&dst.to_be_bytes());
    record_decision(
        ctx,
        direction,
        action,
        reason,
        FAMILY_IPV4,
        src_addr,
        dst_addr,
    );
}

pub fn record_ipv6<C: EbpfContext>(
    ctx: &C,
    direction: u8,
    action: u8,
    reason: u8,
    src: [u8; 16],
    dst: [u8; 16],
) {
    record_decision(ctx, direction, action, reason, FAMILY_IPV6, src, dst);
}

pub const DIR_INGRESS: u8 = DIRECTION_INGRESS;
pub const DIR_EGRESS: u8 = DIRECTION_EGRESS;
