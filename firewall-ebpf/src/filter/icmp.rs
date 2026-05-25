//! ICMP class policy (echo / traceroute / control).

use firewall_common::{
    icmp_policy_shift, ICMP_CLASS_NONE, ICMP_POLICY_ACT_DROP, ICMP_POLICY_ENABLED,
    CONFIG_INDEX_ICMP,
};

use crate::maps::CONFIG;
use crate::packet::L4Info;

#[inline(always)]
fn icmp_policy() -> u32 {
    CONFIG
        .get(CONFIG_INDEX_ICMP)
        .map(|p| *p)
        .unwrap_or(0)
}

#[inline(always)]
pub fn should_drop(l4: &L4Info) -> bool {
    let policy = icmp_policy();
    if policy & ICMP_POLICY_ENABLED == 0 {
        return false;
    }
    let class = l4.icmp_class;
    if class == ICMP_CLASS_NONE {
        return false;
    }
    let shift = icmp_policy_shift(class);
    (policy >> shift) & ICMP_POLICY_ACT_DROP != 0
}
