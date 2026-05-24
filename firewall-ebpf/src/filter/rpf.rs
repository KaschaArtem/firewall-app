//! Ingress RPF on external interfaces: drop packets with an internal source address.

use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::maps::LpmTrie;
use firewall_common::{
    CONFIG_FLAG_IFACE_EXTERNAL, CONFIG_FLAG_RPF_ENABLED, CONFIG_INDEX_FLAGS, DIRECTION_INGRESS,
};

use crate::maps::{CONFIG, RPF_INTERNAL_V4, RPF_INTERNAL_V6};

#[inline(always)]
fn config_flags() -> u32 {
    CONFIG
        .get(CONFIG_INDEX_FLAGS)
        .map(|f| *f)
        .unwrap_or(0)
}

#[inline(always)]
pub fn rpf_active_on_ingress(direction: u8) -> bool {
    if direction != DIRECTION_INGRESS {
        return false;
    }
    let flags = config_flags();
    (flags & CONFIG_FLAG_RPF_ENABLED) != 0 && (flags & CONFIG_FLAG_IFACE_EXTERNAL) != 0
}

#[inline(always)]
fn ipv4_in_internal(map: &LpmTrie<[u8; 4], u8>, addr: [u8; 4]) -> bool {
    map.get(&Key::new(32, addr)).is_some()
}

#[inline(always)]
fn ipv6_in_internal(map: &LpmTrie<[u8; 16], u8>, addr: [u8; 16]) -> bool {
    map.get(&Key::new(128, addr)).is_some()
}

/// `true` if the source address is spoofed (internal prefix on external ingress).
#[inline(always)]
pub fn ipv4_ingress_spoofed(direction: u8, src: [u8; 4]) -> bool {
    rpf_active_on_ingress(direction) && ipv4_in_internal(&RPF_INTERNAL_V4, src)
}

#[inline(always)]
pub fn ipv6_ingress_spoofed(direction: u8, src: [u8; 16]) -> bool {
    rpf_active_on_ingress(direction) && ipv6_in_internal(&RPF_INTERNAL_V6, src)
}
