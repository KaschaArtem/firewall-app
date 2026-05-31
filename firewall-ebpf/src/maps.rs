//! eBPF map definitions and CONFIG access helpers.

use aya_ebpf::{
    macros::map,
    maps::{Array, LpmTrie, LruHashMap, RingBuf},
};
use firewall_common::RateLimitState;

#[map]
pub static CONFIG: Array<u32> = Array::with_max_entries(4, 0);

#[inline(always)]
pub fn config_u32(index: u32) -> u32 {
    CONFIG.get(index).map(|v| *v).unwrap_or(0)
}

#[map]
pub static RATE_LIMIT_V4: LruHashMap<[u8; 4], RateLimitState> =
    LruHashMap::with_max_entries(8192, 0);

#[map]
pub static RATE_LIMIT_V6: LruHashMap<[u8; 16], RateLimitState> =
    LruHashMap::with_max_entries(8192, 0);

#[map]
pub static RPF_INTERNAL_V4: LpmTrie<[u8; 4], u8> = LpmTrie::with_max_entries(256, 0);

#[map]
pub static RPF_INTERNAL_V6: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(256, 0);

#[map]
pub static WHITELIST_V4: LpmTrie<[u8; 4], u8> = LpmTrie::with_max_entries(1024, 0);

#[map]
pub static WHITELIST_V6: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(1024, 0);

#[map]
pub static BLACKLIST_V4: LpmTrie<[u8; 4], u8> = LpmTrie::with_max_entries(1024, 0);

#[map]
pub static BLACKLIST_V6: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(1024, 0);

#[map]
pub static DECISIONS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
pub static STATS: Array<u64> = Array::with_max_entries(2, 0);

pub const STAT_DROPS: u32 = 0;
pub const STAT_PASSES: u32 = 1;
