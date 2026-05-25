use aya_ebpf::{macros::map, maps::{Array, LpmTrie, LruHashMap, RingBuf}};

/// LRU map value (layout must match `firewall_common::RateLimitState`).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RateLimitCell {
    pub window_start_ns: u64,
    pub count: u32,
}

/// [0] mode, [1] flags, [2] ICMP policy, [3] rate PPS.
#[map]
pub static CONFIG: Array<u32> = Array::with_max_entries(4, 0);

/// Per IPv4 source: packets counted in the current 1s window.
#[map]
pub static RATE_LIMIT_V4: LruHashMap<[u8; 4], RateLimitCell> =
    LruHashMap::with_max_entries(8192, 0);

#[map]
pub static RATE_LIMIT_V6: LruHashMap<[u8; 16], RateLimitCell> =
    LruHashMap::with_max_entries(8192, 0);

/// Source prefixes considered "internal" for ingress RPF on an external interface.
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

/// Userspace-visible drop/pass counters (debug).
#[map]
pub static STATS: Array<u64> = Array::with_max_entries(2, 0);

pub const STAT_DROPS: u32 = 0;
pub const STAT_PASSES: u32 = 1;
