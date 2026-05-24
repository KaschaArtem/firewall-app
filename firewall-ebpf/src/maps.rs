use aya_ebpf::{macros::map, maps::{Array, LpmTrie, RingBuf}};

#[map]
pub static CONFIG: Array<u32> = Array::with_max_entries(1, 0);

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
