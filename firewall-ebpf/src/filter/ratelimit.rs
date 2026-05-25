//! Per-source IP packet rate limiting (fixed 1-second window).

use aya_ebpf::{helpers::bpf_ktime_get_ns, maps::LruHashMap};
use firewall_common::CONFIG_INDEX_RATE_PPS;

use crate::maps::{RateLimitCell, CONFIG, RATE_LIMIT_V4, RATE_LIMIT_V6};

const NS_PER_SEC: u64 = 1_000_000_000;

#[inline(always)]
fn rate_limit_per_window() -> u32 {
    CONFIG
        .get(CONFIG_INDEX_RATE_PPS)
        .map(|v| *v)
        .unwrap_or(0)
}

#[inline(always)]
fn update_and_exceeded<const N: usize>(
    map: &LruHashMap<[u8; N], RateLimitCell>,
    key: [u8; N],
    now: u64,
    limit: u32,
) -> bool {
    let mut state = unsafe {
        map.get(&key)
            .copied()
            .unwrap_or(RateLimitCell {
                window_start_ns: 0,
                count: 0,
            })
    };

    if now.wrapping_sub(state.window_start_ns) >= NS_PER_SEC {
        state.window_start_ns = now;
        state.count = 1;
    } else {
        state.count = state.count.saturating_add(1);
    }

    let _ = map.insert(&key, &state, 0);
    state.count > limit
}

#[inline(always)]
pub fn ipv4_exceeded(src: [u8; 4]) -> bool {
    let limit = rate_limit_per_window();
    if limit == 0 {
        return false;
    }
    let now = unsafe { bpf_ktime_get_ns() };
    update_and_exceeded(&RATE_LIMIT_V4, src, now, limit)
}

#[inline(always)]
pub fn ipv6_exceeded(src: [u8; 16]) -> bool {
    let limit = rate_limit_per_window();
    if limit == 0 {
        return false;
    }
    let now = unsafe { bpf_ktime_get_ns() };
    update_and_exceeded(&RATE_LIMIT_V6, src, now, limit)
}
