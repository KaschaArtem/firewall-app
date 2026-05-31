//! Per-source IP packet rate limiting.

use aya_ebpf::{helpers::bpf_ktime_get_ns, maps::LruHashMap};
use firewall_common::{RateLimitState, CONFIG_INDEX_RATE_PPS};

use crate::maps::{config_u32, RATE_LIMIT_V4, RATE_LIMIT_V6};

const WINDOW_NS: u64 = 1_000_000_000;

#[inline(always)]
fn limit_pps() -> u32 {
    config_u32(CONFIG_INDEX_RATE_PPS)
}

#[inline(always)]
fn over_limit<const N: usize>(
    map: &LruHashMap<[u8; N], RateLimitState>,
    src: [u8; N],
    limit: u32,
    now: u64,
) -> bool {
    let mut state = unsafe {
        map.get(&src)
            .copied()
            .unwrap_or(RateLimitState::default())
    };

    if now.wrapping_sub(state.window_start_ns) >= WINDOW_NS {
        state.window_start_ns = now;
        state.count = 1;
    } else {
        state.count = state.count.saturating_add(1);
    }

    let _ = map.insert(&src, &state, 0);
    state.count > limit
}

#[inline(always)]
fn source_exceeded<const N: usize>(
    map: &LruHashMap<[u8; N], RateLimitState>,
    src: [u8; N],
) -> bool {
    let limit = limit_pps();
    if limit == 0 {
        return false;
    }
    let now = unsafe { bpf_ktime_get_ns() };
    over_limit(map, src, limit, now)
}

#[inline(always)]
pub fn ipv4_exceeded(src: [u8; 4]) -> bool {
    source_exceeded(&RATE_LIMIT_V4, src)
}

#[inline(always)]
pub fn ipv6_exceeded(src: [u8; 16]) -> bool {
    source_exceeded(&RATE_LIMIT_V6, src)
}
