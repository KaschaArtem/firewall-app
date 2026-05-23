use aya_ebpf::{
    bindings::xdp_action,
    macros::map,
    maps::{lpm_trie::Key, LpmTrie},
    programs::{TcContext, XdpContext},
    EbpfContext,
};
use aya_log_ebpf::info;
use core::mem;
use firewall_common::{MODE_ALL_DROP, MODE_ALL_PASS, MODE_DEFAULT_DROP};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, Ipv6Hdr},
};

#[map]
static WHITELIST_V4: LpmTrie<[u8; 4], u8> = LpmTrie::with_max_entries(1024, 0);

#[map]
static WHITELIST_V6: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(1024, 0);

#[map]
static BLACKLIST_V4: LpmTrie<[u8; 4], u8> = LpmTrie::with_max_entries(1024, 0);

#[map]
static BLACKLIST_V6: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(1024, 0);

#[derive(PartialEq, Eq)]
pub enum FilterVerdict {
    Pass,
    Drop,
}

trait PacketData {
    fn data(&self) -> usize;
    fn data_end(&self) -> usize;
}

impl PacketData for XdpContext {
    fn data(&self) -> usize {
        self.data()
    }

    fn data_end(&self) -> usize {
        self.data_end()
    }
}

impl PacketData for TcContext {
    fn data(&self) -> usize {
        self.data()
    }

    fn data_end(&self) -> usize {
        self.data_end()
    }
}

pub fn check_packet_xdp(ctx: &XdpContext, firewall_mode: u32) -> Result<u32, u32> {
    match filter_packet(ctx, firewall_mode) {
        Ok(FilterVerdict::Pass) => Ok(xdp_action::XDP_PASS),
        Ok(FilterVerdict::Drop) => Ok(xdp_action::XDP_DROP),
        Err(code) => Err(code),
    }
}

pub fn check_packet_tc(ctx: &TcContext, firewall_mode: u32) -> i32 {
    use aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_SHOT};

    match filter_packet(ctx, firewall_mode) {
        Ok(FilterVerdict::Pass) => TC_ACT_OK as i32,
        Ok(FilterVerdict::Drop) => TC_ACT_SHOT as i32,
        Err(_) => TC_ACT_SHOT as i32,
    }
}

fn filter_packet<C>(ctx: &C, firewall_mode: u32) -> Result<FilterVerdict, u32>
where
    C: PacketData + EbpfContext,
{
    if firewall_mode == MODE_ALL_PASS {
        return Ok(FilterVerdict::Pass);
    }
    if firewall_mode == MODE_ALL_DROP {
        return Ok(FilterVerdict::Drop);
    }

    let eth_hdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };

    match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv4 => filter_ipv4(ctx, firewall_mode),
        EtherType::Ipv6 => filter_ipv6(ctx, firewall_mode),
        _ => Ok(FilterVerdict::Pass),
    }
}

fn filter_ipv4<C>(ctx: &C, firewall_mode: u32) -> Result<FilterVerdict, u32>
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
    let mut src_blacklisted = false;
    let mut dst_blacklisted = false;

    // If-else chain only: do not combine map lookups with `||` (verifier rejects pointer OR).
    if BLACKLIST_V4.get(&Key::new(32, src_octets)).is_some() {
        src_blacklisted = true;
        is_drop = true;
    } else if BLACKLIST_V4.get(&Key::new(32, dst_octets)).is_some() {
        dst_blacklisted = true;
        is_drop = true;
    } else if WHITELIST_V4.get(&Key::new(32, src_octets)).is_some() {
        is_drop = false;
    } else if WHITELIST_V4.get(&Key::new(32, dst_octets)).is_some() {
        is_drop = false;
    } else if firewall_mode == MODE_DEFAULT_DROP {
        is_drop = true;
    }

    if is_drop {
        log_ipv4_drop(
            ctx,
            firewall_mode,
            src_clean,
            dst_clean,
            src_blacklisted,
            dst_blacklisted,
        );
        return Ok(FilterVerdict::Drop);
    }

    info!(ctx, "IPv4 PASS: {:i} -> {:i}", src_clean, dst_clean);
    Ok(FilterVerdict::Pass)
}

fn filter_ipv6<C>(ctx: &C, firewall_mode: u32) -> Result<FilterVerdict, u32>
where
    C: PacketData + EbpfContext,
{
    let ip_hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, EthHdr::LEN)? };

    let src = unsafe { (*ip_hdr).src_addr.in6_u.u6_addr8 };
    let dst = unsafe { (*ip_hdr).dst_addr.in6_u.u6_addr8 };

    let mut is_drop = false;
    let mut src_blacklisted = false;
    let mut dst_blacklisted = false;

    if BLACKLIST_V6.get(&Key::new(128, src)).is_some() {
        src_blacklisted = true;
        is_drop = true;
    } else if BLACKLIST_V6.get(&Key::new(128, dst)).is_some() {
        dst_blacklisted = true;
        is_drop = true;
    } else if WHITELIST_V6.get(&Key::new(128, src)).is_some() {
        is_drop = false;
    } else if WHITELIST_V6.get(&Key::new(128, dst)).is_some() {
        is_drop = false;
    } else if firewall_mode == MODE_DEFAULT_DROP {
        is_drop = true;
    }

    if is_drop {
        log_ipv6_drop(
            ctx,
            firewall_mode,
            src,
            dst,
            src_blacklisted,
            dst_blacklisted,
        );
        return Ok(FilterVerdict::Drop);
    }

    info!(ctx, "IPv6 PASS: {:i} -> {:i}", src, dst);
    Ok(FilterVerdict::Pass)
}

fn log_ipv4_drop<C: EbpfContext>(
    ctx: &C,
    firewall_mode: u32,
    src: u32,
    dst: u32,
    src_blacklist: bool,
    dst_blacklist: bool,
) {
    if src_blacklist {
        info!(ctx, "BLACKLIST DROP IPv4 src: {:i}", src);
    } else if dst_blacklist {
        info!(ctx, "BLACKLIST DROP IPv4 dst: {:i}", dst);
    } else if firewall_mode == MODE_DEFAULT_DROP {
        info!(ctx, "DEFAULT DROP IPv4: {:i} -> {:i}", src, dst);
    }
}

fn log_ipv6_drop<C: EbpfContext>(
    ctx: &C,
    firewall_mode: u32,
    src: [u8; 16],
    dst: [u8; 16],
    src_blacklist: bool,
    dst_blacklist: bool,
) {
    if src_blacklist {
        info!(ctx, "BLACKLIST DROP IPv6 src: {:i}", src);
    } else if dst_blacklist {
        info!(ctx, "BLACKLIST DROP IPv6 dst: {:i}", dst);
    } else if firewall_mode == MODE_DEFAULT_DROP {
        info!(ctx, "DEFAULT DROP IPv6: {:i} -> {:i}", src, dst);
    }
}

#[inline(always)]
unsafe fn ptr_at<C: PacketData, T>(ctx: &C, offset: usize) -> Result<*const T, u32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(xdp_action::XDP_ABORTED);
    }

    Ok((start + offset) as *const T)
}
