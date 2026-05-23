use aya_ebpf::{
    bindings::xdp_action,
    macros::map,
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, Ipv6Hdr},
};

use firewall_common::IpAddress;

pub const MODE_BLACKLIST: u32 = 0;
pub const MODE_WHITELIST: u32 = 1;

#[map]
static IP_MAP: HashMap<IpAddress, u8> = HashMap::with_max_entries(1024, 0);

pub fn check_packet(ctx: &XdpContext, firewall_mode: u32) -> Result<u32, u32> {
    let eth_hdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };

    match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv4 => {
            let ip_hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, EthHdr::LEN)? };
            
            let src = unsafe { (*ip_hdr).src_addr };
            let dst = unsafe { (*ip_hdr).dst_addr };

            let key = IpAddress::ipv4(u32::from_be(src).to_be_bytes());
            let is_ip_in_map = unsafe { IP_MAP.get(&key) }.is_some();

            let src_clean = u32::from_be(src);
            let dst_clean = u32::from_be(dst);

            if firewall_mode == MODE_BLACKLIST && is_ip_in_map {
                info!(ctx, "BLACKLIST DROP IPv4: {:i}", src_clean);
                return Ok(xdp_action::XDP_DROP);
            } else if firewall_mode == MODE_WHITELIST && !is_ip_in_map {
                info!(ctx, "WHITELIST DROP IPv4: {:i}", src_clean);
                return Ok(xdp_action::XDP_DROP);
            }

            info!(ctx, "IPv4 PASS: {:i} -> {:i}", src_clean, dst_clean);
        }

        EtherType::Ipv6 => {
            let ip_hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, EthHdr::LEN)? };
            
            let src = unsafe { (*ip_hdr).src_addr.in6_u.u6_addr8 };
            let dst = unsafe { (*ip_hdr).dst_addr.in6_u.u6_addr8 };

            let key = IpAddress::ipv6(src);
            let is_ip_in_map = unsafe { IP_MAP.get(&key) }.is_some();

            if firewall_mode == MODE_BLACKLIST && is_ip_in_map {
                info!(ctx, "BLACKLIST DROP IPv6: {:i}", src);
                return Ok(xdp_action::XDP_DROP);
            } else if firewall_mode == MODE_WHITELIST && !is_ip_in_map {
                info!(ctx, "WHITELIST DROP IPv6: {:i}", src);
                return Ok(xdp_action::XDP_DROP);
            }

            info!(ctx, "IPv6 PASS: {:i} -> {:i}", src, dst);
        }

        _ => {}
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, u32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(xdp_action::XDP_ABORTED);
    }

    Ok((start + offset) as *const T)
}