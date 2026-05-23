use aya_ebpf::{
    bindings::xdp_action,
    macros::map,
    maps::HashMap,
    programs::{TcContext, XdpContext},
    EbpfContext,
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
    let eth_hdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };

    match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv4 => {
            let ip_hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, EthHdr::LEN)? };

            let src = unsafe { (*ip_hdr).src_addr };
            let dst = unsafe { (*ip_hdr).dst_addr };

            let src_key = IpAddress::ipv4(u32::from_be(src).to_be_bytes());
            let dst_key = IpAddress::ipv4(u32::from_be(dst).to_be_bytes());

            let src_clean = u32::from_be(src);
            let dst_clean = u32::from_be(dst);

            let mut src_in_map = false;
            let mut dst_in_map = false;
            let mut drop_packet = false;

            if firewall_mode == MODE_BLACKLIST {
                if unsafe { IP_MAP.get(&src_key) }.is_some() {
                    src_in_map = true;
                    drop_packet = true;
                } else if unsafe { IP_MAP.get(&dst_key) }.is_some() {
                    dst_in_map = true;
                    drop_packet = true;
                }
            } else if firewall_mode == MODE_WHITELIST {
                let src_found = unsafe { IP_MAP.get(&src_key) }.is_some();
                let dst_found = unsafe { IP_MAP.get(&dst_key) }.is_some();
                
                src_in_map = src_found;
                dst_in_map = dst_found;
                
                if !src_found || !dst_found {
                    drop_packet = true;
                }
            }

            if drop_packet {
                log_ipv4_drop(ctx, firewall_mode, src_clean, dst_clean, src_in_map, dst_in_map);
                return Ok(FilterVerdict::Drop);
            }

            info!(ctx, "IPv4 PASS: {:i} -> {:i}", src_clean, dst_clean);
        }

        EtherType::Ipv6 => {
            let ip_hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, EthHdr::LEN)? };

            let src = unsafe { (*ip_hdr).src_addr.in6_u.u6_addr8 };
            let dst = unsafe { (*ip_hdr).dst_addr.in6_u.u6_addr8 };

            let src_key = IpAddress::ipv6(src);
            let dst_key = IpAddress::ipv6(dst);
            
            let mut src_in_map = false;
            let mut dst_in_map = false;
            let mut drop_packet = false;

            if firewall_mode == MODE_BLACKLIST {
                if unsafe { IP_MAP.get(&src_key) }.is_some() {
                    src_in_map = true;
                    drop_packet = true;
                } else if unsafe { IP_MAP.get(&dst_key) }.is_some() {
                    dst_in_map = true;
                    drop_packet = true;
                }
            } else if firewall_mode == MODE_WHITELIST {
                let src_found = unsafe { IP_MAP.get(&src_key) }.is_some();
                let dst_found = unsafe { IP_MAP.get(&dst_key) }.is_some();

                src_in_map = src_found;
                dst_in_map = dst_found;

                if !src_found || !dst_found {
                    drop_packet = true;
                }
            }
        
            if drop_packet {
                log_ipv6_drop(ctx, firewall_mode, src, dst, src_in_map, dst_in_map);
                return Ok(FilterVerdict::Drop);
            }

            info!(ctx, "IPv6 PASS: {:i} -> {:i}", src, dst);
        }

        _ => {}
    }

    Ok(FilterVerdict::Pass)
}

fn log_ipv4_drop<C: EbpfContext>(
    ctx: &C,
    firewall_mode: u32,
    src: u32,
    dst: u32,
    src_in_map: bool,
    dst_in_map: bool,
) {
    if firewall_mode == MODE_BLACKLIST {
        if src_in_map {
            info!(ctx, "BLACKLIST DROP IPv4 src: {:i}", src);
        } else if dst_in_map {
            info!(ctx, "BLACKLIST DROP IPv4 dst: {:i}", dst);
        }
    } else if src_in_map {
        info!(ctx, "WHITELIST DROP IPv4 dst: {:i}", dst);
    } else {
        info!(ctx, "WHITELIST DROP IPv4 src: {:i}", src);
    }
}

fn log_ipv6_drop<C: EbpfContext>(
    ctx: &C,
    firewall_mode: u32,
    src: [u8; 16],
    dst: [u8; 16],
    src_in_map: bool,
    dst_in_map: bool,
) {
    if firewall_mode == MODE_BLACKLIST {
        if src_in_map {
            info!(ctx, "BLACKLIST DROP IPv6 src: {:i}", src);
        } else if dst_in_map {
            info!(ctx, "BLACKLIST DROP IPv6 dst: {:i}", dst);
        }
    } else if src_in_map {
        info!(ctx, "WHITELIST DROP IPv6 dst: {:i}", dst);
    } else {
        info!(ctx, "WHITELIST DROP IPv6 src: {:i}", src);
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
