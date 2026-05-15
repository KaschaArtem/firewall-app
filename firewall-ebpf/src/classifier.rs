use aya_ebpf::bindings::xdp_action;
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, Ipv6Hdr},
};

pub fn check_packet(ctx: &XdpContext) -> Result<u32, u32> {
    let eth_hdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };

    match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv4 => {
            let ip_hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, EthHdr::LEN)? };
            
            let src = unsafe { (*ip_hdr).src_addr };
            let dst = unsafe { (*ip_hdr).dst_addr };

            info!(ctx, "IPv4: {:i} -> {:i}", src, dst);
        }

        EtherType::Ipv6 => {
            let ip_hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, EthHdr::LEN)? };
            
            let src = unsafe { (*ip_hdr).src_addr.in6_u.u6_addr8 };
            let dst = unsafe { (*ip_hdr).dst_addr.in6_u.u6_addr8 };

            info!(ctx, "IPv6: {:i} -> {:i}", src, dst);
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