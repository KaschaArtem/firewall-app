//! eBPF program entry points for ingress XDP and egress TC.

#![no_std]
#![no_main]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{classifier, xdp},
    programs::{TcContext, XdpContext},
};

mod filter;
mod maps;
mod packet;

use maps::CONFIG;

#[xdp]
pub fn ingress_xdp(ctx: XdpContext) -> u32 {
    let mode = CONFIG.get(0).map(|m| *m).unwrap_or(0);

    match filter::check_packet_xdp(&ctx, mode) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[classifier]
pub fn egress_tc(ctx: TcContext) -> i32 {
    let mode = CONFIG.get(0).map(|m| *m).unwrap_or(0);
    filter::check_packet_tc(&ctx, mode)
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
