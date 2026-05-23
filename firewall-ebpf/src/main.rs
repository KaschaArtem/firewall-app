#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{classifier, map, xdp},
    maps::Array,
    programs::{TcContext, XdpContext},
};

mod classifier;

#[map]
static CONFIG: Array<u32> = Array::with_max_entries(1, 0);

#[xdp]
pub fn firewall(ctx: XdpContext) -> u32 {
    let mode = CONFIG.get(0).map(|m| *m).unwrap_or(0);

    match classifier::check_packet_xdp(&ctx, mode) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[classifier]
pub fn firewall_egress(ctx: TcContext) -> i32 {
    let mode = CONFIG.get(0).map(|m| *m).unwrap_or(0);
    classifier::check_packet_tc(&ctx, mode)
}

// Handling panic for compiler
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// License for kernel
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
