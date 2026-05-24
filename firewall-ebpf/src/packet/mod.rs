//! Packet access primitives shared by XDP and TC.

use aya_ebpf::programs::{TcContext, XdpContext};
use core::mem;

pub mod l3;

pub use l3::{
    detect_tc_l3, parse_from_ethernet, parse_from_tc_hint, L3ParseOutcome, L4Info, Ipv4Packet,
    Ipv6Packet, L3Packet,
};

/// Bounds-checked access to `ctx.data()` / `ctx.data_end()`.
pub trait PacketData {
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

/// Read bytes via direct map (XDP) or `bpf_skb_load_bytes` (TC).
pub trait PortReader {
    fn read_u8(&self, offset: usize) -> Option<u8>;
    fn read_u16_be(&self, offset: usize) -> Option<u16>;
    /// TC: `data`/`data_end` are unreliable for L4; use load and skip bounds pre-check.
    fn uses_skb_load(&self) -> bool;
}

impl PortReader for XdpContext {
    fn uses_skb_load(&self) -> bool {
        false
    }

    fn read_u8(&self, offset: usize) -> Option<u8> {
        unsafe { ptr_at::<_, u8>(self, offset).ok().map(|p| *p) }
    }

    fn read_u16_be(&self, offset: usize) -> Option<u16> {
        let hi = self.read_u8(offset)?;
        let lo = self.read_u8(offset + 1)?;
        Some((u16::from(hi) << 8) | u16::from(lo))
    }
}

impl PortReader for TcContext {
    fn uses_skb_load(&self) -> bool {
        true
    }

    fn read_u8(&self, offset: usize) -> Option<u8> {
        self.load::<u8>(offset).ok()
    }

    fn read_u16_be(&self, offset: usize) -> Option<u16> {
        let hi = self.read_u8(offset)?;
        let lo = self.read_u8(offset + 1)?;
        Some((u16::from(hi) << 8) | u16::from(lo))
    }
}

#[inline(always)]
pub unsafe fn ptr_at<C: PacketData, T>(ctx: &C, offset: usize) -> Result<*const T, u32> {
    use aya_ebpf::bindings::xdp_action;

    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(xdp_action::XDP_ABORTED);
    }

    Ok((start + offset) as *const T)
}
