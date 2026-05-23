use aya_ebpf::programs::{TcContext, XdpContext};

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

#[inline(always)]
pub unsafe fn ptr_at<C: PacketData, T>(ctx: &C, offset: usize) -> Result<*const T, u32> {
    use aya_ebpf::bindings::xdp_action::XDP_ABORTED;
    use core::mem;

    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(XDP_ABORTED);
    }

    Ok((start + offset) as *const T)
}
