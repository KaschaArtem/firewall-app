/// Ring buffer record written by eBPF, read by the agent.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PacketDecisionEvent {
    pub ts_ns: u64,
    pub action: u8,
    pub family: u8,
    pub reason: u8,
    pub direction: u8,
    pub src: [u8; 16],
    pub dst: [u8; 16],
}

pub const ACTION_PASS: u8 = 0;
pub const ACTION_DROP: u8 = 1;

pub const DIRECTION_INGRESS: u8 = 0;
pub const DIRECTION_EGRESS: u8 = 1;

pub const REASON_ALL_PASS: u8 = 0;
pub const REASON_ALL_DROP: u8 = 1;
pub const REASON_BLACKLIST: u8 = 2;
pub const REASON_WHITELIST: u8 = 3;
pub const REASON_DEFAULT: u8 = 4;
pub const REASON_NON_IP: u8 = 5;

pub const FAMILY_IPV4: u8 = 4;
pub const FAMILY_IPV6: u8 = 6;

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketDecisionEvent {}
