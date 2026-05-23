mod decision;
mod packet;
mod verdict;

pub use verdict::{check_packet_tc, check_packet_xdp};
