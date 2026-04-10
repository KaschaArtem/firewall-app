use nfq::Verdict;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;

fn print_row(src: &str, dst: &str, proto: &str, info: &str) {
    println!("{:<45} {:<45} {:<8} {}", src, dst, proto, info);
}

fn handle_ipv4(payload: &[u8]) {
    if let Some(ip) = Ipv4Packet::new(payload) {
        print_row(
            &ip.get_source().to_string(),
            &ip.get_destination().to_string(),
            &ip.get_next_level_protocol().to_string(),
            "",
        );
    }
}

fn handle_ipv6(payload: &[u8]) {
    if let Some(ip) = Ipv6Packet::new(payload) {
        print_row(
            &ip.get_source().to_string(),
            &ip.get_destination().to_string(),
            &ip.get_next_header().to_string(),
            "",
        );
    }
}

fn handle_arp(arp: &ArpPacket) {}

pub fn decide_fate(payload: &[u8]) -> Verdict {
    if payload.is_empty() {
        return Verdict::Accept;
    }

    match payload.get(0).map(|b| b >> 4) {
        Some(4) => handle_ipv4(payload),
        Some(6) => handle_ipv6(payload),
        _ => {
            if let Some(arp) = ArpPacket::new(payload) {
                handle_arp(&arp);
            }
        }
    }
    Verdict::Accept
}
