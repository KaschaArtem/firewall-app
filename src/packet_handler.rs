use pnet::packet::Packet;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;

pub fn decide_fate(eth: &EthernetPacket, src_iface: &str) -> bool {
    match eth.get_ethertype() {
        EtherTypes::Arp => {
            if let Some(arp) = ArpPacket::new(eth.payload()) {
                println!(
                    "[ARP] {} | {} ({}) -> {} ({})",
                    src_iface,
                    arp.get_sender_proto_addr(),
                    arp.get_sender_hw_addr(),
                    arp.get_target_proto_addr(),
                    arp.get_target_hw_addr()
                );
            }
            true
        }
        EtherTypes::Ipv4 => {
            if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                println!(
                    "{:<40} {:<40} {:<8}",
                    ipv4.get_source().to_string(),
                    ipv4.get_destination().to_string(),
                    ipv4.get_next_level_protocol().to_string()
                );
            }
            true
        }
        EtherTypes::Ipv6 => {
            if let Some(ipv6) = Ipv6Packet::new(eth.payload()) {
                println!(
                    "{:<40} {:<40} {:<8}",
                    ipv6.get_source().to_string(),
                    ipv6.get_destination().to_string(),
                    ipv6.get_next_header().to_string(),
                );
            }
            true
        }
        _ => true,
    }
}
