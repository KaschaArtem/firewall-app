use nfq::Verdict;
use pnet::packet::Packet;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

pub fn decide_fate(payload: &[u8]) -> Verdict {
    if payload.is_empty() {
        return Verdict::Accept;
    }

    // Определяем версию IP (первые 4 бита первого байта)
    match payload.get(0).map(|b| b >> 4) {
        Some(4) => {
            if let Some(ip) = Ipv4Packet::new(payload) {
                handle_ipv4_packet(&ip);
            }
            Verdict::Accept
        }
        Some(6) => {
            if let Some(ip) = Ipv6Packet::new(payload) {
                handle_ipv6_packet(&ip);
            }
            Verdict::Accept
        }
        _ => Verdict::Accept,
    }
}

fn handle_ipv4_packet(ip: &Ipv4Packet) {
    let src = ip.get_source();
    let dst = ip.get_destination();
    let proto = ip.get_next_level_protocol();

    match proto {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp) = TcpPacket::new(ip.payload()) {
                println!(
                    "[TCP] {}:{} -> {}:{}",
                    src,
                    tcp.get_source(),
                    dst,
                    tcp.get_destination()
                );
            }
        }
        IpNextHeaderProtocols::Udp => {
            if let Some(udp) = UdpPacket::new(ip.payload()) {
                println!(
                    "[UDP] {}:{} -> {}:{}",
                    src,
                    udp.get_source(),
                    dst,
                    udp.get_destination()
                );
            }
        }
        IpNextHeaderProtocols::Icmp => {
            if let Some(icmp) = IcmpPacket::new(ip.payload()) {
                println!(
                    "[ICMPv4] {} -> {} | Type: {:?}",
                    src,
                    dst,
                    icmp.get_icmp_type()
                );
            }
        }
        _ => println!("[IPv4] {} -> {} | Proto: {:?}", src, dst, proto),
    }
}

fn handle_ipv6_packet(ip: &Ipv6Packet) {
    let src = ip.get_source();
    let dst = ip.get_destination();
    let proto = ip.get_next_header();

    match proto {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp) = TcpPacket::new(ip.payload()) {
                println!(
                    "[TCPv6] {}:{} -> {}:{}",
                    src,
                    tcp.get_source(),
                    dst,
                    tcp.get_destination()
                );
            }
        }
        IpNextHeaderProtocols::Udp => {
            if let Some(udp) = UdpPacket::new(ip.payload()) {
                println!(
                    "[UDPv6] {}:{} -> {}:{}",
                    src,
                    udp.get_source(),
                    dst,
                    udp.get_destination()
                );
            }
        }
        IpNextHeaderProtocols::Icmpv6 => {
            if let Some(icmp) = Icmpv6Packet::new(ip.payload()) {
                println!(
                    "[ICMPv6] {} -> {} | Type: {:?}",
                    src,
                    dst,
                    icmp.get_icmpv6_type()
                );
            }
        }
        _ => println!("[IPv6] {} -> {} | Next Header: {:?}", src, dst, proto),
    }
}
