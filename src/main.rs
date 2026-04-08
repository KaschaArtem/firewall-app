use inquire::Select;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::DataLinkReceiver;
use pnet::datalink::NetworkInterface;
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

fn setup_receiver() -> (NetworkInterface, Box<dyn DataLinkReceiver>) {
    let all_interfaces = datalink::interfaces();

    let wl_interfaces: Vec<NetworkInterface> = all_interfaces
        .into_iter()
        .filter(|iface| {
            let name = &iface.name;
            name.starts_with("wl") || name.starts_with("wlan") || name.starts_with("ra")
        })
        .collect();

    if wl_interfaces.is_empty() {
        panic!("Wireless interfaces are not found");
    }

    let options: Vec<String> = wl_interfaces
        .iter()
        .map(|iface| format!("{} (MAC: {})", iface.name, iface.mac.unwrap_or_default()))
        .collect();

    let selection = Select::new("Choose wireless interface:", options)
        .prompt()
        .expect("Cancelled or error");

    let interface_name = selection.split_whitespace().next().unwrap();

    let selected_interface = wl_interfaces
        .into_iter()
        .find(|i| i.name == interface_name)
        .expect("Error choice");

    let (_, rx) = match datalink::channel(&selected_interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unsupported channel type"),
        Err(e) => panic!("Error on creating channel: {}", e),
    };

    (selected_interface, rx)
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

fn main() {
    let (_iface, mut rx) = setup_receiver();

    println!("Start interface listening ...");

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(eth) = EthernetPacket::new(packet) {
                    match eth.get_ethertype() {
                        EtherTypes::Ipv4 => {
                            if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                                handle_ipv4_packet(&ip);
                            }
                        }
                        EtherTypes::Ipv6 => {
                            if let Some(ip) = Ipv6Packet::new(eth.payload()) {
                                handle_ipv6_packet(&ip);
                            }
                        }
                        EtherTypes::Arp => println!(
                            "[ARP] MAC: {} -> {}",
                            eth.get_source(),
                            eth.get_destination()
                        ),
                        _ => {}
                    }
                }
            }
            Err(e) => println!("Error: {}", e),
        }
    }
}
