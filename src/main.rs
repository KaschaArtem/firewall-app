use inquire::Select;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::NetworkInterface;
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

fn main() {
    let all_interfaces = datalink::interfaces();

    let wl_interfaces: Vec<NetworkInterface> = all_interfaces
        .into_iter()
        .filter(|iface| {
            let name = &iface.name;
            name.starts_with("wl") || name.starts_with("wlan") || name.starts_with("ra")
        })
        .collect();

    if wl_interfaces.is_empty() {
        println!("Wireless interfaces are not found");
        return;
    }

    let options: Vec<String> = wl_interfaces
        .iter()
        .map(|iface| format!("{} (MAC: {})", iface.name, iface.mac.unwrap_or_default()))
        .collect();

    let selection = match Select::new("Choose wireless interface:", options).prompt() {
        Ok(s) => s,
        Err(_) => {
            println!("Cancelled");
            return;
        }
    };

    let interface_name = selection.split_whitespace().next().unwrap();
    let selected_interface = wl_interfaces
        .into_iter()
        .find(|i| i.name == interface_name)
        .expect("Error choice");

    let (_, mut rx) = match datalink::channel(&selected_interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unsupported channel type"),
        Err(e) => panic!("Error on creating channel: {}", e),
    };

    println!("Start interface listening {}...", interface_name);

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(eth) = EthernetPacket::new(packet) {
                    match eth.get_ethertype() {
                        EtherTypes::Ipv4 => {
                            if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                                let proto = ip.get_next_level_protocol();
                                let src = ip.get_source();
                                let dst = ip.get_destination();

                                match proto {
                                    IpNextHeaderProtocols::Tcp => {
                                        if let Some(tcp) = TcpPacket::new(ip.payload()) {
                                            println!(
                                                "[TCP] {}:{} -> {}:{} | Len: {}",
                                                src,
                                                tcp.get_source(),
                                                dst,
                                                tcp.get_destination(),
                                                tcp.payload().len()
                                            );
                                        }
                                    }
                                    IpNextHeaderProtocols::Udp => {
                                        if let Some(udp) = UdpPacket::new(ip.payload()) {
                                            println!(
                                                "[UDP] {}:{} -> {}:{} | Len: {}",
                                                src,
                                                udp.get_source(),
                                                dst,
                                                udp.get_destination(),
                                                udp.payload().len()
                                            );
                                        }
                                    }
                                    IpNextHeaderProtocols::Icmp => {
                                        println!("[ICMP] {} -> {}", src, dst);
                                    }
                                    _ => {
                                        println!("[IPv4] {} -> {} | Proto: {:?}", src, dst, proto);
                                    }
                                }
                            }
                        }
                        EtherTypes::Arp => {
                            println!("[ARP] ...");
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => println!("Error: {}", e),
        }
    }
}
