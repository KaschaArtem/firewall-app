use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::EthernetPacket;

fn main() {
    let interface_name = "wlan0";
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Error: interface is not found");

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unsupported channel type"),
        Err(e) => panic!("Error on creating channel: {}", e),
    };

    println!("Start interface listening {}...", interface_name);

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(eth_packet) = EthernetPacket::new(packet) {
                    println!(
                        "Packet: {} -> {} | type: {:?}",
                        eth_packet.get_source(),
                        eth_packet.get_destination(),
                        eth_packet.get_ethertype()
                    );
                }
            }
            Err(e) => {
                panic!("Error on read packet: {}", e);
            }
        }
    }
}
