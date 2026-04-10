use inquire::Select;
use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;
use std::thread;

mod packet_handler;

fn setup_interfaces() -> (NetworkInterface, NetworkInterface) {
    let all_interfaces = datalink::interfaces();

    let wifi_options: Vec<String> = all_interfaces
        .iter()
        .filter(|iface| {
            let name = &iface.name;
            name.starts_with("wl") || name.starts_with("wlan") || name.starts_with("ra")
        })
        .map(|iface| format!("{} (MAC: {})", iface.name, iface.mac.unwrap_or_default()))
        .collect();

    if wifi_options.is_empty() {
        panic!("Wi-Fi interfaces are not found");
    }

    let wifi_selection = Select::new("Choose Wi-Fi interface (Source):", wifi_options)
        .prompt()
        .expect("Error on choosing Wi-Fi");

    let wifi_name = wifi_selection.split_whitespace().next().unwrap();
    let wifi_iface = all_interfaces
        .iter()
        .find(|i| i.name == wifi_name)
        .unwrap()
        .clone();

    let eth_options: Vec<String> = all_interfaces
        .iter()
        .filter(|iface| {
            let name = &iface.name;
            iface.name != wifi_name
                && (name.starts_with("eth") || name.starts_with("en") || name.starts_with("end"))
        })
        .map(|iface| format!("{} (MAC: {})", iface.name, iface.mac.unwrap_or_default()))
        .collect();

    if eth_options.is_empty() {
        panic!("Ethernet interfaces are not found");
    }

    let eth_selection = Select::new("Choose Ethernet interface (Destination):", eth_options)
        .prompt()
        .expect("Error on choosing Ethernet");

    let eth_name = eth_selection.split_whitespace().next().unwrap();
    let eth_iface = all_interfaces
        .iter()
        .find(|i| i.name == eth_name)
        .unwrap()
        .clone();

    (wifi_iface, eth_iface)
}

fn create_channel(
    iface: &NetworkInterface,
) -> (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>) {
    match datalink::channel(iface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => panic!("Error on creating channel for {}", iface.name),
    }
}

fn bridge_loop(
    src_name: &str,
    _dst_name: &str,
    rx: &mut Box<dyn DataLinkReceiver>,
    tx: &mut Box<dyn DataLinkSender>,
) {
    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(eth) = EthernetPacket::new(packet) {
                    if packet_handler::decide_fate(&eth, src_name) {
                        tx.send_to(packet, None);
                    }
                }
            }
            Err(e) => eprintln!("Error on {}: {}", src_name, e),
        }
    }
}

fn main() {
    let (wifi_iface, eth_iface) = setup_interfaces();

    println!("bridge start: {} <-> {}", wifi_iface.name, eth_iface.name);

    let (mut wifi_tx, mut wifi_rx) = create_channel(&wifi_iface);
    let (mut eth_tx, mut eth_rx) = create_channel(&eth_iface);

    let wifi_name_a = wifi_iface.name.clone();
    let eth_name_a = eth_iface.name.clone();

    let wifi_to_eth = thread::spawn(move || {
        bridge_loop(&wifi_name_a, &eth_name_a, &mut wifi_rx, &mut eth_tx);
    });

    let eth_name_b = eth_iface.name.clone();
    let wifi_name_b = wifi_iface.name.clone();

    let eth_to_wifi = thread::spawn(move || {
        bridge_loop(&eth_name_b, &wifi_name_b, &mut eth_rx, &mut wifi_tx);
    });

    wifi_to_eth.join().unwrap();
    eth_to_wifi.join().unwrap();
}
