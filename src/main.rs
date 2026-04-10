use nfq::Queue;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

mod packet_handler;

struct IptablesGuard;

impl IptablesGuard {
    fn new() -> Self {
        println!("Setting up iptables");
        Self::run_iptables("-I");
        IptablesGuard
    }

    pub fn run_iptables(action: &str) {
        let rules = [("INPUT", "0"), ("OUTPUT", "0")];
        let commands = ["iptables", "ip6tables"];

        for cmd_name in commands {
            for (chain, qnum) in rules {
                let status = Command::new("sudo")
                    .arg(cmd_name) // вызываем сначала iptables, потом ip6tables
                    .arg(action)
                    .arg(chain)
                    .arg("-j")
                    .arg("NFQUEUE")
                    .arg("--queue-num")
                    .arg(qnum)
                    .status();

                if let Err(e) = status {
                    eprintln!("Failed to execute {}: {}", cmd_name, e);
                }
            }
        }
    }
}

impl Drop for IptablesGuard {
    fn drop(&mut self) {
        println!("\n[Drop] Cleaning up iptables...");
        Self::run_iptables("-D");
    }
}

fn main() -> std::io::Result<()> {
    let _guard = IptablesGuard::new();

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        println!("\n[SIGINT] Stop program triggered");
        println!("Cleaning up iptables...");
        IptablesGuard::run_iptables("-D");
        std::process::exit(0);
    })
    .expect("Error setting up Ctrl-C handler");

    let mut queue = Queue::open()?;
    queue.bind(0)?;

    println!("Start interface listening...");

    // let mut count = 0;

    loop {
        match queue.recv() {
            Ok(mut msg) => {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                let payload = msg.get_payload();
                msg.set_verdict(packet_handler::decide_fate(payload));
                // println!("{}", count);
                // count += 1;
                // msg.set_verdict(nfq::Verdict::Accept);
                if let Err(e) = queue.verdict(msg) {
                    eprintln!("Error sending verdict: {}", e);
                }
            }
            Err(e) => {
                eprintln!("Error on getting packet: {}", e);
                break;
            }
        }
    }

    Ok(())
}
