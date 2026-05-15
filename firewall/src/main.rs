use anyhow::Context as _;
use aya::programs::{Xdp, XdpFlags};
use inquire::Select;
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let selected_iface = prompt_for_interface()?;

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/firewall"
    )))?;

    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let program: &mut Xdp = ebpf.program_mut("firewall").unwrap().try_into()?;
    program.load()?;
    
    program.attach(&selected_iface, XdpFlags::default())
        .context("failed to attach the XDP program")?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

fn prompt_for_interface() -> anyhow::Result<String> {
    let interfaces = NetworkInterface::show()
        .context("failed to get list of network interfaces")?;
    
    let iface_names: Vec<String> = interfaces
        .into_iter()
        .map(|i| i.name)
        .collect();

    if iface_names.is_empty() {
        return Err(anyhow::anyhow!("network interfaces are not found"));
    }

    let selection = Select::new("Choose network interface:", iface_names)
        .with_help_message("↓ ↑ - navigation, ENTER - confirm")
        .prompt()
        .context("error on choosing network interface")?;

    Ok(selection)
}
