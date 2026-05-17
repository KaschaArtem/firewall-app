use anyhow::Context as _;
use aya::maps::Array;
use aya::programs::{Xdp, XdpFlags};
use inquire::Select;
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
#[rustfmt::skip]
use log::{debug, error, info, warn};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::signal;

mod config;
use config::AppConfig;

const CONFIG_FILE_PATH: &str = "config.yaml";

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

    // Logger initialization
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

    // Loading program in eBPF
    let program: &mut Xdp = ebpf.program_mut("firewall").unwrap().try_into()?;
    program.load()?;
    
    program.attach(&selected_iface, XdpFlags::default())
        .context("failed to attach the XDP program")?;

    // Initial configuration
    let shared_ebpf = Arc::new(Mutex::new(ebpf));

    reload_config_in_bpf(CONFIG_FILE_PATH, &shared_ebpf)
        .await
        .context("Failed to apply initial configuration. Check your config.yaml syntax and values.")?;

    // Handling Hot Reload on config cahnge
    let ebpf_clone = shared_ebpf.clone();
    tokio::task::spawn(async move {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);

        let mut watcher = notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            if let Ok(event) = res {
                if event.kind.is_modify() {
                    let _ = tx.try_send(());
                }
            }
        }).unwrap();

        use notify::Watcher as _;
        if let Err(e) = watcher.watch(Path::new(CONFIG_FILE_PATH), notify::RecursiveMode::NonRecursive) {
            error!("Failed to watch config file: {e}");
            return;
        }

        while rx.recv().await.is_some() {
            tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;
            while rx.try_recv().is_ok() {}

            info!("Config file modified. Reloading...");
            
            match reload_config_in_bpf(CONFIG_FILE_PATH, &ebpf_clone).await {
                Ok(_) => {
                    info!("Hot-reload successful!");
                }
                Err(e) => {
                    error!("INVALID CONFIGURATION DETECTED: {:#}", e);
                    error!("Firewall is still running on the PREVIOUS valid configuration.");
                }
            }
        }
    });

    // Handling Ctral-C exit
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

async fn reload_config_in_bpf(
    path: &str, 
    shared_ebpf: &Arc<Mutex<aya::Ebpf>>
) -> anyhow::Result<()> {
    let config = AppConfig::load(path)?;
    let mode_value = config.get_ebpf_mode()?;

    let mut ebpf = shared_ebpf.lock().await;
    
    let mut config_map: Array<_, u32> = Array::try_from(ebpf.map_mut("CONFIG").unwrap())
        .context("failed to find CONFIG map")?;

    config_map.set(0, mode_value, 0)
        .context("failed to set mode in CONFIG map")?;

    println!(" -> Config reloaded successfully. Mode set to: {}", config.mode.to_uppercase());

    Ok(())
}