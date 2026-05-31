//! Runtime glue: interface selection, config hot-reload, and BPF map updates.

mod interfaces;

use crate::bpf::apply_config_to_ebpf;
use crate::config::AppConfig;
use crate::observability::{SharedDecisionLog, SharedFileLogSettings};
use anyhow::Context as _;
use inquire::Select;
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

pub fn prompt_for_interface() -> anyhow::Result<String> {
    let interfaces = NetworkInterface::show().context("failed to get list of network interfaces")?;

    let all_names: Vec<String> = interfaces.into_iter().map(|i| i.name).collect();
    let iface_names = interfaces::list_physical_interface_names(all_names);

    if iface_names.is_empty() {
        return Err(anyhow::anyhow!(
            "no physical network interfaces found (Docker bridges, veth, and loopback are excluded)"
        ));
    }

    Select::new("Choose physical network interface:", iface_names)
        .with_help_message("↓ ↑ - navigation, ENTER - confirm")
        .prompt()
        .context("error on choosing network interface")
}

pub async fn apply_config(
    path: &str,
    shared_ebpf: &Arc<Mutex<aya::Ebpf>>,
    decision_log: &SharedDecisionLog,
    file_settings: &SharedFileLogSettings,
) -> anyhow::Result<()> {
    let config = AppConfig::load(path)?;
    let file_cfg = config.decision_log_file_settings();

    {
        let mut log = decision_log.lock().await;
        log.set_retention(config.decision_log_retention());
        log.set_max_entries(file_cfg.max_memory_events);
    }

    *file_settings.lock().await = file_cfg;

    let mut ebpf = shared_ebpf.lock().await;
    apply_config_to_ebpf(&mut ebpf, &config)?;

    let whitelist_count = config.get_whitelist_entries()?.len();
    let blacklist_count = config.get_blacklist_entries()?.len();

    println!(
        " -> Config reloaded. Mode: {}, log retention: {} min, max file: {} MB, rate: {} evt/s, whitelist: {}, blacklist: {}",
        config.mode.to_uppercase(),
        config.decision_log_retention_minutes,
        config.decision_log_max_file_mb,
        config.decision_log_max_events_per_second,
        whitelist_count,
        blacklist_count,
    );

    Ok(())
}

pub fn spawn_config_watcher(
    path: &'static str,
    shared_ebpf: Arc<Mutex<aya::Ebpf>>,
    decision_log: SharedDecisionLog,
    file_settings: SharedFileLogSettings,
) {
    tokio::task::spawn(async move {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);

        let mut watcher = notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            if let Ok(event) = res {
                if event.kind.is_modify() {
                    let _ = tx.try_send(());
                }
            }
        })
        .unwrap();

        use notify::Watcher as _;
        if let Err(e) = watcher.watch(Path::new(path), notify::RecursiveMode::NonRecursive) {
            log::error!("Failed to watch config file: {e}");
            return;
        }

        while rx.recv().await.is_some() {
            tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;
            while rx.try_recv().is_ok() {}

            log::info!("Config file modified. Reloading...");

            match apply_config(path, &shared_ebpf, &decision_log, &file_settings).await {
                Ok(_) => log::info!("Hot-reload successful!"),
                Err(e) => {
                    log::error!("INVALID CONFIGURATION DETECTED: {:#}", e);
                    log::error!("Firewall is still running on the PREVIOUS valid configuration.");
                }
            }
        }
    });
}
