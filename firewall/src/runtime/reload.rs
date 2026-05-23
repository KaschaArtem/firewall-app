use crate::bpf::{reload_ip_lists, set_mode};
use crate::config::AppConfig;
use crate::observability::SharedDecisionLog;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

pub async fn apply_config(
    path: &str,
    shared_ebpf: &Arc<Mutex<aya::Ebpf>>,
    decision_log: &SharedDecisionLog,
) -> anyhow::Result<()> {
    let config = AppConfig::load(path)?;
    let mode_value = config.get_ebpf_mode()?;

    {
        let mut log = decision_log.lock().await;
        log.set_retention(config.decision_log_retention());
    }

    let mut ebpf = shared_ebpf.lock().await;

    set_mode(&mut ebpf, mode_value)?;
    let (whitelist_count, blacklist_count) = reload_ip_lists(
        &mut ebpf,
        &config.get_whitelist_nets()?,
        &config.get_blacklist_nets()?,
    )?;

    println!(
        " -> Config reloaded. Mode: {}, retention: {} min, whitelist: {}, blacklist: {}",
        config.mode.to_uppercase(),
        config.decision_log_retention_minutes,
        whitelist_count,
        blacklist_count,
    );

    Ok(())
}

pub fn spawn_config_watcher(
    path: &'static str,
    shared_ebpf: Arc<Mutex<aya::Ebpf>>,
    decision_log: SharedDecisionLog,
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

            match apply_config(path, &shared_ebpf, &decision_log).await {
                Ok(_) => log::info!("Hot-reload successful!"),
                Err(e) => {
                    log::error!("INVALID CONFIGURATION DETECTED: {:#}", e);
                    log::error!("Firewall is still running on the PREVIOUS valid configuration.");
                }
            }
        }
    });
}
