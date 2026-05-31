use anyhow::Context as _;
use log::info;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::signal;
use tokio::sync::Mutex;

mod bpf;
mod config;
mod observability;
mod runtime;

use observability::{
    format_local_timestamp, spawn_file_logger, spawn_ringbuf_reader, spawn_stats_poller,
    DecisionLog, SharedDecisionLog, SharedFileLogSettings, LOG_PATH,
};
use runtime::{apply_config, prompt_for_interface, spawn_config_watcher};

const CONFIG_PATH: &str = "config.yaml";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let interface = prompt_for_interface()?;

    bpf::raise_memlock_limit();

    let mut ebpf = bpf::load_object()?;

    let initial_config = config::AppConfig::load(CONFIG_PATH)?;
    let file_settings: SharedFileLogSettings =
        Arc::new(Mutex::new(initial_config.decision_log_file_settings()));

    bpf::apply_config_to_ebpf(&mut ebpf, &initial_config)
        .context("failed to apply configuration to BPF maps")?;

    let file_log = spawn_file_logger(file_settings.clone())
        .context("failed to start file decision logger")?;

    let file_cfg = initial_config.decision_log_file_settings();
    let decision_log: SharedDecisionLog = Arc::new(Mutex::new(DecisionLog::new(
        initial_config.decision_log_retention(),
        file_cfg.max_memory_events,
    )));

    bpf::attach_programs(&mut ebpf, &interface)
        .context("failed to attach eBPF programs")?;

    let decisions_map = ebpf
        .take_map("DECISIONS")
        .ok_or_else(|| anyhow::anyhow!("DECISIONS ring buffer map not found"))?;
    let _ringbuf_task = spawn_ringbuf_reader(decisions_map, decision_log.clone(), file_log)
        .context("failed to start decision log reader")?;

    let shared_ebpf = Arc::new(Mutex::new(ebpf));
    let ebpf_for_summary = shared_ebpf.clone();
    spawn_stats_poller(shared_ebpf.clone());

    info!(
        "Attached ingress XDP and egress TC on {interface} (inbound + outbound filtering)"
    );

    apply_config(
        CONFIG_PATH,
        &shared_ebpf,
        &decision_log,
        &file_settings,
    )
    .await
    .context("failed to sync configuration")?;

    spawn_config_watcher(
        CONFIG_PATH,
        shared_ebpf,
        decision_log.clone(),
        file_settings,
    );

    let retention_minutes = initial_config.decision_log_retention_minutes;
    let started_at = SystemTime::now();
    println!(
        "Firewall started {} on {interface}. Drops -> {LOG_PATH} (RUST_LOG=info for console).",
        format_local_timestamp(started_at),
    );
    info!(
        "Decision logs: file={LOG_PATH} (max {} MB, {} evt/s), memory window={retention_minutes} min",
        initial_config.decision_log_max_file_mb,
        initial_config.decision_log_max_events_per_second,
    );
    if initial_config.rpf.enabled {
        let nets = initial_config.get_rpf_internal_nets().unwrap_or_default();
        info!("RPF enabled ({} internal prefix(es) on ingress)", nets.len());
    }
    if initial_config.icmp.enabled {
        info!(
            "ICMP filter: echo={}, traceroute={}, control={}, other={}",
            initial_config.icmp.echo,
            initial_config.icmp.traceroute,
            initial_config.icmp.control,
            initial_config.icmp.other,
        );
    }
    if initial_config.rate_limit.enabled {
        info!(
            "Rate limit: {} packets/s per source IP",
            initial_config.rate_limit.packets_per_second,
        );
    }

    println!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;

    let (bpf_passes, bpf_drops) = {
        let mut guard = ebpf_for_summary.lock().await;
        bpf::read_packet_stats(&mut guard).unwrap_or_else(|e| {
            log::warn!("could not read BPF packet stats on exit: {e:#}");
            (0, 0)
        })
    };

    let log = decision_log.lock().await;
    log.print_summary(retention_minutes, LOG_PATH, bpf_passes, bpf_drops);

    println!("Exiting...");
    Ok(())
}
