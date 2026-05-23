use anyhow::Context as _;
use log::info;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::Mutex;

mod bpf;
mod config;
mod observability;
mod runtime;

use observability::{spawn_ringbuf_reader, DecisionLog, SharedDecisionLog};
use runtime::{apply_config, prompt_for_interface, spawn_config_watcher};

const CONFIG_PATH: &str = "config.yaml";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let interface = prompt_for_interface()?;

    bpf::raise_memlock_limit();

    let mut ebpf = bpf::load_object()?;

    let initial_config = config::AppConfig::load(CONFIG_PATH)?;
    let decision_log: SharedDecisionLog = Arc::new(Mutex::new(DecisionLog::new(
        initial_config.decision_log_retention(),
    )));

    let decisions_map = ebpf
        .take_map("DECISIONS")
        .ok_or_else(|| anyhow::anyhow!("DECISIONS ring buffer map not found"))?;
    let _ringbuf_task = spawn_ringbuf_reader(decisions_map, decision_log.clone())
        .context("failed to start decision log reader")?;

    bpf::attach_programs(&mut ebpf, &interface)
        .context("failed to attach eBPF programs")?;

    info!(
        "Attached ingress XDP and egress TC on {interface} (inbound + outbound filtering)"
    );

    let shared_ebpf = Arc::new(Mutex::new(ebpf));

    apply_config(CONFIG_PATH, &shared_ebpf, &decision_log)
        .await
        .context("failed to apply initial configuration")?;

    spawn_config_watcher(CONFIG_PATH, shared_ebpf, decision_log.clone());

    let retention_minutes = initial_config.decision_log_retention_minutes;
    info!(
        "Decision log retention: {retention_minutes} minutes (pass/drop events in memory)"
    );

    println!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;

    let log = decision_log.lock().await;
    log.print_summary(retention_minutes);

    println!("Exiting...");
    Ok(())
}
