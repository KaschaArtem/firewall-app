//! Decision logging, ring buffer reader, file output, and statistics polling.

use crate::config::DecisionLogFileSettings;
use firewall_common::{
    PacketDecisionEvent, ACTION_DROP, ACTION_PASS, DIRECTION_EGRESS, DIRECTION_INGRESS,
    FAMILY_IPV4, FAMILY_IPV6, REASON_ALL_DROP, REASON_ALL_PASS, REASON_BLACKLIST, REASON_DEFAULT,
    ICMP_CLASS_CONTROL, ICMP_CLASS_ECHO, ICMP_CLASS_OTHER, ICMP_CLASS_TRACEROUTE,
    REASON_ICMP_FILTER, REASON_MALFORMED, REASON_NON_IP, REASON_RATE_LIMIT, REASON_RPF,
    REASON_WHITELIST,
};
use std::collections::VecDeque;
use std::fmt;
use std::fs::OpenOptions;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex};

pub const LOG_PATH: &str = "/var/log/firewall-application.log";

pub fn format_local_timestamp(time: SystemTime) -> String {
    let dt: chrono::DateTime<chrono::Local> = time.into();
    format!("[{}]", dt.format("%d.%m.%Y %H:%M:%S%.3f"))
}

const RINGBUF_POLL_INTERVAL: Duration = Duration::from_millis(50);
const BACKUP_SUFFIX: &str = ".1";
const SUPPRESS_REPORT_INTERVAL: Duration = Duration::from_secs(10);
const EVENT_QUEUE_CAPACITY: usize = 8_192;
const STAT_DROPS: u32 = 0;
const STAT_PASSES: u32 = 1;

pub type SharedDecisionLog = Arc<Mutex<DecisionLog>>;
pub type SharedFileLogSettings = Arc<Mutex<DecisionLogFileSettings>>;

#[derive(Clone, Debug)]
struct LoggedDecision {
    received_at: Instant,
    event: PacketDecisionEvent,
}

pub struct DecisionLog {
    retention: Duration,
    max_entries: usize,
    entries: VecDeque<LoggedDecision>,
}

impl DecisionLog {
    pub fn new(retention: Duration, max_entries: usize) -> Self {
        Self {
            retention,
            max_entries: max_entries.max(1_000),
            entries: VecDeque::new(),
        }
    }

    pub fn set_retention(&mut self, retention: Duration) {
        self.retention = retention;
        self.prune();
    }

    pub fn set_max_entries(&mut self, max_entries: usize) {
        self.max_entries = max_entries.max(1_000);
        while self.entries.len() > self.max_entries {
            self.entries.pop_front();
        }
    }

    pub fn push(&mut self, event: PacketDecisionEvent) {
        if self.entries.len() >= self.max_entries {
            self.entries.pop_front();
        }
        self.entries.push_back(LoggedDecision {
            received_at: Instant::now(),
            event,
        });
        self.prune();
    }

    fn prune(&mut self) {
        let cutoff = Instant::now() - self.retention;
        while self
            .entries
            .front()
            .is_some_and(|e| e.received_at < cutoff)
        {
            self.entries.pop_front();
        }
    }

    pub fn print_summary(
        &self,
        retention_minutes: u64,
        log_path: &str,
        bpf_passes: u64,
        bpf_drops: u64,
    ) {
        let bpf_total = bpf_passes.saturating_add(bpf_drops);
        let drop_pct = if bpf_total > 0 {
            bpf_drops as f64 * 100.0 / bpf_total as f64
        } else {
            0.0
        };

        let logged_drops = self
            .entries
            .iter()
            .filter(|e| e.event.action == ACTION_DROP)
            .count();

        println!(
            "\n--- Summary (in-memory window: {retention_minutes} min) ---"
        );
        println!(
            "Packets handled: {bpf_total} total — {bpf_passes} pass, {bpf_drops} drop ({drop_pct:.1}% dropped)"
        );
        if logged_drops > 0 {
            println!(
                "Drop events recorded in memory: {logged_drops} (per-packet lines are in the file log only)"
            );
        }
        println!("Per-packet log: {log_path}");
        println!("--- end summary ---\n");
    }
}

pub fn spawn_ringbuf_reader(
    decisions_map: aya::maps::Map,
    memory_log: SharedDecisionLog,
    file_log: FileLogHandle,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    use aya::maps::RingBuf;

    let ring_buf = RingBuf::try_from(decisions_map)?;

    let handle = tokio::task::spawn(async move {
        let mut async_fd = match tokio::io::unix::AsyncFd::with_interest(
            ring_buf,
            tokio::io::Interest::READABLE,
        ) {
            Ok(fd) => fd,
            Err(e) => {
                log::error!("failed to watch DECISIONS ring buffer: {e}");
                return;
            }
        };

        let mut poll_tick = tokio::time::interval(RINGBUF_POLL_INTERVAL);
        poll_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = poll_tick.tick() => {
                    drain_ringbuf(async_fd.get_mut(), &memory_log, &file_log);
                }
                result = async_fd.readable_mut() => {
                    let mut guard = match result {
                        Ok(g) => g,
                        Err(e) => {
                            log::error!("DECISIONS ring buffer poll error: {e}");
                            continue;
                        }
                    };
                    drain_ringbuf(guard.get_inner_mut(), &memory_log, &file_log);
                    guard.clear_ready();
                }
            }
        }
    });

    Ok(handle)
}

fn drain_ringbuf(
    ring_buf: &mut aya::maps::RingBuf<aya::maps::MapData>,
    memory_log: &SharedDecisionLog,
    file_log: &FileLogHandle,
) {
    while let Some(item) = ring_buf.next() {
        let bytes = item.as_ref();
        if bytes.len() < std::mem::size_of::<PacketDecisionEvent>() {
            continue;
        }

        let event = unsafe { (bytes.as_ptr() as *const PacketDecisionEvent).read_unaligned() };

        if let Ok(mut log_guard) = memory_log.try_lock() {
            log_guard.push(event);
        }

        let _ = file_log.try_send(event);

        if event.action == ACTION_DROP {
            let at = SystemTime::now();
            log::info!("{}", format_log_line(&event, at));
        }
    }
}

pub struct FileLogHandle {
    tx: mpsc::Sender<PacketDecisionEvent>,
    queue_drops: Arc<AtomicU64>,
    _task: tokio::task::JoinHandle<()>,
}

impl FileLogHandle {
    pub fn try_send(&self, event: PacketDecisionEvent) -> bool {
        match self.tx.try_send(event) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.queue_drops.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }
}

pub fn spawn_file_logger(settings: SharedFileLogSettings) -> anyhow::Result<FileLogHandle> {
    let path = PathBuf::from(LOG_PATH);
    verify_log_file_writable(&path)?;

    let (tx, rx) = mpsc::channel(EVENT_QUEUE_CAPACITY);
    let queue_drops = Arc::new(AtomicU64::new(0));

    let drops_for_task = queue_drops.clone();
    let task = tokio::spawn(async move {
        if let Err(e) = run_file_logger(path, rx, settings, drops_for_task).await {
            eprintln!("decision file logger stopped: {e:#}");
            log::error!("decision file logger stopped: {e:#}");
        }
    });

    Ok(FileLogHandle {
        tx,
        queue_drops,
        _task: task,
    })
}

fn verify_log_file_writable(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("cannot create {}: {e}", parent.display()))?;
    }

    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| {
            anyhow::anyhow!(
                "cannot open decision log {}: {e}. Run the firewall with sudo.",
                path.display()
            )
        })?;

    println!("Decision log file: {}", path.display());
    Ok(())
}

async fn run_file_logger(
    path: PathBuf,
    mut rx: mpsc::Receiver<PacketDecisionEvent>,
    settings: SharedFileLogSettings,
    queue_drops: Arc<AtomicU64>,
) -> anyhow::Result<()> {
    rotate_if_oversized(&path, settings.lock().await.max_file_bytes).await?;

    let mut file = open_log_append(&path).await?;
    let header = format!(
        "# firewall decision log started {}\n",
        format_local_timestamp(SystemTime::now())
    );
    file.write_all(header.as_bytes()).await?;
    file.flush().await?;

    let mut cfg = settings.lock().await.clone();
    let mut rate = TokenBucket::new(cfg.max_events_per_second, cfg.rate_burst);
    let mut suppressed_rate: u64 = 0;
    let mut report = tokio::time::interval(SUPPRESS_REPORT_INTERVAL);
    report.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            maybe_event = rx.recv() => {
                let Some(event) = maybe_event else { break };
                cfg = settings.lock().await.clone();
                rate.set_limits(cfg.max_events_per_second, cfg.rate_burst);

                if !rate.allow() {
                    suppressed_rate += 1;
                    continue;
                }

                let queued = queue_drops.swap(0, Ordering::Relaxed);
                flush_suppressed(&mut file, &mut suppressed_rate, queued).await?;

                let at = SystemTime::now();
                file.write_all(format_log_line(&event, at).as_bytes()).await?;
                file.write_all(b"\n").await?;
                file.flush().await?;

                if file.metadata().await?.len() >= cfg.max_file_bytes {
                    rotate_if_oversized(&path, cfg.max_file_bytes).await?;
                    file = open_log_append(&path).await?;
                    file.write_all(
                        format!(
                            "# log rotated at {} (size limit)\n",
                            format_local_timestamp(SystemTime::now())
                        )
                        .as_bytes(),
                    )
                    .await?;
                    file.flush().await?;
                }
            }
            _ = report.tick() => {
                let queued = queue_drops.swap(0, Ordering::Relaxed);
                flush_suppressed(&mut file, &mut suppressed_rate, queued).await?;
            }
        }
    }

    Ok(())
}

async fn flush_suppressed(
    file: &mut tokio::fs::File,
    suppressed_rate: &mut u64,
    suppressed_queue: u64,
) -> anyhow::Result<()> {
    if *suppressed_rate == 0 && suppressed_queue == 0 {
        return Ok(());
    }

    let line = format!(
        "# {} suppressed: {suppressed_rate} (rate limit), {suppressed_queue} (queue full)\n",
        format_local_timestamp(SystemTime::now())
    );
    file.write_all(line.as_bytes()).await?;
    file.flush().await?;
    *suppressed_rate = 0;
    Ok(())
}

async fn open_log_append(path: &Path) -> anyhow::Result<tokio::fs::File> {
    Ok(tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?)
}

async fn rotate_if_oversized(path: &Path, max_bytes: u64) -> anyhow::Result<()> {
    let Ok(meta) = tokio::fs::metadata(path).await else {
        return Ok(());
    };
    if meta.len() < max_bytes {
        return Ok(());
    }

    let backup = backup_path(path);
    let _ = tokio::fs::remove_file(&backup).await;
    tokio::fs::rename(path, &backup).await?;
    log::info!(
        "rotated decision log {} -> {} (was {} bytes, limit {max_bytes})",
        path.display(),
        backup.display(),
        meta.len()
    );
    Ok(())
}

fn backup_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("firewall-application.log");
    path.with_file_name(format!("{name}{BACKUP_SUFFIX}"))
}

pub fn spawn_stats_poller(shared_ebpf: Arc<Mutex<aya::Ebpf>>) {
    tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_drops = 0u64;
        let mut last_passes = 0u64;

        loop {
            interval.tick().await;

            let drops;
            let passes;
            {
                let mut ebpf = shared_ebpf.lock().await;
                let Ok(stats) = aya::maps::Array::<_, u64>::try_from(
                    ebpf.map_mut("STATS").expect("STATS map"),
                ) else {
                    continue;
                };
                drops = stats.get(&STAT_DROPS, 0).unwrap_or(0);
                passes = stats.get(&STAT_PASSES, 0).unwrap_or(0);
            }

            let delta_drops = drops.saturating_sub(last_drops);
            let delta_passes = passes.saturating_sub(last_passes);
            last_drops = drops;
            last_passes = passes;

            if delta_drops > 0 || delta_passes > 0 {
                log::info!(
                    "BPF stats (+5s): {delta_drops} drops, {delta_passes} pass (total: {drops} drop / {passes} pass)"
                );
            }
        }
    });
}

struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_per_sec: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(max_per_second: u32, burst: u32) -> Self {
        let capacity = burst.max(max_per_second).max(1) as f64;
        let refill = max_per_second.max(1) as f64;
        Self {
            tokens: capacity,
            capacity,
            refill_per_sec: refill,
            last_refill: Instant::now(),
        }
    }

    fn set_limits(&mut self, max_per_second: u32, burst: u32) {
        self.capacity = burst.max(max_per_second).max(1) as f64;
        self.refill_per_sec = max_per_second.max(1) as f64;
        if self.tokens > self.capacity {
            self.tokens = self.capacity;
        }
    }

    fn allow(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
            self.last_refill = now;
        }
    }
}

fn format_log_line(event: &PacketDecisionEvent, at: SystemTime) -> String {
    format!(
        "{} {}",
        format_local_timestamp(at),
        DecisionDisplay(event)
    )
}

struct DecisionDisplay<'a>(&'a PacketDecisionEvent);

impl fmt::Display for DecisionDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let e = self.0;
        write!(
            f,
            "{} {} {} {} {} -> {}{}",
            format_action(e.action),
            format_direction(e.direction),
            format_reason(e.reason),
            format_proto(e.protocol),
            format_endpoint(e.family, &e.src, e.src_port, e.protocol),
            format_endpoint(e.family, &e.dst, e.dst_port, e.protocol),
            format_l4_extra(e),
        )
    }
}

fn format_action(action: u8) -> &'static str {
    match action {
        ACTION_PASS => "PASS",
        ACTION_DROP => "DROP",
        _ => "UNKNOWN",
    }
}

fn format_direction(direction: u8) -> &'static str {
    match direction {
        DIRECTION_INGRESS => "ingress",
        DIRECTION_EGRESS => "egress",
        _ => "unknown",
    }
}

fn format_reason(reason: u8) -> &'static str {
    match reason {
        REASON_ALL_PASS => "all_pass",
        REASON_ALL_DROP => "all_drop",
        REASON_BLACKLIST => "blacklist",
        REASON_WHITELIST => "whitelist",
        REASON_DEFAULT => "default_policy",
        REASON_NON_IP => "non_ip",
        REASON_MALFORMED => "malformed",
        REASON_RPF => "rpf_spoof",
        REASON_ICMP_FILTER => "icmp_filter",
        REASON_RATE_LIMIT => "rate_limit",
        _ => "unknown",
    }
}

fn format_addr(family: u8, addr: &[u8; 16]) -> String {
    match family {
        FAMILY_IPV4 => {
            let octets: [u8; 4] = addr[..4].try_into().unwrap();
            Ipv4Addr::from(octets).to_string()
        }
        FAMILY_IPV6 => Ipv6Addr::from(*addr).to_string(),
        _ => "?".to_string(),
    }
}

fn format_endpoint(family: u8, addr: &[u8; 16], port: u16, protocol: u8) -> String {
    let ip = format_addr(family, addr);
    match protocol {
        6 | 17 => {
            if port == 0 {
                format!("{ip}:?")
            } else {
                format!("{ip}:{port}")
            }
        }
        _ => ip,
    }
}

fn format_l4_extra(e: &PacketDecisionEvent) -> String {
    match e.protocol {
        6 | 17 => format!(" [sport={} dport={}]", e.src_port, e.dst_port),
        1 | 58 => format!(
            " [icmp-type={} code={} class={}]",
            e.icmp_type,
            e.icmp_code,
            format_icmp_class(e.icmp_class)
        ),
        0 => String::new(),
        p => format!(" [proto={p} sport={} dport={}]", e.src_port, e.dst_port),
    }
}

fn format_icmp_class(class: u8) -> &'static str {
    match class {
        ICMP_CLASS_ECHO => "echo",
        ICMP_CLASS_TRACEROUTE => "traceroute",
        ICMP_CLASS_CONTROL => "control",
        ICMP_CLASS_OTHER => "other",
        _ => "none",
    }
}

fn format_proto(protocol: u8) -> String {
    match protocol {
        0 => "unknown".to_string(),
        1 => "icmp".to_string(),
        6 => "tcp".to_string(),
        17 => "udp".to_string(),
        58 => "icmpv6".to_string(),
        n => format!("ipproto-{n}"),
    }
}
