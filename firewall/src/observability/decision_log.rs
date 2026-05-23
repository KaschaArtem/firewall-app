use firewall_common::{
    PacketDecisionEvent, ACTION_DROP, ACTION_PASS, DIRECTION_EGRESS, DIRECTION_INGRESS,
    FAMILY_IPV4, FAMILY_IPV6, REASON_ALL_DROP, REASON_ALL_PASS, REASON_BLACKLIST, REASON_DEFAULT,
    REASON_NON_IP, REASON_WHITELIST,
};
use std::collections::VecDeque;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

#[derive(Clone, Debug)]
pub struct LoggedDecision {
    pub received_at: Instant,
    pub event: PacketDecisionEvent,
}

pub struct DecisionLog {
    retention: Duration,
    entries: VecDeque<LoggedDecision>,
}

impl DecisionLog {
    pub fn new(retention: Duration) -> Self {
        Self {
            retention,
            entries: VecDeque::new(),
        }
    }

    pub fn set_retention(&mut self, retention: Duration) {
        self.retention = retention;
        self.prune();
    }

    pub fn push(&mut self, event: PacketDecisionEvent) {
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

    pub fn print_summary(&self, retention_minutes: u64) {
        let mut pass = 0usize;
        let mut drop = 0usize;

        for entry in &self.entries {
            match entry.event.action {
                ACTION_PASS => pass += 1,
                ACTION_DROP => drop += 1,
                _ => {}
            }
        }

        println!(
            "\n--- Decision log (last {retention_minutes} min, {} events) ---",
            self.entries.len()
        );
        println!("Totals: {pass} pass, {drop} drop");

        for entry in &self.entries {
            let wall = format_wall_time(entry.event.ts_ns);
            println!(
                "  [{wall}] {}",
                DecisionDisplay(&entry.event)
            );
        }
        println!("--- end decision log ---\n");
    }
}

pub type SharedDecisionLog = Arc<Mutex<DecisionLog>>;

pub fn spawn_ringbuf_reader(
    decisions_map: aya::maps::Map,
    log: SharedDecisionLog,
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

        loop {
            let mut guard = match async_fd.readable_mut().await {
                Ok(g) => g,
                Err(e) => {
                    log::error!("DECISIONS ring buffer poll error: {e}");
                    continue;
                }
            };

            let ring_buf = guard.get_inner_mut();
            while let Some(item) = ring_buf.next() {
                let bytes = item.as_ref();
                if bytes.len() < std::mem::size_of::<PacketDecisionEvent>() {
                    continue;
                }

                let event =
                    unsafe { (bytes.as_ptr() as *const PacketDecisionEvent).read_unaligned() };

                let mut log_guard = log.lock().await;
                log_guard.push(event);
                log::debug!("{}", DecisionDisplay(&event));
            }
            guard.clear_ready();
        }
    });

    Ok(handle)
}

fn format_wall_time(ts_ns: u64) -> String {
    let secs = ts_ns / 1_000_000_000;
    let nanos = (ts_ns % 1_000_000_000) as u32;
    match SystemTime::UNIX_EPOCH.checked_add(std::time::Duration::new(secs, nanos)) {
        Some(t) => {
            let since = t
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            format!("{}.{:03}s", since.as_secs(), since.subsec_millis())
        }
        None => format!("{ts_ns}ns"),
    }
}

struct DecisionDisplay<'a>(&'a PacketDecisionEvent);

impl fmt::Display for DecisionDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let e = self.0;
        write!(
            f,
            "{} {} {} {} -> {}",
            format_action(e.action),
            format_direction(e.direction),
            format_reason(e.reason),
            format_addr(e.family, &e.src),
            format_addr(e.family, &e.dst),
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
        _ => "unknown",
    }
}

fn format_addr(family: u8, addr: &[u8; 16]) -> String {
    match family {
        FAMILY_IPV4 => {
            let octets: [u8; 4] = addr[..4].try_into().unwrap();
            Ipv4Addr::from(octets).to_string()
        }
        FAMILY_IPV6 => {
            let octets: [u8; 16] = *addr;
            Ipv6Addr::from(octets).to_string()
        }
        _ => "?".to_string(),
    }
}
