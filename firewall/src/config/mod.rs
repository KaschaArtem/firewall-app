use anyhow::Context as _;
use ipnet::IpNet;
use serde::Deserialize;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

pub use firewall_common::{
    MODE_ALL_DROP, MODE_ALL_PASS, MODE_DEFAULT_DROP, MODE_DEFAULT_PASS,
};

/// Limits for `/var/log/firewall-application.log` (rotation + anti-flood).
#[derive(Debug, Clone)]
pub struct DecisionLogFileSettings {
    pub max_file_bytes: u64,
    pub max_events_per_second: u32,
    pub rate_burst: u32,
    pub max_memory_events: usize,
}

#[derive(Deserialize, Debug, Clone)]
pub struct AppConfig {
    pub mode: String,
    /// In-memory window for summary on exit (minutes).
    pub decision_log_retention_minutes: u64,
    /// Max size of the active log file before rotation to `.1` (megabytes).
    #[serde(default = "default_log_max_file_mb")]
    pub decision_log_max_file_mb: u64,
    /// Sustained max lines written per second under flood (token bucket refill).
    #[serde(default = "default_log_max_events_per_second")]
    pub decision_log_max_events_per_second: u32,
    /// Short burst above sustained rate (token bucket capacity).
    #[serde(default = "default_log_rate_burst")]
    pub decision_log_rate_burst: u32,
    /// Cap in-memory events during DDoS (oldest dropped first).
    #[serde(default = "default_log_max_memory_events")]
    pub decision_log_max_memory_events: usize,
    #[serde(default)]
    pub whitelist_ips: Option<Vec<String>>,
    #[serde(default)]
    pub blacklist_ips: Option<Vec<String>>,
}

fn default_log_max_file_mb() -> u64 {
    32
}

fn default_log_max_events_per_second() -> u32 {
    500
}

fn default_log_rate_burst() -> u32 {
    2_000
}

fn default_log_max_memory_events() -> usize {
    50_000
}

impl AppConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let path_ref = path.as_ref();
        let content = fs::read_to_string(path_ref)
            .with_context(|| format!("Could not read config file at {:?}", path_ref))?;

        let config: AppConfig = serde_yaml::from_str(&content)
            .with_context(|| format!("Could not parse YAML config at {:?}", path_ref))?;

        config.validate()?;

        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        let _ = self.get_ebpf_mode()?;
        let _ = self.get_whitelist_nets()?;
        let _ = self.get_blacklist_nets()?;

        if self.decision_log_retention_minutes == 0 {
            anyhow::bail!("decision_log_retention_minutes must be at least 1");
        }
        if self.decision_log_retention_minutes > 24 * 60 {
            anyhow::bail!("decision_log_retention_minutes must be at most 1440 (24 hours)");
        }

        if self.decision_log_max_file_mb == 0 {
            anyhow::bail!("decision_log_max_file_mb must be at least 1");
        }
        if self.decision_log_max_file_mb > 1024 {
            anyhow::bail!("decision_log_max_file_mb must be at most 1024");
        }

        if self.decision_log_max_events_per_second == 0 {
            anyhow::bail!("decision_log_max_events_per_second must be at least 1");
        }
        if self.decision_log_max_events_per_second > 100_000 {
            anyhow::bail!("decision_log_max_events_per_second must be at most 100000");
        }

        if self.decision_log_rate_burst == 0 {
            anyhow::bail!("decision_log_rate_burst must be at least 1");
        }

        if self.decision_log_max_memory_events < 1_000 {
            anyhow::bail!("decision_log_max_memory_events must be at least 1000");
        }

        Ok(())
    }

    pub fn decision_log_retention(&self) -> Duration {
        Duration::from_secs(self.decision_log_retention_minutes * 60)
    }

    pub fn decision_log_file_settings(&self) -> DecisionLogFileSettings {
        DecisionLogFileSettings {
            max_file_bytes: self.decision_log_max_file_mb * 1024 * 1024,
            max_events_per_second: self.decision_log_max_events_per_second,
            rate_burst: self.decision_log_rate_burst,
            max_memory_events: self.decision_log_max_memory_events,
        }
    }

    pub fn get_ebpf_mode(&self) -> anyhow::Result<u32> {
        match self.mode.to_lowercase().as_str() {
            "all_pass" => Ok(MODE_ALL_PASS),
            "all_drop" => Ok(MODE_ALL_DROP),
            "default_pass" => Ok(MODE_DEFAULT_PASS),
            "default_drop" => Ok(MODE_DEFAULT_DROP),
            _ => Err(anyhow::anyhow!(
                "Unknown mode '{}'. Use 'all_pass', 'all_drop', 'default_pass', or 'default_drop'.",
                self.mode
            )),
        }
    }

    pub fn get_whitelist_nets(&self) -> anyhow::Result<Vec<IpNet>> {
        parse_net_list("whitelist_ips", self.whitelist_ips.as_deref())
    }

    pub fn get_blacklist_nets(&self) -> anyhow::Result<Vec<IpNet>> {
        parse_net_list("blacklist_ips", self.blacklist_ips.as_deref())
    }
}

fn parse_net_list(field: &str, entries: Option<&[String]>) -> anyhow::Result<Vec<IpNet>> {
    let Some(entries) = entries else {
        return Ok(Vec::new());
    };

    entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            parse_net(entry).with_context(|| {
                format!(
                    "{field}[{index}] '{entry}': use a host IP or CIDR (quote values in YAML, e.g. \"127.0.0.1\")"
                )
            })
        })
        .collect()
}

fn parse_net(entry: &str) -> anyhow::Result<IpNet> {
    let entry = entry.trim();
    if entry.contains('/') {
        return Ok(entry.parse()?);
    }

    let addr: IpAddr = entry.parse()?;
    Ok(IpNet::from(addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_config_with_log_limits() {
        let yaml = r#"
mode: default_pass
decision_log_retention_minutes: 15
decision_log_max_file_mb: 32
decision_log_max_events_per_second: 500
decision_log_rate_burst: 2000
decision_log_max_memory_events: 50000
whitelist_ips:
  - "127.0.0.1"
"#;
        let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
        let file = config.decision_log_file_settings();
        assert_eq!(file.max_file_bytes, 32 * 1024 * 1024);
        assert_eq!(file.max_events_per_second, 500);
    }

    #[test]
    fn applies_defaults_for_log_fields() {
        let yaml = r#"
mode: default_pass
decision_log_retention_minutes: 5
"#;
        let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.decision_log_max_file_mb, 32);
        assert_eq!(config.decision_log_max_events_per_second, 500);
    }
}
