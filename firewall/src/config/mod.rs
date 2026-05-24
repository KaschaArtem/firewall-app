use anyhow::Context as _;
use firewall_common::{
    CONFIG_FLAG_IFACE_EXTERNAL, CONFIG_FLAG_RPF_ENABLED, LIST_DIR_BOTH, LIST_DIR_EGRESS,
    LIST_DIR_INGRESS,
};
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

/// CIDR/host plus directions where the rule is active.
#[derive(Debug, Clone)]
pub struct IpListEntry {
    pub net: IpNet,
    /// Bit mask: `LIST_DIR_INGRESS` | `LIST_DIR_EGRESS`.
    pub directions: u8,
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
    pub whitelist_ips: Option<Vec<IpListEntrySerde>>,
    #[serde(default)]
    pub blacklist_ips: Option<Vec<IpListEntrySerde>>,
    /// Ingress anti-spoofing on an external interface (RPF / BCP38-style).
    #[serde(default)]
    pub rpf: RpfConfig,
}

/// Reverse-path check: drop ingress packets whose source is in an internal prefix.
#[derive(Deserialize, Debug, Clone)]
pub struct RpfConfig {
    #[serde(default)]
    pub enabled: bool,
    /// `external` — apply RPF on ingress; `internal` — LAN port, skip RPF.
    #[serde(default = "default_rpf_interface_role")]
    pub interface_role: String,
    /// Private/site prefixes; defaults to RFC1918 + loopback when omitted.
    #[serde(default)]
    pub internal_subnets: Option<Vec<String>>,
}

impl Default for RpfConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface_role: default_rpf_interface_role(),
            internal_subnets: None,
        }
    }
}

fn default_rpf_interface_role() -> String {
    "external".to_string()
}

/// `127.0.0.1` or `{ ip: 10.0.0.0/8, direction: egress }`.
#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum IpListEntrySerde {
    Address(String),
    Rule(IpListRuleSerde),
}

#[derive(Deserialize, Debug, Clone)]
pub struct IpListRuleSerde {
    #[serde(alias = "ip", alias = "cidr")]
    pub net: String,
    #[serde(default = "default_direction_both")]
    pub direction: String,
}

fn default_direction_both() -> String {
    "both".to_string()
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
        let _ = self.get_whitelist_entries()?;
        let _ = self.get_blacklist_entries()?;
        let _ = self.get_rpf_internal_nets()?;
        self.validate_rpf()?;

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

    pub fn get_whitelist_entries(&self) -> anyhow::Result<Vec<IpListEntry>> {
        parse_ip_list("whitelist_ips", self.whitelist_ips.as_deref())
    }

    pub fn get_blacklist_entries(&self) -> anyhow::Result<Vec<IpListEntry>> {
        parse_ip_list("blacklist_ips", self.blacklist_ips.as_deref())
    }

    pub fn rpf_config_flags(&self) -> anyhow::Result<u32> {
        if !self.rpf.enabled {
            return Ok(0);
        }

        let mut flags = CONFIG_FLAG_RPF_ENABLED;
        match self.rpf.interface_role.trim().to_lowercase().as_str() {
            "external" | "wan" | "uplink" => flags |= CONFIG_FLAG_IFACE_EXTERNAL,
            "internal" | "lan" | "trusted" => {}
            other => anyhow::bail!(
                "rpf.interface_role '{other}': use external or internal"
            ),
        }
        Ok(flags)
    }

    pub fn get_rpf_internal_nets(&self) -> anyhow::Result<Vec<IpNet>> {
        if !self.rpf.enabled {
            return Ok(Vec::new());
        }

        let Some(list) = &self.rpf.internal_subnets else {
            return Ok(default_rpf_internal_nets());
        };

        list.iter()
            .enumerate()
            .map(|(index, entry)| {
                parse_net(entry).with_context(|| {
                    format!("rpf.internal_subnets[{index}] '{entry}': expected IP or CIDR")
                })
            })
            .collect()
    }

    fn validate_rpf(&self) -> anyhow::Result<()> {
        if self.rpf.enabled {
            let _ = self.rpf_config_flags()?;
            let _ = self.get_rpf_internal_nets()?;
        }
        Ok(())
    }
}

fn default_rpf_internal_nets() -> Vec<IpNet> {
    [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "fc00::/7",
        "fe80::/10",
    ]
    .iter()
    .map(|s| s.parse().expect("valid default RPF prefix"))
    .collect()
}

fn parse_ip_list(field: &str, entries: Option<&[IpListEntrySerde]>) -> anyhow::Result<Vec<IpListEntry>> {
    let Some(entries) = entries else {
        return Ok(Vec::new());
    };

    entries
        .iter()
        .enumerate()
        .map(|(index, entry)| parse_ip_list_entry(field, index, entry))
        .collect()
}

fn parse_ip_list_entry(
    field: &str,
    index: usize,
    entry: &IpListEntrySerde,
) -> anyhow::Result<IpListEntry> {
    let (net_str, direction_str) = match entry {
        IpListEntrySerde::Address(s) => (s.as_str(), "both"),
        IpListEntrySerde::Rule(rule) => (rule.net.as_str(), rule.direction.as_str()),
    };

    let net = parse_net(net_str).with_context(|| {
        format!(
            "{field}[{index}] '{net_str}': use a host IP or CIDR (quote values in YAML)"
        )
    })?;
    let directions = parse_list_direction(direction_str).with_context(|| {
        format!(
            "{field}[{index}]: unknown direction '{direction_str}' (use ingress, egress, or both)"
        )
    })?;

    Ok(IpListEntry { net, directions })
}

pub fn parse_list_direction(direction: &str) -> anyhow::Result<u8> {
    match direction.trim().to_lowercase().as_str() {
        "ingress" | "in" | "inbound" => Ok(LIST_DIR_INGRESS),
        "egress" | "out" | "outbound" => Ok(LIST_DIR_EGRESS),
        "both" | "all" => Ok(LIST_DIR_BOTH),
        _ => Err(anyhow::anyhow!("invalid direction: {direction}")),
    }
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
        let wl = config.get_whitelist_entries().unwrap();
        assert_eq!(wl.len(), 1);
        assert_eq!(wl[0].directions, LIST_DIR_BOTH);
    }

    #[test]
    fn parses_list_entry_with_direction() {
        let yaml = r#"
mode: default_pass
decision_log_retention_minutes: 5
blacklist_ips:
  - ip: "142.0.0.0/8"
    direction: egress
  - ip: "10.0.0.0/24"
    direction: ingress
"#;
        let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
        let bl = config.get_blacklist_entries().unwrap();
        assert_eq!(bl.len(), 2);
        assert_eq!(bl[0].directions, LIST_DIR_EGRESS);
        assert_eq!(bl[1].directions, LIST_DIR_INGRESS);
    }

    #[test]
    fn parses_rpf_config() {
        let yaml = r#"
mode: default_pass
decision_log_retention_minutes: 5
rpf:
  enabled: true
  interface_role: external
  internal_subnets:
    - "10.60.0.0/16"
"#;
        let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.rpf.enabled);
        let flags = config.rpf_config_flags().unwrap();
        assert_ne!(flags & CONFIG_FLAG_RPF_ENABLED, 0);
        assert_ne!(flags & CONFIG_FLAG_IFACE_EXTERNAL, 0);
        let nets = config.get_rpf_internal_nets().unwrap();
        assert_eq!(nets.len(), 1);
    }

    #[test]
    fn rpf_defaults_include_rfc1918() {
        let yaml = r#"
mode: default_pass
decision_log_retention_minutes: 5
rpf:
  enabled: true
  interface_role: external
"#;
        let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
        let nets = config.get_rpf_internal_nets().unwrap();
        assert!(nets.len() >= 4);
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
