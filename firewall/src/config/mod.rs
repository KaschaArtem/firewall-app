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

#[derive(Deserialize, Debug, Clone)]
pub struct AppConfig {
    pub mode: String,
    pub decision_log_retention_minutes: u64,
    #[serde(default)]
    pub whitelist_ips: Option<Vec<String>>,
    #[serde(default)]
    pub blacklist_ips: Option<Vec<String>>,
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

        Ok(())
    }

    pub fn decision_log_retention(&self) -> Duration {
        Duration::from_secs(self.decision_log_retention_minutes * 60)
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
