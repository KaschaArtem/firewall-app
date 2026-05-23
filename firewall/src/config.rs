use anyhow::Context as _;
use serde::Deserialize;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

pub const MODE_BLACKLIST: u32 = 0;
pub const MODE_WHITELIST: u32 = 1;

#[derive(Deserialize, Debug, Clone)]
pub struct AppConfig {
    pub mode: String,
    pub whitelist_ips: Option<Vec<IpAddr>>,
    pub blacklist_ips: Option<Vec<IpAddr>>,
}

impl AppConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let path_ref = path.as_ref();
        let content = fs::read_to_string(path_ref)
            .with_context(|| format!("Could not read config file at {:?}", path_ref))?;
        
        let config: AppConfig = serde_yaml::from_str(&content)
            .with_context(|| format!("Could not parse YAML config at {:?}", path_ref))?;
        
        Ok(config)
    }

    pub fn get_ebpf_mode(&self) -> anyhow::Result<u32> {
        match self.mode.to_lowercase().as_str() {
            "whitelist" => Ok(MODE_WHITELIST),
            "blacklist" => Ok(MODE_BLACKLIST),
            _ => Err(anyhow::anyhow!(
                "Unknown mode '{}'. Use 'whitelist' or 'blacklist'.", 
                self.mode
            )),
        }
    }

    pub fn get_whitelist_ips(&self) -> Vec<IpAddr> {
        self.whitelist_ips.clone().unwrap_or_default()
    }

    pub fn get_blacklist_ips(&self) -> Vec<IpAddr> {
        self.blacklist_ips.clone().unwrap_or_default()
    }
}