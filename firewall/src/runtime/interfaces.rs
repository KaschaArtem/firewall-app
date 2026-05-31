//! Keeps only hardware-backed network interfaces in the attach picker.

use std::fs;
use std::path::Path;

#[cfg(target_os = "linux")]
pub fn is_physical_netdev(name: &str) -> bool {
    if name == "lo" {
        return false;
    }

    let sysfs = Path::new("/sys/class/net").join(name);
    let Ok(canonical) = fs::canonicalize(&sysfs) else {
        return false;
    };

    sysfs_path_is_physical(&canonical.to_string_lossy())
}

fn sysfs_path_is_physical(path: &str) -> bool {
    path.contains("/net/") && !path.contains("/virtual/")
}

#[cfg(not(target_os = "linux"))]
pub fn is_physical_netdev(name: &str) -> bool {
    !is_obviously_virtual_name(name)
}

#[cfg(not(target_os = "linux"))]
fn is_obviously_virtual_name(name: &str) -> bool {
    name == "lo"
        || name.starts_with("docker")
        || name.starts_with("veth")
        || name.starts_with("br-")
        || name.starts_with("virbr")
        || name.starts_with("tun")
        || name.starts_with("tap")
}

pub fn list_physical_interface_names(all_names: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut names: Vec<String> = all_names
        .into_iter()
        .filter(|name| is_physical_netdev(name))
        .collect();
    names.sort();
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sysfs_path_heuristic() {
        assert!(sysfs_path_is_physical(
            "/sys/devices/pci0000:00/0000:00:02.1/0000:02:00.0/net/eno1"
        ));
        assert!(!sysfs_path_is_physical("/sys/devices/virtual/net/docker0"));
        assert!(!sysfs_path_is_physical("/sys/devices/virtual/net/veth0"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn loopback_is_not_physical() {
        assert!(!is_physical_netdev("lo"));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn filters_obvious_virtual_names() {
        assert!(!is_physical_netdev("docker0"));
        assert!(!is_physical_netdev("veth123"));
        assert!(!is_physical_netdev("br-abc"));
    }
}
