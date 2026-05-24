use anyhow::Context as _;
use aya::maps::{Array, LpmTrie, lpm_trie::Key};
use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags, tc};
use ipnet::IpNet;

use crate::config::AppConfig;
use crate::config::IpListEntry;
use firewall_common::{CONFIG_INDEX_FLAGS, CONFIG_INDEX_MODE};

pub fn raise_memlock_limit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        log::debug!("remove limit on locked memory failed, ret is: {ret}");
    }
}

pub fn load_object() -> anyhow::Result<aya::Ebpf> {
    aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/firewall"
    )))
    .context("failed to load eBPF object")
}

pub fn attach_programs(ebpf: &mut aya::Ebpf, interface: &str) -> anyhow::Result<()> {
    let xdp: &mut Xdp = ebpf
        .program_mut("ingress_xdp")
        .context("failed to find ingress_xdp program")?
        .try_into()
        .context("failed to cast ingress_xdp to Xdp")?;
    xdp.load()?;
    xdp.attach(interface, XdpFlags::default())
        .context("failed to attach ingress XDP program")?;

    let _ = tc::qdisc_detach_program(interface, TcAttachType::Egress, "egress_tc");

    let _ = std::process::Command::new("tc")
        .args(["qdisc", "del", "dev", interface, "clsact"])
        .output();

    tc::qdisc_add_clsact(interface).context("failed to add clsact qdisc")?;

    let tc_program: &mut SchedClassifier = ebpf
        .program_mut("egress_tc")
        .context("failed to find egress_tc program")?
        .try_into()
        .context("failed to cast egress_tc to SchedClassifier")?;
    tc_program.load()?;
    tc_program
        .attach(interface, TcAttachType::Egress)
        .context("failed to attach egress TC program")?;

    Ok(())
}

pub fn apply_config_to_ebpf(ebpf: &mut aya::Ebpf, config: &AppConfig) -> anyhow::Result<()> {
    set_config(ebpf, config.get_ebpf_mode()?, config.rpf_config_flags()?)?;
    reload_ip_lists(
        ebpf,
        &config.get_whitelist_entries()?,
        &config.get_blacklist_entries()?,
    )?;
    reload_rpf_internal(ebpf, &config.get_rpf_internal_nets()?)?;
    Ok(())
}

fn set_config(ebpf: &mut aya::Ebpf, mode: u32, flags: u32) -> anyhow::Result<()> {
    let mut config_map: Array<_, u32> = Array::try_from(
        ebpf.map_mut("CONFIG")
            .context("failed to find CONFIG map")?,
    )?;
    config_map
        .set(CONFIG_INDEX_MODE, mode, 0)
        .context("failed to set mode in CONFIG map")?;
    config_map
        .set(CONFIG_INDEX_FLAGS, flags, 0)
        .context("failed to set flags in CONFIG map")?;
    Ok(())
}

fn reload_rpf_internal(ebpf: &mut aya::Ebpf, nets: &[IpNet]) -> anyhow::Result<()> {
    reload_rpf_trie_v4(ebpf, nets)?;
    reload_rpf_trie_v6(ebpf, nets)?;
    Ok(())
}

fn reload_rpf_trie_v4(ebpf: &mut aya::Ebpf, nets: &[IpNet]) -> anyhow::Result<()> {
    let map_name = "RPF_INTERNAL_V4";
    let map_raw = ebpf
        .map_mut(map_name)
        .with_context(|| format!("failed to find {map_name} map"))?;
    let mut trie: LpmTrie<_, [u8; 4], u8> =
        LpmTrie::try_from(map_raw).with_context(|| format!("failed to cast {map_name}"))?;

    let old_keys: Vec<Key<[u8; 4]>> = trie.keys().filter_map(|k| k.ok()).collect();
    for key in old_keys {
        trie.remove(&key)
            .with_context(|| format!("failed to clear {map_name}"))?;
    }

    for net in nets {
        let IpNet::V4(v4) = net else {
            continue;
        };
        let key = Key::new(v4.prefix_len().into(), v4.network().octets());
        trie.insert(&key, 1, 0)
            .with_context(|| format!("failed to insert {v4} into {map_name}"))?;
    }

    Ok(())
}

fn reload_rpf_trie_v6(ebpf: &mut aya::Ebpf, nets: &[IpNet]) -> anyhow::Result<()> {
    let map_name = "RPF_INTERNAL_V6";
    let map_raw = ebpf
        .map_mut(map_name)
        .with_context(|| format!("failed to find {map_name} map"))?;
    let mut trie: LpmTrie<_, [u8; 16], u8> =
        LpmTrie::try_from(map_raw).with_context(|| format!("failed to cast {map_name}"))?;

    let old_keys: Vec<Key<[u8; 16]>> = trie.keys().filter_map(|k| k.ok()).collect();
    for key in old_keys {
        trie.remove(&key)
            .with_context(|| format!("failed to clear {map_name}"))?;
    }

    for net in nets {
        let IpNet::V6(v6) = net else {
            continue;
        };
        let key = Key::new(v6.prefix_len().into(), v6.network().octets());
        trie.insert(&key, 1, 0)
            .with_context(|| format!("failed to insert {v6} into {map_name}"))?;
    }

    Ok(())
}

fn reload_ip_lists(
    ebpf: &mut aya::Ebpf,
    whitelist: &[IpListEntry],
    blacklist: &[IpListEntry],
) -> anyhow::Result<()> {
    reload_lpm_trie_maps(ebpf, "WHITELIST", whitelist)?;
    reload_lpm_trie_maps(ebpf, "BLACKLIST", blacklist)?;
    Ok(())
}

fn reload_lpm_trie_maps(
    ebpf: &mut aya::Ebpf,
    base_name: &str,
    entries: &[IpListEntry],
) -> anyhow::Result<()> {
    let (v4_map, v6_map) = match base_name {
        "WHITELIST" => ("WHITELIST_V4", "WHITELIST_V6"),
        "BLACKLIST" => ("BLACKLIST_V4", "BLACKLIST_V6"),
        _ => anyhow::bail!("unknown LPM map base name: {base_name}"),
    };

    reload_lpm_trie_v4(ebpf, v4_map, entries)?;
    reload_lpm_trie_v6(ebpf, v6_map, entries)?;
    Ok(())
}

fn reload_lpm_trie_v4(ebpf: &mut aya::Ebpf, map_name: &str, entries: &[IpListEntry]) -> anyhow::Result<()> {
    let map_raw = ebpf
        .map_mut(map_name)
        .with_context(|| format!("failed to find {map_name} map"))?;
    let mut trie: LpmTrie<_, [u8; 4], u8> =
        LpmTrie::try_from(map_raw).with_context(|| format!("failed to cast {map_name}"))?;

    let old_keys: Vec<Key<[u8; 4]>> = trie.keys().filter_map(|k| k.ok()).collect();
    for key in old_keys {
        trie.remove(&key)
            .with_context(|| format!("failed to remove key from {map_name}"))?;
    }

    for entry in entries {
        let IpNet::V4(v4) = entry.net else {
            continue;
        };
        let key = Key::new(v4.prefix_len().into(), v4.network().octets());
        trie.insert(&key, entry.directions, 0)
            .with_context(|| format!("failed to insert {v4} into {map_name}"))?;
    }

    Ok(())
}

fn reload_lpm_trie_v6(ebpf: &mut aya::Ebpf, map_name: &str, entries: &[IpListEntry]) -> anyhow::Result<()> {
    let map_raw = ebpf
        .map_mut(map_name)
        .with_context(|| format!("failed to find {map_name} map"))?;
    let mut trie: LpmTrie<_, [u8; 16], u8> =
        LpmTrie::try_from(map_raw).with_context(|| format!("failed to cast {map_name}"))?;

    let old_keys: Vec<Key<[u8; 16]>> = trie.keys().filter_map(|k| k.ok()).collect();
    for key in old_keys {
        trie.remove(&key)
            .with_context(|| format!("failed to remove key from {map_name}"))?;
    }

    for entry in entries {
        let IpNet::V6(v6) = entry.net else {
            continue;
        };
        let key = Key::new(v6.prefix_len().into(), v6.network().octets());
        trie.insert(&key, entry.directions, 0)
            .with_context(|| format!("failed to insert {v6} into {map_name}"))?;
    }

    Ok(())
}

const STAT_DROPS: u32 = 0;
const STAT_PASSES: u32 = 1;

/// Cumulative pass/drop counts from the BPF filter (all handled packets).
pub fn read_packet_stats(ebpf: &mut aya::Ebpf) -> anyhow::Result<(u64, u64)> {
    let stats = Array::<_, u64>::try_from(
        ebpf.map_mut("STATS")
            .context("failed to find STATS map")?,
    )?;
    let passes = stats.get(&STAT_PASSES, 0).unwrap_or(0);
    let drops = stats.get(&STAT_DROPS, 0).unwrap_or(0);
    Ok((passes, drops))
}
