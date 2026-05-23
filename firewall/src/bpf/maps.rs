use anyhow::Context as _;
use aya::maps::{Array, LpmTrie, lpm_trie::Key};
use ipnet::IpNet;

pub fn set_mode(ebpf: &mut aya::Ebpf, mode: u32) -> anyhow::Result<()> {
    let mut config_map: Array<_, u32> = Array::try_from(
        ebpf.map_mut("CONFIG")
            .context("failed to find CONFIG map")?,
    )?;
    config_map
        .set(0, mode, 0)
        .context("failed to set mode in CONFIG map")?;
    Ok(())
}

pub fn reload_ip_lists(
    ebpf: &mut aya::Ebpf,
    whitelist: &[IpNet],
    blacklist: &[IpNet],
) -> anyhow::Result<(usize, usize)> {
    let whitelist_count = reload_lpm_trie_maps(ebpf, "WHITELIST", whitelist)?;
    let blacklist_count = reload_lpm_trie_maps(ebpf, "BLACKLIST", blacklist)?;
    Ok((whitelist_count, blacklist_count))
}

fn reload_lpm_trie_maps(ebpf: &mut aya::Ebpf, base_name: &str, nets: &[IpNet]) -> anyhow::Result<usize> {
    let (v4_map, v6_map) = match base_name {
        "WHITELIST" => ("WHITELIST_V4", "WHITELIST_V6"),
        "BLACKLIST" => ("BLACKLIST_V4", "BLACKLIST_V6"),
        _ => anyhow::bail!("unknown LPM map base name: {base_name}"),
    };

    reload_lpm_trie_v4(ebpf, v4_map, nets)?;
    reload_lpm_trie_v6(ebpf, v6_map, nets)?;

    Ok(nets.len())
}

fn reload_lpm_trie_v4(ebpf: &mut aya::Ebpf, map_name: &str, nets: &[IpNet]) -> anyhow::Result<()> {
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

fn reload_lpm_trie_v6(ebpf: &mut aya::Ebpf, map_name: &str, nets: &[IpNet]) -> anyhow::Result<()> {
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
