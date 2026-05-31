# firewall

L3 eBPF firewall for Linux: **XDP on ingress**, **TC on egress**. Policy is defined in `config.yaml` and applied to BPF maps with **hot reload** (edit the file while the daemon runs).

On start you pick a **physical network interface** (Docker bridges, veth, loopback, and other virtual netdevs are hidden).

## Build & run

```shell
cargo build --release
sudo RUST_LOG=info target/release/firewall
```

The binary reads **`config.yaml` from the current working directory**. Run it from the repo root (or copy `config.yaml` next to the binary).

Drop decisions are appended to **`/var/log/firewall-application.log`** (root required). On **Ctrl-C** a short in-memory summary is printed; the full history stays in the log file.

## How traffic is filtered

Each IPv4/IPv6 packet goes through this pipeline (both directions, except where noted):

1. **Pre-policy** (always before lists/mode on parsed IP packets):
   - **RPF** — ingress only: drop if source is in an internal prefix on the external interface
   - **ICMP filter** — drop selected ICMP/ICMPv6 message classes
   - **Rate limit** — drop if source IP exceeds packets/s in a 1-second window
2. **Mode + lists** — whitelist/blacklist and default pass/drop

Pre-policy runs **before** whitelist/blacklist. A whitelisted IP does **not** bypass ICMP filter or rate limit.

| Hook | Direction | Notes |
|------|-----------|--------|
| XDP | Ingress | Ethernet → IPv4/IPv6 parse |
| TC clsact | Egress | IPv4/IPv6 parse (with or without Ethernet header) |

In `all_pass` / `all_drop` mode, **egress TC** skips parsing and pre-policy entirely (pass or drop all). **Ingress XDP** still runs pre-policy, then mode.

## Configuration

Copy and edit `config.yaml`. Minimal example:

```yaml
mode: default_pass
decision_log_retention_minutes: 15

whitelist_ips:
  - "127.0.0.1"
blacklist_ips: []

rpf:
  enabled: false

icmp:
  enabled: false

rate_limit:
  enabled: false
  packets_per_second: 100
```

### Firewall mode (`mode`)

| Value | Behaviour |
|-------|-----------|
| `all_pass` | Pass all IP traffic; lists ignored (pre-policy still applies on ingress) |
| `all_drop` | Drop all IP traffic; lists ignored |
| `default_pass` | Pass by default; **blacklist** entries drop matching traffic |
| `default_drop` | **Ingress:** drop unless **whitelist** matches src or dst. **Egress:** drop unless whitelisted; blacklist always drops |

List match checks **source or destination** against the CIDR. Each entry can be limited to **ingress**, **egress**, or **both**.

### IP lists (`whitelist_ips`, `blacklist_ips`)

Optional. Omitted or empty = no entries.

**Short form** — applies to both directions:

```yaml
whitelist_ips:
  - "10.0.0.0/8"
  - "203.0.113.50"
```

**With direction** (`ingress`, `egress`, `both`; aliases `in`/`out`, `inbound`/`outbound`, `all`):

```yaml
blacklist_ips:
  - ip: "142.0.0.0/8"
    direction: egress
  - ip: "10.0.0.0/24"
    direction: ingress
```

Quote IPs and CIDRs in YAML (`"127.0.0.1"`) — unquoted `127.0.0.1` may be parsed as a number.

### Reverse-path forwarding (`rpf`)

Ingress anti-spoofing on the attached interface: drop packets whose **source** is in an internal prefix (BCP38-style).

```yaml
rpf:
  enabled: true
  internal_subnets:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "127.0.0.0/8"
```

- **`enabled: false`** — RPF off (use on LAN ports where private sources are normal).
- If **`internal_subnets` is omitted** while enabled, defaults are RFC1918, loopback, `fc00::/7`, `fe80::/10`.

### ICMP filter (`icmp`)

Filters **ICMP (IPv4)** and **ICMPv6** only; TCP/UDP/DNS are unaffected.

```yaml
icmp:
  enabled: true
  echo: pass          # ping (Echo Request/Reply)
  traceroute: drop      # TTL exceeded, port/protocol unreachable (traceroute)
  control: pass         # redirect, parameter problem, etc.
  other: pass           # everything else
```

Each class: `pass` / `allow` or `drop` / `deny` / `block`.

| Class | IPv4 (type) | ICMPv6 (type) |
|-------|-------------|---------------|
| `echo` | 0, 8 | 128, 129 |
| `traceroute` | 11; 3 with code 3 or 4 | 3; 1 with code 4 |
| `control` | 5, 9, 10, 12–15, 17, 18; other type 3 codes | 1 (other codes), 2, 4 |
| `other` | remaining ICMP | remaining ICMPv6 |

### Rate limit (`rate_limit`)

Per **source IP**, counting **all L3 packets** (any protocol) in a **1-second sliding window** (LRU maps in eBPF).

```yaml
rate_limit:
  enabled: true
  packets_per_second: 100   # 1–1_000_000 when enabled; 0 = off
```

Applies to ingress and egress. **`enabled: false`** disables limiting.

### Decision logging

| Field | Default | Description |
|-------|---------|-------------|
| `decision_log_retention_minutes` | — | In-memory window for exit summary (1–1440) |
| `decision_log_max_file_mb` | 32 | Max size of active log before rotate to `.1` (1–1024) |
| `decision_log_max_events_per_second` | 500 | Sustained write rate under flood (token bucket) |
| `decision_log_rate_burst` | 2000 | Burst capacity above sustained rate |
| `decision_log_max_memory_events` | 50000 | In-memory cap during floods (≥ 1000) |

When the log exceeds `decision_log_max_file_mb`, it rotates to `firewall-application.log.1` (single backup). Overflow under rate limit is dropped and summarized as `# suppressed: …` lines.

### Hot reload

Saving `config.yaml` triggers reload. Invalid YAML or validation errors are logged; the **previous valid config** keeps running.

## Prerequisites

1. Stable Rust: `rustup toolchain install stable`
2. Nightly Rust (eBPF build): `rustup toolchain install nightly --component rust-src`
3. (Cross-compiling) target: `rustup target add ${ARCH}-unknown-linux-musl`
4. (Cross-compiling) LLVM, e.g. `brew install llvm` (macOS)
5. (Cross-compiling) musl toolchain, e.g. [musl-cross](https://github.com/FiloSottile/homebrew-musl-cross) (macOS)
6. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Cross-compiling on macOS

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package firewall \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

## License

With the exception of eBPF code, firewall is distributed under the terms of either the [MIT license] or the [Apache License] (version 2.0), at your option.

eBPF code is distributed under either the [GNU General Public License, Version 2] or the [MIT license], at your option.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
