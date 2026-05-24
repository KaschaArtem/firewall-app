# firewall

eBPF firewall: XDP on ingress, TC on egress. Rules come from `config.yaml` with hot reload.

## Configuration

| Field | Description |
|-------|-------------|
| `mode` | `all_pass`, `all_drop`, `default_pass`, `default_drop` |
| `decision_log_retention_minutes` | In-memory window for summary on exit (1–1440) |
| `decision_log_max_file_mb` | Max size of `/var/log/firewall-application.log` before rotation (1–1024) |
| `decision_log_max_events_per_second` | Sustained file write rate under flood (token bucket) |
| `decision_log_rate_burst` | Short burst above sustained rate |
| `decision_log_max_memory_events` | In-memory cap during DDoS (≥1000) |
| `whitelist_ips` | IPs/CIDRs that always pass (in filter modes) |
| `blacklist_ips` | IPs/CIDRs that always drop |

Pass/drop events go to **`/var/log/firewall-application.log`** (append). When the file exceeds `decision_log_max_file_mb`, it is rotated to `firewall-application.log.1` (only one backup — disk use is bounded). Under flood, writes are limited by a token bucket; overflow is dropped and summarized in the log as `# suppressed: …` lines. On **Ctrl-C**, a short in-memory summary is printed; the full history is in the log file.

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

```shell
cargo build
sudo RUST_LOG=info target/release/firewall
```

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
