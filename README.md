# firewall

eBPF firewall: XDP on ingress, TC on egress. Rules come from `config.yaml` with hot reload.

## Project layout

```
firewall/
├── config.yaml              # runtime configuration
├── firewall-common/         # shared types (modes, decision events)
│   └── src/
│       ├── mode.rs
│       └── event.rs
├── firewall-ebpf/           # kernel programs
│   └── src/
│       ├── main.rs          # ingress_xdp, egress_tc entrypoints
│       ├── maps.rs          # CONFIG, LPM tries, DECISIONS ring buffer
│       └── filter/
│           ├── verdict.rs   # pass/drop logic
│           ├── decision.rs  # emit events to userspace
│           └── packet.rs    # packet bounds checks
└── firewall/                # userspace agent
    └── src/
        ├── main.rs
        ├── config/          # YAML parsing
        ├── bpf/             # load, attach, map updates
        ├── observability/   # decision log (retention window)
        └── runtime/         # interface picker, config watcher
```

## Configuration

| Field | Description |
|-------|-------------|
| `mode` | `all_pass`, `all_drop`, `default_pass`, `default_drop` |
| `decision_log_retention_minutes` | How long to keep pass/drop events in memory (1–1440) |
| `whitelist_ips` | IPs/CIDRs that always pass (in filter modes) |
| `blacklist_ips` | IPs/CIDRs that always drop |

While running, each pass/drop is recorded via a BPF ring buffer. On **Ctrl-C**, the agent prints all events still within the retention window.

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

```shell
cargo build --release
sudo RUST_LOG=info target/release/firewall
```

## Cross-compiling on macOS

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package firewall --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

## License

With the exception of eBPF code, firewall is distributed under the terms of either the [MIT license] or the [Apache License] (version 2.0), at your option.

eBPF code is distributed under either the [GNU General Public License, Version 2] or the [MIT license], at your option.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
