<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# warper

A Rust service for selective host traffic tunneling. The current Linux slice
forwards static IPv4 routes through SOCKS5 TCP, with an authenticated local CLI,
managed configuration, recovery, and a source systemd unit. SSH, WireGuard,
DNS-based route discovery, native macOS networking, and the Tauri desktop remain
later-phase work.

Phase 0 selected direct smoltcp adapters and BoringTun for Linux. Phase 1's
networking and lifecycle tests run against controlled peers in disposable CI
namespaces; native macOS builds do not establish macOS networking support.
See the phase ledger for accepted evidence and remaining gates.

- [Implementation plan](docs/implementation-plan.md)
- [Configuration and CLI contract](docs/configuration.md)
- [Implementation contracts](docs/implementation-contracts.md)
- [Service and desktop UX](docs/service-and-client.md)
- [Architecture decisions](docs/adr/README.md)
- [Acceptance criteria](docs/acceptance.md)
- [Development and checks](docs/development.md)
- [Phase status](docs/implementation-status.md)

Run `scripts/check.sh` to validate the repository, including its Rust
experiments. See the development guide for isolated packet probes and the
real-traffic role gates and their limits.

Validate an example without opening credentials or connecting to a backend:

```sh
cargo run --locked -p warper-cli --bin warper -- check-config --config examples/socks5.yaml
```

See [Linux service installation and operation](docs/linux-service.md) for
enrollment, approved configuration import, Connect/Disconnect, recovery, and
foreground diagnostics. Closing a control client leaves networking running.

## Acknowledgments and license

The project is inspired by [WARP](https://github.com/merzzzl/warp), created by
Aleksandr Khamis. The Rust implementation and development infrastructure are
maintained by skunkie.

Licensed under the [MIT License](LICENSE). The original author's copyright
notice is retained alongside skunkie's notice. File-level SPDX metadata and
the license text in [LICENSES/MIT.txt](LICENSES/MIT.txt) support REUSE checks.
