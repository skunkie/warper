<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# warper

A planned Rust service for selective host traffic tunneling through SSH,
SOCKS5, and WireGuard, with DNS-based route discovery and a Tauri desktop
client. The macOS app will bundle the client and networking service.

The repository contains the design, configuration examples, development
infrastructure, Phase 0 Rust stack experiments, core static routing, and offline
configuration validation with a thin CLI beginning Phase 1. A production
networking service has not been implemented. Phase 0 selects direct smoltcp
adapters and BoringTun for Linux; native macOS networking remains unverified.

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

Help and version are available. Service control commands remain explicitly
unsupported until the authenticated local-control service is implemented.

## Acknowledgments and license

The project is inspired by [WARP](https://github.com/merzzzl/warp), created by
Aleksandr Khamis. The Rust implementation and development infrastructure are
maintained by skunkie.

Licensed under the [MIT License](LICENSE). The original author's copyright
notice is retained alongside skunkie's notice. File-level SPDX metadata and
the license text in [LICENSES/MIT.txt](LICENSES/MIT.txt) support REUSE checks.
