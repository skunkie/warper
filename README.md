<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# warper

A planned Rust service for selective host traffic tunneling through SSH,
SOCKS5, and WireGuard, with DNS-based route discovery and a Tauri desktop
client. The macOS app will bundle the client and networking service.

The repository currently contains the design, configuration examples, ADRs,
and development infrastructure. A Rust runtime has not been implemented.

- [Implementation plan](docs/implementation-plan.md)
- [Configuration and CLI contract](docs/configuration.md)
- [Implementation contracts](docs/implementation-contracts.md)
- [Service and desktop UX](docs/service-and-client.md)
- [Architecture decisions](docs/adr/README.md)
- [Acceptance criteria](docs/acceptance.md)
- [Development and checks](docs/development.md)
- [Phase status](docs/implementation-status.md)

Run `scripts/check.sh` to validate the repository's current stage. Cargo
checks become mandatory when the root workspace is introduced; no placeholder
crate is needed to make the planning stage pass.

## Acknowledgments and license

The project is inspired by [WARP](https://github.com/merzzzl/warp), created by
Aleksandr Khamis. The Rust implementation and development infrastructure are
maintained by skunkie.

Licensed under the [MIT License](LICENSE). The original author's copyright
notice is retained alongside skunkie's notice. File-level SPDX metadata and
the license text in [LICENSES/MIT.txt](LICENSES/MIT.txt) support REUSE checks.
