<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# Linux service installation

The initial headless Linux application supports static IPv4 CIDRs through a
SOCKS5 TCP backend. Linux x86-64 and AArch64 builds have native CI coverage.
This source installation needs systemd, util-linux (`/usr/bin/setpriv`),
`/dev/net/tun`, and the machine's initial user/network namespaces. It does not
install the future desktop app. There are no release packages yet.

Build the pinned workspace without administrative privileges:

```sh
cargo build --locked --release -p warper-cli -p warper-service
```

For a first installation, verify that `/usr/local/bin`,
`/etc/systemd/system`, `/run`, `/var/lib` and `/etc` are administrator-owned
and not writable by ordinary users. Existing `/run/warper` must be root-owned
mode 0755; `/var/lib/warper` and `/etc/warper` must be root-owned mode 0700.
Do not replace foreign directories, symlinks or existing installations to make
these checks pass. The daemon also validates its fixed protected paths.

Install the actual binaries and unit with explicit OS elevation:

```sh
sudo install -o root -g root -m 0755 target/release/warper /usr/local/bin/warper
sudo install -o root -g root -m 0755 target/release/warperd /usr/local/bin/warperd
sudo install -o root -g root -m 0644 packaging/linux/warper.service /etc/systemd/system/warper.service
sudo systemd-analyze verify /etc/systemd/system/warper.service
sudo systemctl daemon-reload
sudo systemctl enable --now warper.service
sudo /usr/local/bin/warper status
```

The unit creates the protected directories, runs the foreground daemon as root
and preserves the runtime directory and lock inode across restarts. It allows
45 seconds for shutdown, exceeding the daemon's 35-second cleanup budget and
5-second runtime-stop budget. systemd sends SIGTERM to the daemon first and
only kills the remaining control group after the stop timeout. Failed starts
are retried at most three times per minute. A running unit establishes process
availability; query `warper status` to observe network readiness.

As the intended ordinary owner, validate and approve a supported configuration:

```sh
warper check-config --config ./sample.yaml
sudo /usr/local/bin/warper config install --config ./sample.yaml
sudo /usr/local/bin/warper owner enroll
warper status
warper up
```

The elevated CLI validates the invoking sudo account and reads configuration
and credentials under that account's ordinary access. The service receives
normalized data. Owner enrollment grants control of the already approved
configuration; it does not grant administrative configuration access.

Closing the CLI leaves networking running. `warper down` explicitly disconnects.
Stopping/restarting the unit preserves same-boot desired intent; it can reconnect
after recovery. A fresh boot connects only when the approved configuration has
`service.autoconnect: true`. Do not treat `systemctl stop` as a persisted
Disconnect. Service diagnostics are available with:

```sh
sudo journalctl --unit warper.service
```

Before updating binaries, run `warper down`, stop the unit, and verify the stop
succeeded. Preserve protected configuration, enrollment, intent and journals.
Install the new binaries, then start the unit and inspect status again.

To remove this source installation, disconnect, disable and stop the unit, and
verify successful cleanup before removing the three installed files and running
`systemctl daemon-reload`. Retain `/run/warper`, `/var/lib/warper` and
`/etc/warper` for recovery and administrator review. Do not remove the persistent
lock inode or erase a cleanup failure by deleting its journal. Offline recovery
commands are still incomplete.

Unit syntax validation does not establish a successful systemd lifecycle.
Actual daemon/CLI native traffic has separate disposable acceptance evidence;
full installed-unit start/restart/stop acceptance remains unverified.
