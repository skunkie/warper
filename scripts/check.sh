#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

# Local entry point matching CI; never turn missing tools into successful skips.
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

mode=${1:-all}
if [[ $# -gt 1 || ! "$mode" =~ ^(all|infra|rust)$ ]]; then
    echo "usage: scripts/check.sh [all|infra|rust]" >&2
    exit 2
fi

require_tools() {
    local tool
    for tool in "$@"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "Required validation tool is missing: $tool" >&2
            exit 1
        fi
    done
}

require_tools git python3
stage=$(scripts/check-repository-stage.sh)

if [[ "$mode" != rust ]]; then
    require_tools reuse actionlint shellcheck
    reuse lint
    actionlint -color
    ACTIONLINT=$(command -v actionlint) python3 -B -m unittest discover -s scripts
    python3 -B scripts/lint_actions.py
    shellcheck scripts/*.sh
    git diff --check
    git diff --cached --check
fi

if [[ "$mode" != infra ]]; then
    case "$stage" in
        rust=true)
            require_tools cargo
            cargo fmt --all -- --check
            cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
            RUSTDOCFLAGS="${RUSTDOCFLAGS:+$RUSTDOCFLAGS }-D warnings" cargo doc --locked --workspace --all-features --no-deps
            cargo test --locked --workspace
            cargo test --locked --workspace --all-features
            cargo build --locked --workspace --release
            cargo deny --locked check
            ;;
        rust=false)
            echo "Cargo checks not run: no Rust workspace exists at this stage." >&2
            ;;
        *)
            echo "Unexpected repository-stage result: $stage" >&2
            exit 1
            ;;
    esac
fi
