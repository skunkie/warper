// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;

#[test]
fn boot_policy_preserves_same_boot_disconnect_and_requires_matching_approval() {
    struct Case {
        id: &'static str,
        approved: Option<(u64, bool)>,
        saved: Option<(bool, Desired, u64)>,
        expected: Boot,
    }
    let cases = [
        Case {
            id: "new installation",
            approved: None,
            saved: None,
            expected: Boot::Disconnected,
        },
        Case {
            id: "autoconnect",
            approved: Some((7, true)),
            saved: None,
            expected: Boot::Autoconnect,
        },
        Case {
            id: "explicit same boot disconnect",
            approved: Some((7, true)),
            saved: Some((true, Desired::Down, 7)),
            expected: Boot::Disconnected,
        },
        Case {
            id: "same boot resume",
            approved: Some((7, false)),
            saved: Some((true, Desired::Up, 7)),
            expected: Boot::Resume,
        },
        Case {
            id: "approval replaced",
            approved: Some((8, false)),
            saved: Some((true, Desired::Up, 7)),
            expected: Boot::Blocked,
        },
        Case {
            id: "approval missing",
            approved: None,
            saved: Some((true, Desired::Up, 7)),
            expected: Boot::Blocked,
        },
        Case {
            id: "fresh boot",
            approved: Some((7, false)),
            saved: Some((false, Desired::Up, 7)),
            expected: Boot::Disconnected,
        },
        Case {
            id: "fresh boot autoconnect",
            approved: Some((8, true)),
            saved: Some((false, Desired::Down, 7)),
            expected: Boot::Autoconnect,
        },
    ];
    for case in cases {
        assert_eq!(
            boot_decision(case.saved, case.approved),
            case.expected,
            "{}",
            case.id
        );
    }
}

#[test]
fn bootstrap_admission_matches_canonical_configuration_defaults() {
    use std::path::Path;
    use warper_config::schema::Config;
    use warper_core::configuration::paths::{Account, Paths};
    let paths = Paths::new(
        &Account {
            uid: 1000,
            name: "sample".into(),
            home: "/sample".into(),
        },
        Path::new("/sample"),
        None,
    )
    .unwrap();
    let config = Config::parse(b"tunnel: {ip: 198.18.0.1}\nprotocols: [{socks5: {host: '127.0.0.1:1080', ips: [198.18.0.2/32]}}]", &paths, Platform::Linux).unwrap();
    assert_eq!(plan(None).unwrap(), plan(Some(&config.limits)).unwrap());
}

#[test]
fn unavailable_configuration_capabilities_keep_their_wire_category() {
    assert_eq!(
        Error::Configuration(configuration::Error::Preflight(
            crate::preflight::Error::UnsupportedBackend
        ))
        .code(),
        Code::Unsupported
    );
    assert_eq!(
        Error::Configuration(configuration::Error::Preflight(
            crate::preflight::Error::InvalidCredentials
        ))
        .code(),
        Code::Malformed
    );
}
