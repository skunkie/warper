// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! The catalog's semantic expectations remain open; this registers its YAML
//! decoding expectations only. Most migration fixtures are valid YAML.

use warper_config::yaml::{Reason, Value, decode};

#[test]
fn canonical_and_migration_fixtures_have_explicit_decoder_expectations() {
    struct Case {
        id: &'static str,
        sample: &'static [u8],
        expected_duplicate_field: Option<&'static str>,
    }
    let cases = [
        Case {
            id: "canonical-ssh",
            sample: include_bytes!("../../../examples/ssh.yaml"),
            expected_duplicate_field: None,
        },
        Case {
            id: "canonical-socks5",
            sample: include_bytes!("../../../examples/socks5.yaml"),
            expected_duplicate_field: None,
        },
        Case {
            id: "canonical-wireguard",
            sample: include_bytes!("../../../examples/wireguard.yaml"),
            expected_duplicate_field: None,
        },
        Case {
            id: "original-socks5",
            sample: include_bytes!("../../../tests/fixtures/configuration/original-socks5.yaml"),
            expected_duplicate_field: None,
        },
        Case {
            id: "original-ssh",
            sample: include_bytes!("../../../tests/fixtures/configuration/original-ssh.yaml"),
            expected_duplicate_field: None,
        },
        Case {
            id: "original-wireguard",
            sample: include_bytes!("../../../tests/fixtures/configuration/original-wireguard.yaml"),
            expected_duplicate_field: None,
        },
        Case {
            id: "normalized-domains",
            sample: include_bytes!("../../../tests/fixtures/configuration/normalized-domains.yaml"),
            expected_duplicate_field: None,
        },
        Case {
            id: "unknown-field",
            sample: include_bytes!("../../../tests/fixtures/configuration/unknown-field.yaml"),
            expected_duplicate_field: None,
        },
        Case {
            id: "missing-dns",
            sample: include_bytes!("../../../tests/fixtures/configuration/missing-dns.yaml"),
            expected_duplicate_field: None,
        },
        Case {
            id: "partial-socks-credentials",
            sample: include_bytes!(
                "../../../tests/fixtures/configuration/partial-socks-credentials.yaml"
            ),
            expected_duplicate_field: None,
        },
        Case {
            id: "invalid-cidr",
            sample: include_bytes!("../../../tests/fixtures/configuration/invalid-cidr.yaml"),
            expected_duplicate_field: None,
        },
        Case {
            id: "invalid-key",
            sample: include_bytes!("../../../tests/fixtures/configuration/invalid-key.yaml"),
            expected_duplicate_field: None,
        },
        Case {
            id: "conflicting-routing-mode",
            sample: include_bytes!(
                "../../../tests/fixtures/configuration/conflicting-routing-mode.yaml"
            ),
            expected_duplicate_field: None,
        },
        Case {
            id: "duplicate-key",
            sample: include_bytes!("../../../tests/fixtures/configuration/duplicate-key.yaml"),
            expected_duplicate_field: Some("tunnel.ip"),
        },
    ];
    for case in cases {
        match case.expected_duplicate_field {
            Some(expected_field) => {
                let error = decode(case.sample).unwrap_err();
                assert_eq!(error.reason, Reason::DuplicateKey, "{}", case.id);
                assert_eq!(error.field, expected_field, "{}", case.id);
            }
            None => assert!(
                matches!(decode(case.sample), Ok(Value::Mapping(_))),
                "{}",
                case.id
            ),
        }
    }
}
