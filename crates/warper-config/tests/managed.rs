// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Managed data crosses the ordinary-client/service boundary without paths.

use std::{path::Path, time::Duration};

use warper_config::{
    managed::{Error, Snapshot},
    schema::{BackendSettings, PasswordSource, Platform},
};
use warper_core::configuration::paths::{Account, Paths};

fn paths() -> Paths {
    Paths::new(
        &Account {
            uid: 1234,
            name: "sample".into(),
            home: "/sample".into(),
        },
        Path::new("/sample"),
        Some("/sample/source.yaml"),
    )
    .unwrap()
}
fn source(fields: &str, root: &str) -> String {
    format!(
        "tunnel: {{ip: 198.18.0.1}}\nprotocols: [{{socks5: {{host: '127.0.0.1:1080', ips: [198.18.0.2/32], {fields}}}}}]\n{root}"
    )
}
fn import(sample: &str) -> Snapshot {
    Snapshot::import(sample.as_bytes(), &paths(), Platform::Linux).unwrap()
}
fn password(snapshot: &Snapshot, index: usize) -> (&str, &str) {
    let BackendSettings::Socks5(socks) = &snapshot.config().protocols[index].settings else {
        panic!("expected SOCKS5");
    };
    let Some((user, PasswordSource::Inline(password))) = &socks.authentication else {
        panic!("expected imported credentials");
    };
    (user, password.expose())
}
fn document(bytes: &[u8]) -> &[u8] {
    let length = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
    &bytes[16..16 + length]
}
fn envelope(document: &[u8]) -> Vec<u8> {
    let mut bytes = b"WMCF\0\0\0\x01".to_vec();
    bytes.extend_from_slice(&(document.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(document);
    bytes
}

#[test]
fn managed_round_trip_materializes_defaults_and_normalizes_equivalent_sources() {
    let snapshot = import(&source("", ""));
    let encoded = snapshot.encode().unwrap();
    let decoded = Snapshot::decode(encoded.expose(), Platform::Linux).unwrap();
    assert_eq!(decoded.config().protocols[0].id, "socks5-1");
    assert_eq!(decoded.config().tunnel.mtu, 1280);
    assert_eq!(decoded.config().timeouts.connect, Duration::from_secs(10));
    assert_eq!(decoded.config().limits.max_control_message_bytes, 1_048_576);
    assert!(!decoded.config().autoconnect);
    assert_eq!(decoded.encode().unwrap().expose(), encoded.expose());
    let explicit = import(
        "tunnel: {ip: 198.18.0.1, mtu: 1280, serve_dns: false}\nprotocols: [{id: socks5-1, socks5: {host: '127.0.0.1:1080', ips: [198.18.0.2/32], routing_mode: static}}]\ntimeouts: {connect_ms: 10000}\nservice: {autoconnect: false}",
    );
    assert_eq!(explicit.encode().unwrap().expose(), encoded.expose());
    let document = std::str::from_utf8(document(encoded.expose())).unwrap();
    for field in [
        "max_control_events_per_client",
        "dns_route_grace_ms",
        "flow_max_age_ms",
        "routing_mode",
        "direct_upstreams",
    ] {
        assert!(document.contains(field), "{field}");
    }
    assert_eq!(format!("{snapshot:?}"), "ManagedSnapshot(<redacted>)");
    assert_eq!(format!("{encoded:?}"), "<redacted>");
}

#[test]
fn managed_credentials_are_separate_and_preserve_unicode_and_protocol_indices() {
    let sample = "tunnel: {ip: 198.18.0.1}\nprotocols:\n- socks5: {host: '127.0.0.1:1080', ips: [198.18.0.2/32]}\n- socks5: {host: '127.0.0.1:1081', ips: [203.0.113.2/32], user: sample-user, password: '秘密-sample'}";
    let snapshot = import(sample);
    let encoded = snapshot.encode().unwrap();
    let doc = std::str::from_utf8(document(encoded.expose())).unwrap();
    for private in ["sample-user", "秘密-sample", "password", "user", "_file"] {
        assert!(!doc.contains(private));
    }
    let decoded = Snapshot::decode(encoded.expose(), Platform::Linux).unwrap();
    assert_eq!(password(&decoded, 1), ("sample-user", "秘密-sample"));
    assert!(
        matches!(&decoded.config().protocols[0].settings, BackendSettings::Socks5(socks) if socks.authentication.is_none())
    );
    assert_eq!(decoded.encode().unwrap().expose(), encoded.expose());
}

#[test]
fn managed_normalization_preserves_large_durations_routing_families_and_boot_policy() {
    let sample = "tunnel: {ip: 198.18.0.1, ipv6_address: 'fd00::1', name: tun-sample}\nipv6: true\nprotocols: [{socks5: {host: '[::1]:1080', domains: [SAMPLE.TEST.], ips: ['fd00::/64'], dns: ['2001:db8::53'], routing_mode: mixed}}]\ndns: {direct_upstreams: [192.0.2.53]}\ntimeouts: {connect_ms: 18446744073709551615}\nservice: {autoconnect: true}";
    let snapshot = import(sample);
    let encoded = snapshot.encode().unwrap();
    let decoded = Snapshot::decode(encoded.expose(), Platform::Linux).unwrap();
    assert_eq!(
        decoded.config().timeouts.connect,
        Duration::from_millis(u64::MAX)
    );
    assert!(decoded.config().autoconnect);
    assert_eq!(decoded.config().protocols[0].domains, ["sample.test"]);
    assert!(decoded.config().ipv6);
    assert_eq!(decoded.config().tunnel.name.as_deref(), Some("tun-sample"));
    assert_eq!(decoded.encode().unwrap().expose(), encoded.expose());
    // Platform name validation still applies during service-side decoding.
    assert_eq!(
        Snapshot::decode(encoded.expose(), Platform::MacOs).unwrap_err(),
        Error::InvalidEnvelope
    );
}

#[test]
fn managed_decoder_rejects_truncation_reserved_versions_credentials_and_trailing_data() {
    let encoded = import(&source("user: sample-user, password: sample-password", ""))
        .encode()
        .unwrap();
    let original = encoded.expose();
    for length in 0..original.len() {
        assert!(
            Snapshot::decode(&original[..length], Platform::Linux).is_err(),
            "truncation {length}"
        );
    }
    struct Case {
        id: &'static str,
        offset: usize,
        value: u8,
    }
    let credential = 16 + document(original).len();
    for case in [
        Case {
            id: "magic",
            offset: 0,
            value: b'X',
        },
        Case {
            id: "version",
            offset: 7,
            value: 2,
        },
        Case {
            id: "reserved",
            offset: 15,
            value: 1,
        },
        Case {
            id: "document_length",
            offset: 8,
            value: 0xff,
        },
        Case {
            id: "credential_count",
            offset: 13,
            value: 65,
        },
        Case {
            id: "backend_index",
            offset: credential + 1,
            value: 1,
        },
        Case {
            id: "empty_user",
            offset: credential + 3,
            value: 0,
        },
        Case {
            id: "oversized_user",
            offset: credential + 2,
            value: 1,
        },
        Case {
            id: "empty_password",
            offset: credential + 5,
            value: 0,
        },
        Case {
            id: "credential_reserved",
            offset: credential + 7,
            value: 1,
        },
        Case {
            id: "invalid_utf8",
            offset: credential + 8,
            value: 0xff,
        },
    ] {
        let mut changed = original.clone();
        changed[case.offset] = case.value;
        assert!(
            Snapshot::decode(&changed, Platform::Linux).is_err(),
            "{}",
            case.id
        );
    }
    let mut duplicate = original.clone();
    duplicate[13] = 2;
    duplicate.extend_from_slice(&original[credential..]);
    assert_eq!(
        Snapshot::decode(&duplicate, Platform::Linux).unwrap_err(),
        Error::InvalidEnvelope
    );
    let mut trailing = original.clone();
    trailing.push(0);
    assert_eq!(
        Snapshot::decode(&trailing, Platform::Linux).unwrap_err(),
        Error::InvalidEnvelope
    );
    assert_eq!(
        Snapshot::decode(&vec![0; 1_048_577], Platform::Linux).unwrap_err(),
        Error::ResourceLimit
    );
}

#[test]
fn managed_decoder_requires_canonical_path_free_configuration() {
    for sample in [
        source("", ""),
        source("user: sample, password_file: /dev/zero", ""),
        source("user: sample, password: sample-secret", ""),
    ] {
        assert_eq!(
            Snapshot::decode(&envelope(sample.as_bytes()), Platform::Linux).unwrap_err(),
            Error::InvalidEnvelope
        );
    }
    let encoded = import(&source("", "")).encode().unwrap();
    let mut changed = document(encoded.expose()).to_vec();
    changed.push(b' ');
    assert_eq!(
        Snapshot::decode(&envelope(&changed), Platform::Linux).unwrap_err(),
        Error::InvalidEnvelope
    );
}

#[test]
fn managed_import_rejects_unsupported_backends_before_reading_any_password_file() {
    let sample = "tunnel: {ip: 198.18.0.1}\nprotocols:\n- socks5: {host: '127.0.0.1:1080', ips: [198.18.0.2/32], user: sample, password_file: /nonexistent/selected-secret}\n- ssh: {host: bastion.example.test, user: sample, password: sample, ips: [203.0.113.2/32]}";
    assert_eq!(
        Snapshot::import(sample.as_bytes(), &paths(), Platform::Linux).unwrap_err(),
        Error::UnsupportedBackend
    );
    let mut sample = String::from("tunnel: {ip: 198.18.0.1}\nprotocols:\n");
    for index in 0..65 {
        sample.push_str(&format!(
            "- socks5: {{host: '127.0.0.1:1080', ips: [198.18.0.{index}/32]}}\n"
        ));
    }
    assert_eq!(
        Snapshot::import(sample.as_bytes(), &paths(), Platform::Linux).unwrap_err(),
        Error::BackendLimit
    );
}

#[cfg(unix)]
#[test]
fn native_password_import_enforces_backend_limit_after_exact_newline_removal() {
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, OpenOptionsExt},
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture(std::path::PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    let fixture = (0..128)
        .find_map(|_| {
            let path = std::env::temp_dir().join(format!(
                "warper-managed-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => Some(Fixture(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                Err(error) => panic!("create managed fixture: {error}"),
            }
        })
        .unwrap();
    let path = fixture.0.join("password");
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    drop(file);
    let sample = source(
        &format!("user: sample, password_file: '{}'", path.display()),
        "",
    );
    fs::write(&path, format!("{}\r\n", "x".repeat(255))).unwrap();
    let snapshot = import(&sample);
    assert_eq!(password(&snapshot, 0), ("sample", "x".repeat(255).as_str()));
    let encoded = snapshot.encode().unwrap();
    fs::remove_file(&path).unwrap();
    let decoded = Snapshot::decode(encoded.expose(), Platform::Linux).unwrap();
    assert_eq!(password(&decoded, 0), password(&snapshot, 0));
    assert!(
        !std::str::from_utf8(document(encoded.expose()))
            .unwrap()
            .contains(path.to_str().unwrap())
    );
    let failed = Snapshot::import(sample.as_bytes(), &paths(), Platform::Linux).unwrap_err();
    assert!(matches!(failed, Error::Credential(_)));
    assert!(!failed.to_string().contains(path.to_str().unwrap()));
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    drop(file);
    fs::write(&path, "x".repeat(256)).unwrap();
    assert_eq!(
        Snapshot::import(sample.as_bytes(), &paths(), Platform::Linux).unwrap_err(),
        Error::InvalidCredentials
    );
}

#[test]
fn materialized_snapshots_obey_decoder_node_and_encoded_byte_limits() {
    let entries = |prefix: &str| {
        (0..65_500)
            .map(|index| format!("{prefix}.{}.{}", index / 256, index % 256))
            .collect::<Vec<_>>()
            .join(",")
    };
    // The source fits the node limit; writing every default must not produce an
    // envelope that the service's bounded decoder cannot subsequently admit.
    let sample = source(&format!("dns: [{}]", entries("10.0")), "");
    warper_config::schema::Config::parse(sample.as_bytes(), &paths(), Platform::Linux).unwrap();
    assert_eq!(
        Snapshot::import(sample.as_bytes(), &paths(), Platform::Linux).unwrap_err(),
        Error::InvalidConfig(warper_config::schema::Reason::Yaml(
            warper_config::yaml::Reason::NodeLimit
        ))
    );
    // Quoting these longer benchmark-net addresses expands a valid input over
    // the encoded byte budget. No partially encoded snapshot escapes.
    let sample = source(&format!("dns: [{}]", entries("198.18")), "");
    assert!(sample.len() < 1_048_576);
    warper_config::schema::Config::parse(sample.as_bytes(), &paths(), Platform::Linux).unwrap();
    assert_eq!(
        Snapshot::import(sample.as_bytes(), &paths(), Platform::Linux).unwrap_err(),
        Error::ResourceLimit
    );
}

#[test]
fn managed_maximum_backend_and_credential_lengths_round_trip() {
    let mut sample = String::from("tunnel: {ip: 198.18.0.1}\nprotocols:\n");
    for index in 0..64 {
        sample.push_str(&format!("- socks5: {{host: '127.0.0.1:1080', ips: [198.18.0.{index}/32], user: '{}', password: '{}'}}\n", "u".repeat(255), "p".repeat(255)));
    }
    let encoded = import(&sample).encode().unwrap();
    let decoded = Snapshot::decode(encoded.expose(), Platform::Linux).unwrap();
    assert_eq!(decoded.config().protocols.len(), 64);
    for index in 0..64 {
        let (user, password) = password(&decoded, index);
        assert_eq!(user.len(), 255);
        assert_eq!(password.len(), 255);
    }
    assert_eq!(decoded.encode().unwrap().expose(), encoded.expose());
}

#[test]
fn canonical_names_escape_quotes_backslashes_and_control_characters() {
    let sample = "tunnel: {ip: 198.18.0.1, name: \"tun\\\"\\\\\\u0001\"}\nprotocols: [{socks5: {host: '127.0.0.1:1080', ips: [198.18.0.2/32]}}]";
    let snapshot = import(sample);
    let encoded = snapshot.encode().unwrap();
    let decoded = Snapshot::decode(encoded.expose(), Platform::Linux).unwrap();
    assert_eq!(decoded.config().tunnel.name, snapshot.config().tunnel.name);
    assert_eq!(decoded.encode().unwrap().expose(), encoded.expose());
}
