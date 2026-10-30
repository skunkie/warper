// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Offline application-facing validation with controlled configuration inputs.

use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use warper_config::{
    schema::{
        Authentication, BackendSettings, Config, DnsTransport, Error, Host, PasswordSource,
        Platform, Reason, RoutingMode, Trust,
    },
    yaml::Category,
};
use warper_core::{
    BackendId,
    configuration::paths::{Account, Paths},
};

const SOCKS: &str = "host: proxy.example.test:1080, ips: [10.0.0.0/8]";
const SSH: &str =
    "host: bastion.example.test, user: sample, password: sample-secret, ips: [10.0.0.0/8]";
const WG: &str = "private_key: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=', peer_public_key: 'ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=', endpoint: wg.example.test:51820, address: 10.66.66.2, ips: [10.0.0.0/8]";

fn paths() -> Paths {
    let account = Account {
        uid: 1234,
        name: "sample".into(),
        home: "/fixture/home".into(),
    };
    Paths::new(&account, Path::new("/fixture"), Some("configs/warper.yaml")).unwrap()
}

fn document(kind: &str, fields: &str, root: &str) -> String {
    format!("tunnel: {{ip: 192.0.2.1}}\nprotocols: [{{{kind}: {{{fields}}}}}]\n{root}")
}

fn parse(source: &str) -> Result<Config, Error> {
    Config::parse(source.as_bytes(), &paths(), Platform::Linux)
}

fn with_ipv6(source: &str) -> String {
    format!(
        "{}\nipv6: true\n",
        source.replace(
            "tunnel: {ip: 192.0.2.1}",
            "tunnel: {ip: 192.0.2.1, ipv6_address: fd00::1}"
        )
    )
}

fn assert_error(id: &str, source: &str, field: &str, reason: Reason) {
    let error = parse(source).expect_err(id);
    assert_eq!(error.field, field, "{id}");
    assert_eq!(error.reason, reason, "{id}");
    assert!(
        !format!("{error} {error:?}").contains("sample-secret"),
        "{id}"
    );
}

#[test]
fn configuration_catalog_validates_examples_migrations_and_required_protocol_matrix() {
    let catalog: toml::Table = include_str!("../../../tests/fixtures/configuration/cases.toml")
        .parse()
        .unwrap();
    assert_eq!(catalog["version"].as_integer(), Some(1));
    let directory =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/configuration");
    let mut validated = Vec::new();
    for case in catalog["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let sample = std::fs::read(directory.join(case["path"].as_str().unwrap())).unwrap();
        let result = Config::parse(&sample, &paths(), Platform::Linux);
        match case["expected"].as_str().unwrap() {
            "valid" => {
                let config = result.unwrap();
                let backend = &config.protocols[0];
                if let Some(expected) = case.get("expected_backend_id") {
                    assert_eq!(backend.id, expected.as_str().unwrap(), "{id}");
                }
                if let Some(expected) = case.get("expected_routing_mode") {
                    let mode = match backend.routing_mode {
                        RoutingMode::Static => "static",
                        RoutingMode::Dynamic => "dynamic",
                        RoutingMode::Mixed => "mixed",
                    };
                    assert_eq!(mode, expected.as_str().unwrap(), "{id}");
                }
                if let Some(expected) = case.get("expected_domains") {
                    let expected: Vec<_> = expected
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|value| value.as_str().unwrap())
                        .collect();
                    assert_eq!(backend.domains, expected, "{id}");
                }
                // expected_preflight describes a later runtime gate. This test
                // intentionally opens neither known_hosts nor credential files.
                validated.push(config);
            }
            "InvalidConfig" => {
                let error = result.unwrap_err();
                assert_eq!(error.category(), Category::InvalidConfig, "{id}");
                assert_eq!(
                    error.field,
                    case["expected_field"].as_str().unwrap(),
                    "{id}"
                );
            }
            _ => panic!("unknown catalog expectation for {id}"),
        }
    }
    for case in catalog["capabilities"].as_array().unwrap() {
        let kind = case["backend"].as_str().unwrap();
        let settings = &validated
            .iter()
            .flat_map(|config| &config.protocols)
            .find(|backend| backend.settings.kind() == kind)
            .unwrap()
            .settings;
        let requirements = settings.requirements();
        assert_eq!(requirements.tcp, case["tcp"].as_bool().unwrap(), "{kind}");
        assert_eq!(requirements.udp, case["udp"].as_bool().unwrap(), "{kind}");
        let transport = match requirements.dns_transport {
            DnsTransport::Tcp => "tcp",
            DnsTransport::UdpWithTcpFallback => "udp-with-tcp-fallback",
        };
        assert_eq!(transport, case["dns_transport"].as_str().unwrap(), "{kind}");
    }
}

#[test]
fn defaults_and_explicit_budgets_are_typed_and_do_not_enable_networking() {
    let config = parse(&document("socks5", SOCKS, "")).unwrap();
    assert!(!config.ipv6);
    assert!(!config.autoconnect);
    assert!(!config.tunnel.serve_dns);
    assert_eq!(config.tunnel.mtu, 1280);
    assert!(config.tunnel.name.is_none());
    assert!(config.direct_upstreams.is_empty());
    assert_eq!(config.protocols[0].id, "socks5-1");
    assert_eq!(config.protocols[0].routing_mode, RoutingMode::Static);
    for (actual, expected) in [
        (config.timeouts.connect, 10_000),
        (config.timeouts.dns, 5000),
        (config.timeouts.dns_route_grace, 30_000),
        (config.timeouts.tcp_idle, 300_000),
        (config.timeouts.udp_idle, 60_000),
        (config.timeouts.flow_max_age, 86_400_000),
        (config.timeouts.shutdown, 10_000),
        (config.timeouts.control, 5000),
    ] {
        assert_eq!(actual, Duration::from_millis(expected));
    }
    for (actual, expected) in [
        (config.limits.max_tcp_flows, 1024),
        (config.limits.max_udp_flows, 1024),
        (config.limits.max_dns_requests, 128),
        (config.limits.max_dns_alias_hops, 8),
        (config.limits.max_dns_dependency_queries, 32),
        (config.limits.max_dns_endpoint_addresses, 64),
        (config.limits.max_dns_lease_entries, 32_768),
        (config.limits.max_dns_cache_entries, 4096),
        (config.limits.max_dns_state_bytes_total, 16_777_216),
        (config.limits.max_route_entries, 16_384),
        (config.limits.max_pending_route_ops, 256),
        (config.limits.max_queued_datagrams_per_flow, 64),
        (config.limits.max_buffered_bytes_total, 67_108_864),
        (config.limits.max_log_entries, 2000),
        (config.limits.max_log_message_bytes, 4096),
        (config.limits.max_control_clients, 16),
        (config.limits.max_control_message_bytes, 1_048_576),
        (config.limits.max_control_inflight_requests, 64),
        (config.limits.max_control_events_per_client, 256),
        (config.limits.max_control_buffered_bytes_total, 8_388_608),
        (config.limits.max_control_operations, 256),
    ] {
        assert_eq!(actual, expected);
    }
    let source = document(
        "socks5",
        SOCKS,
        "service: {autoconnect: true}\ntimeouts: {connect_ms: 0x10, dns_ms: 0o10, control_ms: +1}\nlimits: {max_tcp_flows: 1}\ndns: {direct_upstreams: [192.0.2.53, '2001:db8::53']}",
    );
    let config = parse(&source).unwrap();
    assert!(config.autoconnect);
    assert_eq!(config.timeouts.connect, Duration::from_millis(16));
    assert_eq!(config.timeouts.dns, Duration::from_millis(8));
    assert_eq!(config.timeouts.control, Duration::from_millis(1));
    assert_eq!(config.limits.max_tcp_flows, 1);
    assert_eq!(config.direct_upstreams.len(), 2);
}

#[test]
fn required_fields_unknown_keys_and_scalar_types_fail_at_schema_paths() {
    struct Case {
        id: &'static str,
        sample: String,
        expected_field: &'static str,
        expected_reason: Reason,
    }
    let base = document("socks5", SOCKS, "");
    let cases = [
        Case {
            id: "missing tunnel",
            sample: "protocols: []".into(),
            expected_field: "tunnel",
            expected_reason: Reason::MissingField,
        },
        Case {
            id: "missing protocols",
            sample: "tunnel: {ip: 192.0.2.1}".into(),
            expected_field: "protocols",
            expected_reason: Reason::MissingField,
        },
        Case {
            id: "empty protocols",
            sample: "tunnel: {ip: 192.0.2.1}\nprotocols: []".into(),
            expected_field: "protocols",
            expected_reason: Reason::OutOfRange,
        },
        Case {
            id: "wrong tunnel type",
            sample: base.replace("{ip: 192.0.2.1}", "[]"),
            expected_field: "tunnel",
            expected_reason: Reason::WrongType,
        },
        Case {
            id: "wrong boolean",
            sample: format!("{base}ipv6: 'true'"),
            expected_field: "ipv6",
            expected_reason: Reason::WrongType,
        },
        Case {
            id: "wrong optional map",
            sample: format!("{base}service: false"),
            expected_field: "service",
            expected_reason: Reason::WrongType,
        },
        Case {
            id: "wrong sequence",
            sample: document("socks5", "host: proxy.example.test:1080, ips: false", ""),
            expected_field: "protocols[0].socks5.ips",
            expected_reason: Reason::WrongType,
        },
        Case {
            id: "wrong sequence element",
            sample: document("socks5", "host: proxy.example.test:1080, ips: [true]", ""),
            expected_field: "protocols[0].socks5.ips[0]",
            expected_reason: Reason::WrongType,
        },
        Case {
            id: "missing host",
            sample: document("socks5", "ips: [10.0.0.0/8]", ""),
            expected_field: "protocols[0].socks5.host",
            expected_reason: Reason::MissingField,
        },
        Case {
            id: "wrong host type",
            sample: base.replace("proxy.example.test:1080", "true"),
            expected_field: "protocols[0].socks5.host",
            expected_reason: Reason::WrongType,
        },
        Case {
            id: "root unknown",
            sample: format!("{base}sample-secret: value"),
            expected_field: "$[key]",
            expected_reason: Reason::UnknownField,
        },
        Case {
            id: "tunnel unknown",
            sample: base.replace("ip: 192.0.2.1", "ip: 192.0.2.1, sample-secret: true"),
            expected_field: "tunnel[key]",
            expected_reason: Reason::UnknownField,
        },
        Case {
            id: "dns unknown",
            sample: format!("{base}dns: {{sample-secret: true}}"),
            expected_field: "dns[key]",
            expected_reason: Reason::UnknownField,
        },
        Case {
            id: "timeouts unknown",
            sample: format!("{base}timeouts: {{sample-secret: true}}"),
            expected_field: "timeouts[key]",
            expected_reason: Reason::UnknownField,
        },
        Case {
            id: "limits unknown",
            sample: format!("{base}limits: {{sample-secret: true}}"),
            expected_field: "limits[key]",
            expected_reason: Reason::UnknownField,
        },
        Case {
            id: "service unknown",
            sample: format!("{base}service: {{development_auth: true}}"),
            expected_field: "service[key]",
            expected_reason: Reason::UnknownField,
        },
        Case {
            id: "backend unknown",
            sample: document("socks5", &format!("{SOCKS}, udp: true"), ""),
            expected_field: "protocols[0].socks5[key]",
            expected_reason: Reason::UnknownField,
        },
        Case {
            id: "sibling unknown",
            sample: base.replace("{socks5:", "{sample-secret: true, socks5:"),
            expected_field: "protocols[0][key]",
            expected_reason: Reason::UnknownField,
        },
        Case {
            id: "multiple backend kinds",
            sample: base.replace("{socks5:", "{ssh: {}, socks5:"),
            expected_field: "protocols[0]",
            expected_reason: Reason::BackendCount,
        },
        Case {
            id: "no backend kind",
            sample: "tunnel: {ip: 192.0.2.1}\nprotocols: [{id: sample}]".into(),
            expected_field: "protocols[0]",
            expected_reason: Reason::BackendCount,
        },
    ];
    for case in cases {
        assert_error(
            case.id,
            &case.sample,
            case.expected_field,
            case.expected_reason,
        );
    }
    for sample in ["'1280'", "1280.0", "true"] {
        assert_error(
            sample,
            &base.replace("ip: 192.0.2.1", &format!("ip: 192.0.2.1, mtu: {sample}")),
            "tunnel.mtu",
            Reason::WrongType,
        );
    }
    for sample in ["0", "1279", "9001", "-1", "18446744073709551616"] {
        assert_error(
            sample,
            &base.replace("ip: 192.0.2.1", &format!("ip: 192.0.2.1, mtu: {sample}")),
            "tunnel.mtu",
            Reason::OutOfRange,
        );
    }
}

#[test]
fn target_names_address_safety_and_ipv6_switch_are_validated_offline() {
    let base = document("socks5", SOCKS, "");
    for sample in [
        "0.0.0.0",
        "127.0.0.1",
        "255.255.255.255",
        "224.0.0.1",
        "192.0.2.1/32",
        "::1",
        "fd00::1",
    ] {
        assert_error(
            sample,
            &base.replace("ip: 192.0.2.1", &format!("ip: '{sample}'")),
            "tunnel.ip",
            Reason::InvalidAddress,
        );
    }
    for sample in [
        "",
        ".",
        "..",
        "sixteen-byte-name",
        "bad/name",
        "bad:name",
        "bad name",
        "имя",
    ] {
        assert_error(
            sample,
            &base.replace("ip: 192.0.2.1", &format!("ip: 192.0.2.1, name: '{sample}'")),
            "tunnel.name",
            Reason::InvalidName,
        );
    }
    let mac = base.replace("ip: 192.0.2.1", "ip: 192.0.2.1, name: utun12");
    assert!(Config::parse(mac.as_bytes(), &paths(), Platform::MacOs).is_ok());
    for name in ["utun", "warp0", "utun-1", "utun１２"] {
        let error = Config::parse(
            mac.replace("utun12", name).as_bytes(),
            &paths(),
            Platform::MacOs,
        )
        .unwrap_err();
        assert_eq!(error.reason, Reason::InvalidName, "{name}");
    }
    assert_error(
        "missing IPv6 local",
        &format!("{base}ipv6: true"),
        "tunnel.ipv6_address",
        Reason::UnsupportedFamily,
    );
    assert_error(
        "forbidden IPv6 local",
        &base.replace("ip: 192.0.2.1", "ip: 192.0.2.1, ipv6_address: fd00::1"),
        "tunnel.ipv6_address",
        Reason::UnsupportedFamily,
    );
    for sample in ["::", "::1", "ff02::1", "fe80::1", "192.0.2.2"] {
        assert_error(
            sample,
            &with_ipv6(&base).replace("fd00::1", &format!("'{sample}'")),
            "tunnel.ipv6_address",
            Reason::InvalidAddress,
        );
    }
    for sample in [
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "ff02::1",
        "192.0.2.53:53",
    ] {
        assert_error(
            sample,
            &format!("{base}dns: {{direct_upstreams: ['{sample}']}}"),
            "dns.direct_upstreams[0]",
            Reason::InvalidAddress,
        );
    }
    assert_error(
        "duplicate DNS",
        &format!("{base}dns: {{direct_upstreams: ['2001:db8::53', '2001:db8:0:0::53']}}"),
        "dns.direct_upstreams[1]",
        Reason::DuplicateAddress,
    );
    assert!(parse(&with_ipv6(&base)).is_ok());
}

#[test]
fn routing_defaults_conflicts_and_static_policy_keep_backend_selection() {
    for (fields, mode) in [
        (SOCKS.to_owned(), RoutingMode::Static),
        (
            "host: proxy.example.test:1080, domains: [apps.example.test], dns: [10.0.0.53]".into(),
            RoutingMode::Dynamic,
        ),
        (
            format!("{SOCKS}, domains: [apps.example.test], dns: [10.0.0.53], routing_mode: mixed"),
            RoutingMode::Mixed,
        ),
    ] {
        assert_eq!(
            parse(&document("socks5", &fields, "")).unwrap().protocols[0].routing_mode,
            mode
        );
    }
    assert_error(
        "missing routing",
        &document("socks5", "host: proxy.example.test:1080", ""),
        "protocols[0].socks5",
        Reason::MissingRouting,
    );
    for fields in [format!("{SOCKS}, routing_mode: dynamic"), format!("{SOCKS}, routing_mode: mixed"), format!("{SOCKS}, routing_mode: unknown"), "host: proxy.example.test:1080, domains: [apps.example.test], dns: [10.0.0.53], routing_mode: static".into()] {
        assert_error("mode conflict", &document("socks5", &fields, ""), "protocols[0].socks5.routing_mode", Reason::RoutingMode);
    }
    for cidr in [
        "10.0.0.1/8",
        "10.0.0.0",
        "10.0.0.0/33",
        "10.0.0.0/+8",
        "10.0.0.0/08",
        "2001:db8::1/32",
    ] {
        assert_error(
            cidr,
            &document(
                "socks5",
                &format!("host: proxy.example.test:1080, ips: ['{cidr}']"),
                "",
            ),
            "protocols[0].socks5.ips[0]",
            Reason::InvalidCidr,
        );
    }
    assert_error(
        "IPv6 capture disabled",
        &document(
            "socks5",
            "host: proxy.example.test:1080, ips: ['2001:db8::/32']",
            "",
        ),
        "protocols[0].socks5.ips[0]",
        Reason::UnsupportedFamily,
    );
    assert_error(
        "duplicate same backend",
        &document(
            "socks5",
            "host: proxy.example.test:1080, ips: [10.0.0.0/8, 10.0.0.0/8]",
            "",
        ),
        "protocols[0].socks5.ips[1]",
        Reason::DuplicateRoute,
    );
    let two = format!(
        "tunnel: {{ip: 192.0.2.1}}\nprotocols: [{{socks5: {{{SOCKS}}}}}, {{ssh: {{{SSH}}}}}]"
    );
    assert_error(
        "identical cross-backend CIDR",
        &two,
        "protocols[1].ssh.ips[0]",
        Reason::DuplicateRoute,
    );
    let two = two.replacen("ips: [10.0.0.0/8]", "ips: [10.1.0.0/16]", 1);
    let config = parse(&two).unwrap();
    assert_eq!(config.protocols[0].id, "socks5-1");
    assert_eq!(config.protocols[1].id, "ssh-2");
    let policy = config.static_policy().unwrap();
    assert_eq!(
        policy.select("10.1.2.3".parse().unwrap()),
        Some(BackendId(1))
    );
    assert_eq!(
        policy.select("10.2.3.4".parse().unwrap()),
        Some(BackendId(2))
    );
    assert_eq!(policy.select("192.0.2.1".parse().unwrap()), None);
    let mut modified = config.clone();
    modified.limits.max_route_entries = 1;
    assert!(matches!(
        modified.static_policy(),
        Err(warper_core::routing::Error::ResourceLimit)
    ));
    modified.limits.max_route_entries = 0;
    assert!(matches!(
        modified.static_policy(),
        Err(warper_core::routing::Error::InvalidLimit)
    ));
    let error = parse(&format!("{two}\nlimits: {{max_route_entries: 1}}")).unwrap_err();
    assert_eq!(error.reason, Reason::RouteLimit);
    assert_eq!(error.category(), Category::ResourceLimit);
    for id in [
        "",
        "Uppercase",
        "1starts-with-digit",
        "non ascii",
        &"a".repeat(65),
    ] {
        assert_error(
            id,
            &document("socks5", SOCKS, "").replace("{socks5:", &format!("{{id: '{id}', socks5:")),
            "protocols[0].id",
            Reason::InvalidId,
        );
    }
    assert_error(
        "duplicate IDs",
        &two.replace("{socks5:", "{id: shared, socks5:")
            .replace("{ssh:", "{id: shared, ssh:"),
        "protocols[1].id",
        Reason::DuplicateId,
    );
}

#[test]
fn idna_normalization_locks_the_configuration_profile_and_global_uniqueness() {
    for (sample, expected) in [
        ("APPS.Example.Test.", "apps.example.test"),
        ("BÜCHER.example.test", "xn--bcher-kva.example.test"),
        ("faß.example.test", "xn--fa-hia.example.test"),
        ("ＥＸＡＭＰＬＥ。ＴＥＳＴ。", "example.test"),
        ("ab--cd.example.test", "ab--cd.example.test"),
    ] {
        let fields = format!("{SOCKS}, domains: ['{sample}'], dns: [10.0.0.53]");
        assert_eq!(
            parse(&document("socks5", &fields, "")).unwrap().protocols[0].domains,
            [expected],
            "{sample}"
        );
    }
    for sample in [
        "",
        ".",
        "example.test..",
        "*.example.test",
        "_service.example.test",
        "192.0.2.1",
        "１９２。０。２。１",
        "-label.test",
        "label-.test",
        "xn--.test",
        "a\u{200d}.test",
    ] {
        assert_error(
            sample,
            &document(
                "socks5",
                &format!("{SOCKS}, domains: ['{sample}'], dns: [10.0.0.53]"),
                "",
            ),
            "protocols[0].socks5.domains[0]",
            Reason::InvalidDomain,
        );
    }
    let longest = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert!(
        parse(&document(
            "socks5",
            &format!("{SOCKS}, domains: ['{longest}.'], dns: [10.0.0.53]"),
            ""
        ))
        .is_ok()
    );
    for sample in [format!("{longest}d"), format!("{}.test", "a".repeat(64))] {
        assert_error(
            "DNS length",
            &document(
                "socks5",
                &format!("{SOCKS}, domains: ['{sample}'], dns: [10.0.0.53]"),
                "",
            ),
            "protocols[0].socks5.domains[0]",
            Reason::InvalidDomain,
        );
    }
    assert_error(
        "duplicate normalized names",
        &document(
            "socks5",
            &format!("{SOCKS}, domains: [APPS.example.test, apps.example.test.], dns: [10.0.0.53]"),
            "",
        ),
        "protocols[0].socks5.domains[1]",
        Reason::DuplicateDomain,
    );
    let source = "tunnel: {ip: 192.0.2.1}\nprotocols: [{socks5: {host: proxy.example.test:1080, domains: [apps.example.test], dns: [10.0.0.53]}}, {socks5: {host: other.example.test:1080, domains: [APPS.example.test.], dns: [10.0.0.53]}}]";
    assert_error(
        "cross-backend domain",
        source,
        "protocols[1].socks5.domains[0]",
        Reason::DuplicateDomain,
    );
}

#[test]
fn credentials_trust_and_paths_are_checked_without_opening_files() {
    let source = document(
        "ssh",
        &SSH.replace(
            "password: sample-secret",
            "private_key_file: keys/key, private_key_passphrase_file: ~/key-passphrase",
        ),
        "",
    );
    let config = parse(&source).unwrap();
    let BackendSettings::Ssh(ssh) = &config.protocols[0].settings else {
        panic!("SSH configuration expected");
    };
    assert_eq!(ssh.port, 22);
    assert!(
        matches!(&ssh.authentication, Authentication::PrivateKey { file, passphrase_file: Some(passphrase) } if file == &PathBuf::from("/fixture/configs/keys/key") && passphrase == &PathBuf::from("/fixture/home/key-passphrase"))
    );
    assert!(
        matches!(&ssh.trust, Trust::KnownHosts(file) if file == Path::new("/fixture/home/.ssh/known_hosts"))
    );
    let pin = format!("SHA256:{}", STANDARD_NO_PAD.encode([7; 32]));
    let source = document(
        "ssh",
        &format!("{SSH}, pinned_host_key_sha256: '{pin}'"),
        "",
    );
    let config = parse(&source).unwrap();
    let BackendSettings::Ssh(ssh) = &config.protocols[0].settings else {
        panic!("SSH configuration expected");
    };
    assert!(matches!(ssh.trust, Trust::Sha256(value) if value == [7; 32]));
    assert!(
        matches!(&ssh.authentication, Authentication::Password(PasswordSource::Inline(value)) if value.expose() == "sample-secret")
    );
    assert!(!format!("{config:?} {ssh:?}").contains("sample-secret"));
    for (extra, field, reason) in [
        (
            "password_file: keys/password",
            "password",
            Reason::Credentials,
        ),
        (
            "private_key_file: keys/key",
            "password",
            Reason::Credentials,
        ),
        (
            "private_key_passphrase_file: keys/passphrase",
            "private_key_passphrase_file",
            Reason::Credentials,
        ),
        (
            "known_hosts: trust, pinned_host_key_sha256: invalid",
            "known_hosts",
            Reason::TrustConflict,
        ),
        (
            "pinned_host_key_sha256: invalid",
            "pinned_host_key_sha256",
            Reason::InvalidKey,
        ),
        (
            "known_hosts: '~someone/secret'",
            "known_hosts",
            Reason::Path(warper_core::configuration::paths::Error::UnsupportedHomeExpansion),
        ),
    ] {
        assert_error(
            extra,
            &document("ssh", &format!("{SSH}, {extra}"), ""),
            &format!("protocols[0].ssh.{field}"),
            reason,
        );
    }
    assert_error(
        "empty SSH user",
        &document("ssh", &SSH.replace("user: sample", "user: ''"), ""),
        "protocols[0].ssh.user",
        Reason::OutOfRange,
    );
    assert_error(
        "empty password",
        &document(
            "ssh",
            &SSH.replace("password: sample-secret", "password: ''"),
            "",
        ),
        "protocols[0].ssh.password",
        Reason::OutOfRange,
    );
    assert_error(
        "SSH port",
        &document("ssh", &format!("{SSH}, port: 0"), ""),
        "protocols[0].ssh.port",
        Reason::OutOfRange,
    );
    let source = document(
        "socks5",
        &format!("{SOCKS}, user: sample, password_file: 'keys/$HOME/`sample`'"),
        "",
    );
    let config = parse(&source).unwrap();
    let BackendSettings::Socks5(socks) = &config.protocols[0].settings else {
        panic!("SOCKS configuration expected");
    };
    assert!(
        matches!(&socks.authentication, Some((user, PasswordSource::File(file))) if user == "sample" && file == Path::new("/fixture/configs/keys/$HOME/`sample`"))
    );
    for (extra, field, reason) in [
        ("user: sample", "password", Reason::Credentials),
        ("password: sample-secret", "user", Reason::Credentials),
        (
            "user: '', password: sample-secret",
            "user",
            Reason::OutOfRange,
        ),
        (
            "user: sample, password: sample-secret, password_file: key",
            "password",
            Reason::Credentials,
        ),
        (
            "user: sample, password_file: ''",
            "password_file",
            Reason::Path(warper_core::configuration::paths::Error::EmptyPath),
        ),
    ] {
        assert_error(
            extra,
            &document("socks5", &format!("{SOCKS}, {extra}"), ""),
            &format!("protocols[0].socks5.{field}"),
            reason,
        );
    }
    for (sample, valid) in [("é".repeat(127) + "a", true), ("é".repeat(128), false)] {
        for field in ["user", "password"] {
            let extra = if field == "user" {
                format!("user: '{sample}', password: sample-secret")
            } else {
                format!("user: sample, password: '{sample}'")
            };
            let source = document("socks5", &format!("{SOCKS}, {extra}"), "");
            if valid {
                assert!(parse(&source).is_ok());
            } else {
                assert_error(
                    field,
                    &source,
                    &format!("protocols[0].socks5.{field}"),
                    Reason::OutOfRange,
                );
            }
        }
    }
}

#[test]
fn endpoint_syntax_is_validated_without_resolution_or_family_coupling() {
    for endpoint in [
        "proxy.example.test",
        "proxy.example.test:0",
        "proxy.example.test:65536",
        "proxy.example.test:+1",
        "[proxy.example.test]:1080",
        "[192.0.2.1]:1080",
        "2001:db8::1:1080",
        "[2001:db8::1]",
        "http://proxy.example.test:1080",
    ] {
        assert_error(
            endpoint,
            &document(
                "socks5",
                &SOCKS.replace("proxy.example.test:1080", &format!("'{endpoint}'")),
                "",
            ),
            "protocols[0].socks5.host",
            Reason::InvalidHost,
        );
    }
    for (endpoint, expected) in [
        ("127.0.0.1:1", "127.0.0.1"),
        ("[2001:db8::1]:65535", "2001:db8::1"),
    ] {
        let config = parse(&document(
            "socks5",
            &SOCKS.replace("proxy.example.test:1080", &format!("'{endpoint}'")),
            "",
        ))
        .unwrap();
        let BackendSettings::Socks5(settings) = &config.protocols[0].settings else {
            panic!("SOCKS configuration expected");
        };
        assert_eq!(
            settings.endpoint.host,
            Host::Ip(expected.parse::<IpAddr>().unwrap())
        );
    }
    assert_error(
        "SSH combined port",
        &document(
            "ssh",
            &SSH.replace("bastion.example.test", "bastion.example.test:22"),
            "",
        ),
        "protocols[0].ssh.host",
        Reason::InvalidHost,
    );
}

#[test]
fn wireguard_key_shapes_inner_families_and_mtu_are_validated_before_runtime() {
    let config = parse(&document("wireguard", WG, "")).unwrap();
    let BackendSettings::WireGuard(wg) = &config.protocols[0].settings else {
        panic!("WireGuard configuration expected");
    };
    assert_eq!(wg.private_key.expose().len(), 32);
    assert_eq!(wg.persistent_keepalive, Duration::from_secs(5));
    assert!(wg.inner_mtu.is_none());
    for (extra, field, reason) in [
        (
            "persistent_keepalive_secs: 65536",
            "persistent_keepalive_secs",
            Reason::OutOfRange,
        ),
        ("inner_mtu: 575", "inner_mtu", Reason::OutOfRange),
        ("inner_mtu: 9001", "inner_mtu", Reason::OutOfRange),
        (
            "extra_addresses: [10.66.66.3]",
            "extra_addresses[0]",
            Reason::DuplicateAddress,
        ),
        (
            "extra_addresses: ['fe80::2']",
            "extra_addresses[0]",
            Reason::InvalidAddress,
        ),
        (
            "dns: ['2001:db8::53']",
            "address",
            Reason::UnsupportedFamily,
        ),
    ] {
        assert_error(
            extra,
            &document("wireguard", &format!("{WG}, {extra}"), ""),
            &format!("protocols[0].wireguard.{field}"),
            reason,
        );
    }
    assert!(
        parse(&document(
            "wireguard",
            &format!("{WG}, persistent_keepalive_secs: 0, inner_mtu: 576"),
            ""
        ))
        .is_ok()
    );
    assert!(
        parse(&with_ipv6(&document("wireguard", WG, ""))).is_ok(),
        "static IPv4-only backends can coexist with captured IPv6"
    );
    let mixed =
        format!("{WG}, domains: [private.example.test], dns: [10.66.66.1], routing_mode: mixed");
    assert_error(
        "dynamic IPv6 requires an inner address",
        &with_ipv6(&document("wireguard", &mixed, "")),
        "protocols[0].wireguard.address",
        Reason::UnsupportedFamily,
    );
    assert!(
        parse(&with_ipv6(&document(
            "wireguard",
            &format!("{mixed}, extra_addresses: ['fd66::2'], inner_mtu: 1280"),
            ""
        )))
        .is_ok()
    );
    assert_error(
        "IPv6 minimum MTU",
        &document(
            "wireguard",
            &format!("{WG}, extra_addresses: ['fd66::2'], inner_mtu: 1279"),
            "",
        ),
        "protocols[0].wireguard.inner_mtu",
        Reason::OutOfRange,
    );
    for size in [31, 33] {
        let encoded = STANDARD.encode(vec![1; size]);
        assert_error(
            "private key length",
            &document(
                "wireguard",
                &WG.replace("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=", &encoded),
                "",
            ),
            "protocols[0].wireguard.private_key",
            Reason::InvalidKey,
        );
    }
    let zero = STANDARD.encode([0; 32]);
    assert_error(
        "zero peer key",
        &document(
            "wireguard",
            &WG.replace("ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=", &zero),
            "",
        ),
        "protocols[0].wireguard.peer_public_key",
        Reason::ZeroPeerKey,
    );
    let source = document("wireguard", &format!("{WG}, preshared_key: '{zero}'"), "");
    assert!(parse(&source).is_ok());
    assert_error(
        "key padding",
        &document("wireguard", &WG.replace("eHyA=", "eHyA"), ""),
        "protocols[0].wireguard.private_key",
        Reason::InvalidKey,
    );
    assert_error(
        "noncanonical padding bits",
        &document("wireguard", &WG.replace("eHyA=", "eHyB="), ""),
        "protocols[0].wireguard.private_key",
        Reason::InvalidKey,
    );
    for name in ["private_key", "peer_public_key", "endpoint", "address"] {
        let fields = WG
            .split(", ")
            .filter(|pair| !pair.starts_with(&format!("{name}:")))
            .collect::<Vec<_>>()
            .join(", ");
        assert_error(
            name,
            &document("wireguard", &fields, ""),
            &format!("protocols[0].wireguard.{name}"),
            Reason::MissingField,
        );
    }
    assert_error(
        "invalid peer encoding",
        &document(
            "wireguard",
            &WG.replace(
                "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=",
                "sample-secret",
            ),
            "",
        ),
        "protocols[0].wireguard.peer_public_key",
        Reason::InvalidKey,
    );
    assert_error(
        "invalid endpoint",
        &document(
            "wireguard",
            &WG.replace("wg.example.test:51820", "'wg.example.test:0'"),
            "",
        ),
        "protocols[0].wireguard.endpoint",
        Reason::InvalidHost,
    );
    assert_error(
        "invalid inner primary address",
        &document(
            "wireguard",
            &WG.replace("address: 10.66.66.2", "address: 127.0.0.1"),
            "",
        ),
        "protocols[0].wireguard.address",
        Reason::InvalidAddress,
    );
}

#[test]
fn source_admission_and_sensitive_debug_remain_safe_at_the_schema_boundary() {
    let source = vec![b'a'; warper_config::yaml::MAX_SOURCE_BYTES + 1];
    let error = Config::parse(&source, &paths(), Platform::Linux).unwrap_err();
    assert_eq!(error.category(), Category::ResourceLimit);
    assert_eq!(
        error.reason,
        Reason::Yaml(warper_config::yaml::Reason::SourceLimit)
    );
    let config = parse(&document(
        "ssh",
        &SSH.replace("user: sample", "user: sample-secret"),
        "",
    ))
    .unwrap();
    let backend = &config.protocols[0];
    let BackendSettings::Ssh(ssh) = &backend.settings else {
        panic!("SSH configuration expected");
    };
    assert!(
        !format!(
            "{config:?} {backend:?} {:?} {ssh:?} {:?} {:?}",
            backend.settings, ssh.authentication, ssh.trust
        )
        .contains("sample-secret")
    );
}

#[test]
fn every_resource_and_timeout_field_rejects_unlimited_or_coerced_input() {
    let timeouts = [
        "connect_ms",
        "dns_ms",
        "dns_route_grace_ms",
        "tcp_idle_ms",
        "udp_idle_ms",
        "flow_max_age_ms",
        "shutdown_ms",
        "control_ms",
    ];
    let limits = [
        "max_tcp_flows",
        "max_udp_flows",
        "max_dns_requests",
        "max_dns_alias_hops",
        "max_dns_dependency_queries",
        "max_dns_endpoint_addresses",
        "max_dns_lease_entries",
        "max_dns_cache_entries",
        "max_dns_state_bytes_total",
        "max_route_entries",
        "max_pending_route_ops",
        "max_queued_datagrams_per_flow",
        "max_buffered_bytes_total",
        "max_log_entries",
        "max_log_message_bytes",
        "max_control_clients",
        "max_control_message_bytes",
        "max_control_inflight_requests",
        "max_control_events_per_client",
        "max_control_buffered_bytes_total",
        "max_control_operations",
    ];
    for (group, names) in [
        ("timeouts", timeouts.as_slice()),
        ("limits", limits.as_slice()),
    ] {
        for name in names {
            for (value, reason) in [
                ("0", Reason::OutOfRange),
                ("-1", Reason::OutOfRange),
                ("18446744073709551616", Reason::OutOfRange),
                ("true", Reason::WrongType),
                ("1.5", Reason::WrongType),
                ("'1'", Reason::WrongType),
            ] {
                assert_error(
                    name,
                    &document("socks5", SOCKS, &format!("{group}: {{{name}: {value}}}")),
                    &format!("{group}.{name}"),
                    reason,
                );
            }
        }
    }
}
