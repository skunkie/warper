// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use std::{path::Path, time::Duration};
use warper_core::configuration::paths::{Account, Paths};

#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(target_os = "linux")]
use warper_core::transport::{Error as TransportError, OpenTcp, Request};

fn parse(source: &str) -> Config {
    let account = Account {
        uid: 1234,
        name: "sample".into(),
        home: "/fixture/home".into(),
    };
    let paths = Paths::new(&account, Path::new("/fixture"), Some("sample.yaml")).unwrap();
    Config::parse(source.as_bytes(), &paths, Platform::Linux).unwrap()
}
fn config() -> Config {
    parse(
        "tunnel: {ip: 192.0.2.1}\nprotocols: [{socks5: {host: '198.51.100.1:1080', ips: [10.0.0.0/8]}}]\n",
    )
}

#[test]
fn effective_flow_capacity_preserves_configured_ceilings_and_exact_budget_boundary() {
    for (configured, expected) in [(1, 1), (16, 16), (1024, 16)] {
        let mut config = config();
        config.limits.max_tcp_flows = configured;
        let plan = Plan::prepare(&config, Platform::Linux).unwrap();
        assert_eq!(plan.flow_capacity(), expected);
        let buffers = plan.buffers();
        assert_eq!(
            buffers.total,
            buffers.stack_runtime
                + buffers.relays
                + buffers.tun_io
                + buffers.backend_setup
                + buffers.credentials
        );
        assert_eq!(buffers.relays, expected * 16384);
        assert_eq!(buffers.backend_setup, expected * 792);
        config.limits.max_buffered_bytes_total = buffers.total;
        assert!(Plan::prepare(&config, Platform::Linux).is_ok());
        config.limits.max_buffered_bytes_total = buffers.total - 1;
        assert!(matches!(
            Plan::prepare(&config, Platform::Linux),
            Err(Error::BufferBudget)
        ));
    }
}
#[test]
fn static_longest_prefix_policy_and_registry_endpoints_survive_preparation() {
    let source = "tunnel: {ip: 192.0.2.1}\nprotocols:\n - socks5: {host: '198.51.100.1:1080', ips: [10.0.0.0/8]}\n - socks5: {host: '198.51.100.2:1080', ips: [10.1.0.0/16]}\n";
    let plan = Plan::prepare(&parse(source), Platform::Linux).unwrap();
    assert_eq!(
        plan.policy().select("10.1.2.3".parse().unwrap()),
        Some(BackendId(2))
    );
    assert_eq!(
        plan.policy().select("10.2.2.3".parse().unwrap()),
        Some(BackendId(1))
    );
    assert_eq!(plan.policy().select("203.0.113.7".parse().unwrap()), None);
    assert_eq!(
        plan.endpoints().collect::<Vec<_>>(),
        vec![
            (BackendId(1), "198.51.100.1:1080".parse().unwrap()),
            (BackendId(2), "198.51.100.2:1080".parse().unwrap())
        ]
    );
}
#[test]
fn unsupported_fields_and_inconsistent_snapshots_fail_with_typed_redacted_errors() {
    struct Case {
        id: &'static str,
        change: fn(&mut Config),
        expected: Error,
    }
    for case in [
        Case {
            id: "dns",
            change: |c| c.tunnel.serve_dns = true,
            expected: Error::UnsupportedDns,
        },
        Case {
            id: "direct dns",
            change: |c| c.direct_upstreams.push("192.0.2.53".parse().unwrap()),
            expected: Error::UnsupportedDns,
        },
        Case {
            id: "ipv6",
            change: |c| c.ipv6 = true,
            expected: Error::UnsupportedFamily,
        },
        Case {
            id: "mtu",
            change: |c| c.tunnel.mtu = 1500,
            expected: Error::UnsupportedMtu,
        },
        Case {
            id: "dynamic",
            change: |c| c.protocols[0].routing_mode = RoutingMode::Dynamic,
            expected: Error::UnsupportedRouting,
        },
        Case {
            id: "domain",
            change: |c| c.protocols[0].domains.push("sample.example.test".into()),
            expected: Error::UnsupportedDns,
        },
        Case {
            id: "backend dns",
            change: |c| c.protocols[0].dns.push("192.0.2.53".parse().unwrap()),
            expected: Error::UnsupportedDns,
        },
        Case {
            id: "route identity",
            change: |c| c.protocols[0].routes[0].backend = BackendId(7),
            expected: Error::InvalidConfiguration,
        },
        Case {
            id: "zero identity",
            change: |c| c.protocols[0].registry_id = BackendId(0),
            expected: Error::InvalidConfiguration,
        },
        Case {
            id: "zero flow limit",
            change: |c| c.limits.max_tcp_flows = 0,
            expected: Error::InvalidLimits,
        },
        Case {
            id: "zero setup",
            change: |c| c.timeouts.connect = Duration::ZERO,
            expected: Error::InvalidLimits,
        },
        Case {
            id: "excessive age",
            change: |c| c.timeouts.flow_max_age = Duration::MAX,
            expected: Error::InvalidLimits,
        },
        Case {
            id: "unsafe tunnel",
            change: |c| c.tunnel.ipv4 = std::net::Ipv4Addr::LOCALHOST,
            expected: Error::InvalidConfiguration,
        },
        Case {
            id: "unsafe name",
            change: |c| c.tunnel.name = Some("../secret".into()),
            expected: Error::InvalidConfiguration,
        },
    ] {
        let mut config = config();
        (case.change)(&mut config);
        let error = Plan::prepare(&config, Platform::Linux).unwrap_err();
        assert_eq!(error, case.expected, "{}", case.id);
        assert!(!error.to_string().contains("sample.example.test"));
        assert!(!error.to_string().contains("secret"));
    }
    assert!(matches!(
        Plan::prepare(&config(), Platform::MacOs),
        Err(Error::UnsupportedPlatform)
    ));
}
#[test]
fn file_credentials_and_hostnames_are_never_resolved_or_opened() {
    for (fields, expected) in [
        (
            "host: proxy.example.test:1080, ips: [10.0.0.0/8]",
            Error::EndpointResolutionRequired,
        ),
        (
            "host: '198.51.100.1:1080', user: sample, password_file: /fixture/does-not-exist, ips: [10.0.0.0/8]",
            Error::CredentialImportRequired,
        ),
        (
            "host: '[2001:db8::1]:1080', ips: [10.0.0.0/8]",
            Error::UnsupportedFamily,
        ),
    ] {
        let source = format!("tunnel: {{ip: 192.0.2.1}}\nprotocols: [{{socks5: {{{fields}}}}}]\n");
        assert!(
            matches!(Plan::prepare(&parse(&source),Platform::Linux),Err(error) if error==expected)
        );
    }
}
#[test]
fn inline_credentials_are_charged_and_never_exposed_by_plan_diagnostics() {
    let source = "tunnel: {ip: 192.0.2.1}\nprotocols: [{socks5: {host: '198.51.100.1:1080', user: sample, password: sample-secret, ips: [10.0.0.0/8]}}]\n";
    let plan = Plan::prepare(&parse(source), Platform::Linux).unwrap();
    assert_eq!(
        plan.buffers().credentials,
        "sample".len() + "sample-secret".len()
    );
    assert_eq!(format!("{plan:?}"), "Plan(<redacted>)");
}
#[cfg(target_os = "linux")]
struct RejectConnector(AtomicUsize);
#[cfg(target_os = "linux")]
impl EndpointConnector for RejectConnector {
    fn connect_tcp(&self, _endpoint: SocketAddr, _request: Request) -> OpenTcp<'_> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Box::pin(async { Err(TransportError::UnsupportedCapability) })
    }
}
#[cfg(target_os = "linux")]
#[tokio::test]
async fn allocation_creates_real_adapters_without_dialing_or_starting_networking() {
    let plan = Plan::prepare(&config(), Platform::Linux).unwrap();
    let expected = plan.buffers();
    let connector = Arc::new(RejectConnector(AtomicUsize::new(0)));
    let Networking {
        tunnel,
        runtime,
        channels,
        relays,
        buffers,
    } = plan
        .instantiate(Seed::generate().unwrap(), connector.clone())
        .unwrap();
    assert_eq!(
        tunnel.ipv4,
        "192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap()
    );
    assert_eq!(buffers, expected);
    assert_eq!(runtime.buffer_capacity(), buffers.stack_runtime);
    assert_eq!(relays.retained(), 0);
    assert_eq!(connector.0.load(Ordering::Relaxed), 0);
    channels.shutdown.send(()).unwrap();
    let report = runtime.run().await.unwrap();
    assert_eq!(report.admitted_packets, 0);
    assert_eq!(relays.shutdown().await.admitted, 0);
}

#[test]
fn unimplemented_protocols_excessive_registry_and_invalid_runtime_values_are_rejected() {
    for fields in [
        "ssh: {host: 198.51.100.2, user: sample, password: sample-secret, ips: [10.0.0.0/8]}",
        "wireguard: {private_key: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=', peer_public_key: 'ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=', endpoint: '198.51.100.2:51820', address: 10.66.66.2, ips: [10.0.0.0/8]}",
    ] {
        let source = format!("tunnel: {{ip: 192.0.2.1}}\nprotocols: [{{{fields}}}]\n");
        assert!(matches!(
            Plan::prepare(&parse(&source), Platform::Linux),
            Err(Error::UnsupportedBackend)
        ));
    }
    let mut sample = config();
    sample.protocols = vec![sample.protocols[0].clone(); 65];
    assert!(matches!(
        Plan::prepare(&sample, Platform::Linux),
        Err(Error::InvalidLimits)
    ));
    sample.protocols.truncate(2);
    assert!(matches!(
        Plan::prepare(&sample, Platform::Linux),
        Err(Error::InvalidConfiguration)
    ));
    let mut sample = config();
    sample.timeouts.shutdown = Duration::MAX;
    assert!(matches!(
        Plan::prepare(&sample, Platform::Linux),
        Err(Error::InvalidLimits)
    ));
    let mut sample = config();
    if let BackendSettings::Socks5(socks) = &mut sample.protocols[0].settings {
        socks.endpoint.port = 0;
    }
    assert!(matches!(
        Plan::prepare(&sample, Platform::Linux),
        Err(Error::InvalidConfiguration)
    ));
    let mut sample = config();
    sample.protocols[0].routes[0].network = "10.1.2.3".parse().unwrap();
    assert!(matches!(
        Plan::prepare(&sample, Platform::Linux),
        Err(Error::InvalidConfiguration)
    ));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn instantiated_backend_failure_is_reported_once_and_all_allocated_owners_shutdown() {
    let plan = Plan::prepare(&config(), Platform::Linux).unwrap();
    let destination = "10.1.2.3:443".parse::<SocketAddr>().unwrap();
    let backend = plan.policy().select(destination.ip()).unwrap();
    let connector = Arc::new(RejectConnector(AtomicUsize::new(0)));
    let Networking {
        runtime,
        channels,
        mut relays,
        ..
    } = plan
        .instantiate(Seed::generate().unwrap(), connector.clone())
        .unwrap();
    let (_app, capture) = tokio::io::duplex(128);
    relays
        .admit(warper_core::transport::CapturedTcp {
            metadata: warper_core::transport::Metadata {
                id: 1,
                source: "192.0.2.2:50000".parse().unwrap(),
                destination,
                backend,
            },
            stream: Box::new(capture),
        })
        .unwrap();
    let completion = relays.next().await.unwrap().unwrap();
    assert_eq!(completion.backend, backend);
    assert_eq!(
        completion.outcome,
        Err(relay::FlowError::Setup(
            TransportError::UnsupportedCapability
        ))
    );
    assert_eq!(connector.0.load(Ordering::Relaxed), 1);
    let report = relays.shutdown().await;
    assert_eq!(report.first_flow_failure, Some(completion));
    channels.shutdown.send(()).unwrap();
    assert_eq!(runtime.run().await.unwrap().admitted_packets, 0);
}
