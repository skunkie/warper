// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use crate::dns::Limits;

fn name(value: &str) -> Name {
    Name::from_ascii(value).unwrap()
}
fn wire(owner: &str, kind: u16, response: bool) -> Vec<u8> {
    let mut bytes = vec![
        0,
        19,
        if response { 0x81 } else { 1 },
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    bytes.extend_from_slice(name(owner).wire());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes
}
fn record(
    bytes: &mut Vec<u8>,
    section: usize,
    owner: &str,
    kind: u16,
    class: u16,
    ttl: u32,
    data: &[u8],
) {
    bytes[section + 1] += 1;
    bytes.extend_from_slice(name(owner).wire());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&class.to_be_bytes());
    bytes.extend_from_slice(&ttl.to_be_bytes());
    bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
    bytes.extend_from_slice(data);
}
fn service(
    bytes: &mut Vec<u8>,
    owner: &str,
    kind: u16,
    priority: u16,
    target: &str,
    ttl: u32,
    parameters: &[(u16, &[u8])],
) {
    let mut data = priority.to_be_bytes().to_vec();
    data.extend_from_slice(name(target).wire());
    for (key, value) in parameters {
        data.extend_from_slice(&key.to_be_bytes());
        data.extend_from_slice(&(value.len() as u16).to_be_bytes());
        data.extend_from_slice(value);
    }
    record(bytes, 6, owner, kind, 1, ttl, &data);
}
fn packet(owner: &str, kind: u16, bytes: &[u8]) -> Packet {
    let limits = Limits::new(65535, 64).unwrap();
    let request = Packet::request(&wire(owner, kind, false), limits).unwrap();
    Packet::response(bytes, &request, limits).unwrap()
}
fn bindings(set: BindingSet<'_>) -> Stored<ServiceBinding<'_>> {
    match set {
        BindingSet::ServiceMode(records) => records,
        _ => panic!("expected every ServiceMode alternative"),
    }
}

#[test]
fn every_priority_hint_and_unknown_mandatory_parameter_is_preserved() {
    let now = Instant::now();
    let v6: std::net::Ipv6Addr = "2001:db8::5".parse().unwrap();
    for kind in [64, 65] {
        let mut bytes = wire("service.test", kind, true);
        service(
            &mut bytes,
            "service.test",
            kind,
            99,
            "alt.test",
            10,
            &[
                (0, &[0, 123]),
                (4, &[192, 0, 2, 1, 192, 0, 2, 2]),
                (6, &v6.octets()),
                (123, &[7, 9]),
            ],
        );
        service(
            &mut bytes,
            "service.test",
            kind,
            1,
            ".",
            20,
            &[(4, &[192, 0, 2, 3])],
        );
        let response = packet("service.test", kind, &bytes);
        let encoded = response.encode().unwrap();
        let entries = bindings(
            response
                .service_bindings(name("service.test"), now)
                .unwrap(),
        );
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].priority(), 99);
        assert_eq!(entries[0].owner(), name("service.test"));
        assert_eq!(entries[0].target(), name("alt.test"));
        assert_eq!(
            entries[0].hints().collect::<Vec<_>>(),
            [
                "192.0.2.1".parse::<IpAddr>().unwrap(),
                "192.0.2.2".parse().unwrap(),
                IpAddr::V6(v6)
            ]
        );
        assert_eq!(entries[1].priority(), 1);
        assert_eq!(entries[1].target(), name("service.test"));
        assert_eq!(
            entries[1].hints().collect::<Vec<_>>(),
            ["192.0.2.3".parse::<IpAddr>().unwrap()]
        );
        assert!(
            entries
                .iter()
                .all(|entry| entry.expires_at() == now + Duration::from_secs(10))
        );
        assert_eq!(
            response.encode().unwrap(),
            encoded,
            "discovery must not filter or rewrite the passed-through RRset"
        );
        assert!(!format!("{entries:?}").contains("192.0.2"));
    }
}

#[test]
fn root_service_targets_keep_effective_owner_and_alias_targets_are_not_prefixed() {
    let now = Instant::now();
    for (kind, owner) in [
        (64, "_8443._custom.service.test"),
        (65, "_8443._https.service.test"),
    ] {
        let mut bytes = wire(owner, kind, true);
        service(&mut bytes, owner, kind, 1, ".", 5, &[]);
        let response = packet(owner, kind, &bytes);
        assert_eq!(
            bindings(response.service_bindings(name(owner), now).unwrap())[0].target(),
            name(owner)
        );
        let mut bytes = wire(owner, kind, true);
        service(&mut bytes, owner, kind, 0, "alias.test", 5, &[]);
        let response = packet(owner, kind, &bytes);
        let BindingSet::AliasMode(aliases) = response.service_bindings(name(owner), now).unwrap()
        else {
            panic!("expected AliasMode");
        };
        assert_eq!(
            aliases[..],
            [ServiceAlias::Target(TimedAlias {
                target: name("alias.test"),
                expires_at: now + Duration::from_secs(5)
            })]
        );
    }
}

#[test]
fn alias_mode_suppresses_service_mode_and_ignores_parameters() {
    let now = Instant::now();
    let mut bytes = wire("service.test", 65, true);
    // These ServiceMode parameters are inconsistent but the record is ignored.
    service(
        &mut bytes,
        "service.test",
        65,
        1,
        "ignored.test",
        30,
        &[(2, &[])],
    );
    // AliasMode parameters never become usable hints.
    service(
        &mut bytes,
        "service.test",
        65,
        0,
        "one.test",
        20,
        &[(4, &[192, 0, 2, 1])],
    );
    service(
        &mut bytes,
        "service.test",
        65,
        0,
        "two.test",
        10,
        &[(2, &[])],
    );
    service(&mut bytes, "service.test", 65, 0, "ONE.test", 25, &[]);
    service(&mut bytes, "service.test", 65, 0, ".", 15, &[]);
    let response = packet("service.test", 65, &bytes);
    let BindingSet::AliasMode(aliases) = response
        .service_bindings(name("service.test"), now)
        .unwrap()
    else {
        panic!("expected AliasMode");
    };
    let expires_at = now + Duration::from_secs(10);
    assert_eq!(
        aliases[..],
        [
            ServiceAlias::Target(TimedAlias {
                target: name("one.test"),
                expires_at
            }),
            ServiceAlias::Target(TimedAlias {
                target: name("two.test"),
                expires_at
            }),
            ServiceAlias::Unavailable { expires_at }
        ]
    );
}

#[test]
fn unrelated_service_data_and_the_other_rr_type_do_not_expand_discovery() {
    let mut bytes = wire("service.test", 65, true);
    service(
        &mut bytes,
        "unrelated.test",
        65,
        1,
        "foreign.test",
        1,
        &[(2, &[])],
    );
    service(&mut bytes, "service.test", 64, 1, "other-type.test", 1, &[]);
    service(&mut bytes, "service.test", 65, 1, "target.test", 20, &[]);
    // Same owner/type but wrong class is irrelevant.
    record(&mut bytes, 6, "service.test", 65, 3, 1, &[0, 0, 0]);
    // A service RR in Additional is not a reachable Answer service RRset.
    record(&mut bytes, 10, "service.test", 65, 1, 1, &[0, 0, 0]);
    let response = packet("service.test", 65, &bytes);
    let entries = bindings(
        response
            .service_bindings(name("service.test"), Instant::now())
            .unwrap(),
    );
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].target(), name("target.test"));
    assert!(matches!(
        response
            .service_bindings(name("absent.test"), Instant::now())
            .unwrap(),
        BindingSet::Empty
    ));
}

#[test]
fn malformed_self_consistency_rejects_the_whole_reachable_service_set() {
    struct Case {
        id: &'static str,
        parameters: Vec<(u16, Vec<u8>)>,
    }
    for case in [
        Case {
            id: "mandatory itself",
            parameters: vec![(0, vec![0, 0])],
        },
        Case {
            id: "missing mandatory",
            parameters: vec![(0, vec![0, 3])],
        },
        Case {
            id: "repeated mandatory",
            parameters: vec![(0, vec![0, 3, 0, 3]), (3, vec![1, 187])],
        },
        Case {
            id: "unordered mandatory",
            parameters: vec![
                (0, vec![0, 4, 0, 3]),
                (3, vec![1, 187]),
                (4, vec![192, 0, 2, 1]),
            ],
        },
        Case {
            id: "no default without alpn",
            parameters: vec![(2, vec![])],
        },
        Case {
            id: "empty v4 hints",
            parameters: vec![(4, vec![])],
        },
        Case {
            id: "empty v6 hints",
            parameters: vec![(6, vec![])],
        },
        Case {
            id: "reserved invalid key",
            parameters: vec![(65535, vec![])],
        },
    ] {
        let mut bytes = wire("service.test", 65, true);
        service(&mut bytes, "service.test", 65, 1, "safe.test", 10, &[]);
        let parameters = case
            .parameters
            .iter()
            .map(|(key, value)| (*key, value.as_slice()))
            .collect::<Vec<_>>();
        service(
            &mut bytes,
            "service.test",
            65,
            99,
            "unsafe.test",
            10,
            &parameters,
        );
        let response = packet("service.test", 65, &bytes);
        assert!(
            matches!(
                response.service_bindings(name("service.test"), Instant::now()),
                Err(ServiceError::Malformed)
            ),
            "{}",
            case.id
        );
    }
    let mut bytes = wire("service.test", 65, true);
    service(
        &mut bytes,
        "service.test",
        65,
        1,
        ".",
        10,
        &[(1, b"\x02h2"), (2, &[])],
    );
    assert!(matches!(
        packet("service.test", 65, &bytes)
            .service_bindings(name("service.test"), Instant::now())
            .unwrap(),
        BindingSet::ServiceMode(_)
    ));
}

#[test]
fn cname_is_distinct_and_conflicting_or_coexisting_data_fails() {
    let now = Instant::now();
    for conflict in [None, Some(1), Some(5), Some(65)] {
        let mut bytes = wire("service.test", 65, true);
        record(
            &mut bytes,
            6,
            "service.test",
            5,
            1,
            20,
            name("alias.test").wire(),
        );
        record(
            &mut bytes,
            6,
            "service.test",
            5,
            1,
            10,
            name("ALIAS.test").wire(),
        );
        match conflict {
            Some(1) => record(&mut bytes, 6, "service.test", 1, 1, 1, &[192, 0, 2, 1]),
            Some(5) => record(
                &mut bytes,
                6,
                "service.test",
                5,
                1,
                1,
                name("other.test").wire(),
            ),
            Some(65) => service(&mut bytes, "service.test", 65, 1, ".", 1, &[]),
            _ => {}
        }
        let response = packet("service.test", 65, &bytes);
        let result = response.service_bindings(name("service.test"), now);
        if conflict.is_some() {
            assert!(matches!(result, Err(ServiceError::Malformed)));
        } else {
            assert!(
                matches!(result.unwrap(), BindingSet::Cname(TimedAlias { target, expires_at }) if target == name("alias.test") && expires_at == now + Duration::from_secs(10))
            );
        }
    }
}

#[test]
fn negatives_empty_sets_and_zero_freshness_preserve_wire_semantics() {
    let now = Instant::now();
    for code in [0, 2, 3, 5] {
        let mut bytes = wire("service.test", 65, true);
        bytes[3] = code;
        let response = packet("service.test", 65, &bytes);
        let result = response
            .service_bindings(name("service.test"), now)
            .unwrap();
        if code == 0 {
            assert!(matches!(result, BindingSet::Empty));
        } else {
            assert!(matches!(result, BindingSet::Negative(value) if value == u16::from(code)));
        }
    }
    for ttl in [0, 0x8000_0000, u32::MAX] {
        let mut bytes = wire("service.test", 65, true);
        service(&mut bytes, "service.test", 65, 1, ".", ttl, &[]);
        let response = packet("service.test", 65, &bytes);
        assert_eq!(
            bindings(
                response
                    .service_bindings(name("service.test"), now)
                    .unwrap()
            )[0]
            .expires_at(),
            now
        );
        assert_eq!(response.message.answers[0].ttl, ttl);
    }
}

#[test]
fn related_addresses_keep_both_families_sections_and_minimum_rrset_ttls() {
    let now = Instant::now();
    let mut bytes = wire("service.test", 65, true);
    record(&mut bytes, 6, "target.test", 1, 1, 30, &[192, 0, 2, 1]);
    record(&mut bytes, 6, "target.test", 1, 1, 20, &[192, 0, 2, 1]);
    record(&mut bytes, 8, "target.test", 1, 1, 1, &[192, 0, 2, 9]);
    let ip: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
    record(&mut bytes, 10, "target.test", 28, 1, 10, &ip.octets());
    record(&mut bytes, 10, "target.test", 1, 1, 15, &[192, 0, 2, 1]);
    record(&mut bytes, 10, "unrelated.test", 1, 1, 1, &[192, 0, 2, 99]);
    record(&mut bytes, 10, "target.test", 1, 3, 1, &[192, 0, 2, 98]);
    let response = packet("service.test", 65, &bytes);
    let RelatedSet::Addresses(addresses) = response
        .related_addresses(name("target.test"), now, 2)
        .unwrap()
    else {
        panic!("missing related endpoints");
    };
    assert_eq!(
        addresses[..],
        [
            RelatedAddress {
                address: Address {
                    ip: "192.0.2.1".parse().unwrap(),
                    expires_at: now + Duration::from_secs(15)
                },
                section: AddressSection::Answer
            },
            RelatedAddress {
                address: Address {
                    ip: IpAddr::V6(ip),
                    expires_at: now + Duration::from_secs(10)
                },
                section: AddressSection::Additional
            },
            RelatedAddress {
                address: Address {
                    ip: "192.0.2.1".parse().unwrap(),
                    expires_at: now + Duration::from_secs(15)
                },
                section: AddressSection::Additional
            }
        ]
    );
    assert!(matches!(
        response.related_addresses(name("target.test"), now, 1),
        Err(ServiceError::ResourceLimit)
    ));
    assert!(matches!(
        response
            .related_addresses(name("absent.test"), now, 1)
            .unwrap(),
        RelatedSet::Empty
    ));
}

#[test]
fn related_cname_is_an_explicit_continuation_and_ambiguity_is_rejected() {
    let now = Instant::now();
    for conflict in [None, Some(1), Some(5)] {
        let mut bytes = wire("service.test", 65, true);
        record(
            &mut bytes,
            10,
            "target.test",
            5,
            1,
            10,
            name("end.test").wire(),
        );
        record(
            &mut bytes,
            10,
            "target.test",
            5,
            1,
            0,
            name("END.test").wire(),
        );
        match conflict {
            Some(1) => record(&mut bytes, 10, "target.test", 1, 1, 1, &[192, 0, 2, 1]),
            Some(5) => record(
                &mut bytes,
                10,
                "target.test",
                5,
                1,
                1,
                name("foreign.test").wire(),
            ),
            _ => {}
        }
        let response = packet("service.test", 65, &bytes);
        let result = response.related_addresses(name("target.test"), now, 1);
        if conflict.is_some() {
            assert!(matches!(result, Err(ServiceError::Malformed)));
        } else {
            assert!(
                matches!(result.unwrap(), RelatedSet::Cname(TimedAlias { target, expires_at }) if target == name("end.test") && expires_at == now)
            );
        }
    }
}

#[test]
fn related_negative_answers_create_no_address_metadata() {
    let mut bytes = wire("service.test", 65, true);
    bytes[3] = 3;
    record(&mut bytes, 10, "target.test", 1, 1, 10, &[192, 0, 2, 1]);
    let response = packet("service.test", 65, &bytes);
    assert!(matches!(
        response
            .related_addresses(name("target.test"), Instant::now(), 1)
            .unwrap(),
        RelatedSet::Empty
    ));
}

#[test]
fn request_direction_question_type_class_and_limits_are_validated() {
    let limits = Limits::new(512, 16).unwrap();
    let request = Packet::request(&wire("service.test", 65, false), limits).unwrap();
    assert!(matches!(
        request.service_bindings(name("service.test"), Instant::now()),
        Err(ServiceError::InvalidQuestion)
    ));
    assert!(matches!(
        request.related_addresses(name("service.test"), Instant::now(), 1),
        Err(ServiceError::InvalidQuestion)
    ));
    let response = packet("service.test", 1, &wire("service.test", 1, true));
    assert!(matches!(
        response.service_bindings(name("service.test"), Instant::now()),
        Err(ServiceError::InvalidQuestion)
    ));
    assert!(matches!(
        response.related_addresses(name("service.test"), Instant::now(), 0),
        Err(ServiceError::InvalidLimits)
    ));
    let mut request = wire("service.test", 65, false);
    let last = request.len() - 1;
    request[last] = 3;
    let query = Packet::request(&request, limits).unwrap();
    request[2] = 0x81;
    let response = Packet::response(&request, &query, limits).unwrap();
    assert!(matches!(
        response.service_bindings(name("service.test"), Instant::now()),
        Err(ServiceError::InvalidQuestion)
    ));
}

#[test]
fn additional_records_cannot_contradict_service_or_cname_ownership() {
    let now = Instant::now();
    for case in 0..3 {
        let mut bytes = wire("service.test", 65, true);
        if case == 0 {
            service(&mut bytes, "service.test", 65, 1, ".", 10, &[]);
        } else {
            record(
                &mut bytes,
                6,
                "service.test",
                5,
                1,
                10,
                name("target.test").wire(),
            );
        }
        if case == 1 {
            record(&mut bytes, 10, "service.test", 1, 1, 10, &[192, 0, 2, 1]);
        } else {
            record(
                &mut bytes,
                10,
                "service.test",
                5,
                1,
                10,
                name("foreign.test").wire(),
            );
        }
        let response = packet("service.test", 65, &bytes);
        assert!(
            matches!(
                response.service_bindings(name("service.test"), now),
                Err(ServiceError::Malformed)
            ),
            "case {case}"
        );
    }
}

#[test]
fn packet_views_retain_metadata_and_reject_byte_pressure_before_allocation() {
    let buffers = crate::dns::memory::Budget::new(1_048_576).unwrap();
    let limits = Limits::new(65535, 64).unwrap();
    let request =
        Packet::request_with_budget(&wire("service.test", 65, false), limits, &buffers).unwrap();
    let now = Instant::now();
    for priority in [0, 1] {
        let mut bytes = wire("service.test", 65, true);
        service(
            &mut bytes,
            "service.test",
            65,
            priority,
            "target.test",
            10,
            &[],
        );
        record(&mut bytes, 10, "target.test", 1, 1, 10, &[192, 0, 2, 1]);
        let response = Packet::response(&bytes, &request, limits).unwrap();
        let baseline = buffers.used();
        let competing = buffers.reserve(buffers.limit() - baseline).unwrap();
        assert!(matches!(
            response.service_bindings(name("service.test"), now),
            Err(ServiceError::ResourceLimit)
        ));
        assert!(matches!(
            response.related_addresses(name("target.test"), now, 1),
            Err(ServiceError::ResourceLimit)
        ));
        assert_eq!(buffers.used(), buffers.limit());
        drop(competing);
        match response
            .service_bindings(name("service.test"), now)
            .unwrap()
        {
            BindingSet::AliasMode(values) => {
                let mut values = values.into_iter();
                assert!(buffers.used() > baseline);
                assert!(values.next().is_some());
                assert!(values.next().is_none());
                assert!(buffers.used() > baseline);
                drop(values);
            }
            BindingSet::ServiceMode(values) => {
                let mut values = values.into_iter();
                assert!(buffers.used() > baseline);
                assert!(values.next().is_some());
                assert!(values.next().is_none());
                assert!(buffers.used() > baseline);
                drop(values);
            }
            _ => panic!("expected an admitted service view"),
        }
        assert_eq!(buffers.used(), baseline);
        let RelatedSet::Addresses(values) = response
            .related_addresses(name("target.test"), now, 1)
            .unwrap()
        else {
            panic!("expected related addresses");
        };
        assert!(buffers.used() > baseline);
        let mut values = values.into_iter();
        assert!(values.next().is_some());
        assert!(values.next().is_none());
        assert!(buffers.used() > baseline);
        drop(values);
        assert_eq!(buffers.used(), baseline);
        drop(response);
    }
    drop(request);
    assert_eq!(buffers.used(), 0);
}
