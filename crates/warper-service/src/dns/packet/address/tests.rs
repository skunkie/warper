// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use crate::dns::Limits;

fn name(value: &str) -> Name {
    Name::from_ascii(value).unwrap()
}

fn question(owner: &str, record_type: u16) -> Question {
    Question {
        name: name(owner),
        record_type,
        class: 1,
    }
}

fn wire(query: Question, response: bool) -> Vec<u8> {
    let mut bytes = vec![
        0,
        17,
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
    bytes.extend_from_slice(query.name.wire());
    bytes.extend_from_slice(&query.record_type.to_be_bytes());
    bytes.extend_from_slice(&query.class.to_be_bytes());
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

fn alias(bytes: &mut Vec<u8>, owner: &str, target: &str, ttl: u32) {
    record(bytes, 6, owner, 5, 1, ttl, name(target).wire());
}

fn address(bytes: &mut Vec<u8>, owner: &str, ttl: u32, ip: [u8; 4]) {
    record(bytes, 6, owner, 1, 1, ttl, &ip);
}

fn packet(query: Question, bytes: &[u8]) -> Packet {
    let limits = Limits::new(65535, 64).unwrap();
    let request = Packet::request(&wire(query, false), limits).unwrap();
    Packet::response(bytes, &request, limits).unwrap()
}

fn complete(progress: AddressProgress) -> AddressAnswer {
    match progress {
        AddressProgress::Complete(answer) => answer,
        AddressProgress::Followup(_) => panic!("unexpected address dependency query"),
    }
}

fn followup(progress: AddressProgress) -> AddressLookup {
    match progress {
        AddressProgress::Followup(lookup) => lookup,
        AddressProgress::Complete(_) => panic!("missing address dependency query"),
    }
}

#[test]
fn out_of_order_aliases_keep_only_reachable_answer_addresses() {
    let query = question("start.example.test", 1);
    let mut bytes = wire(query, true);
    address(&mut bytes, "end.example.test", 40, [192, 0, 2, 1]);
    address(&mut bytes, "unrelated.test", 1, [192, 0, 2, 99]);
    record(&mut bytes, 6, "end.example.test", 1, 3, 1, &[192, 0, 2, 96]);
    alias(&mut bytes, "mid.example.test", "end.example.test", 10);
    alias(&mut bytes, "start.example.test", "mid.example.test", 20);
    record(&mut bytes, 8, "end.example.test", 1, 1, 1, &[192, 0, 2, 97]);
    record(
        &mut bytes,
        10,
        "end.example.test",
        1,
        1,
        1,
        &[192, 0, 2, 98],
    );
    let response = packet(query, &bytes);
    let before = response.encode().unwrap();
    let now = Instant::now();
    let answer = complete(
        AddressLookup::new(query, 2, 1)
            .unwrap()
            .advance(&response, now)
            .unwrap(),
    );
    assert_eq!(answer.question, query);
    assert_eq!(answer.canonical_name, name("end.example.test"));
    assert_eq!(
        answer.aliases[..],
        [name("mid.example.test"), name("end.example.test")]
    );
    assert_eq!(
        answer.addresses[..],
        [Address {
            ip: "192.0.2.1".parse().unwrap(),
            expires_at: now + Duration::from_secs(10)
        }]
    );
    assert_eq!(
        response.encode().unwrap(),
        before,
        "analysis must preserve the original response"
    );
}

#[test]
fn followup_preserves_original_question_path_and_expiry() {
    let query = question("start.test", 1);
    let now = Instant::now();
    let mut bytes = wire(query, true);
    alias(&mut bytes, "start.test", "end.test", 2);
    let lookup = followup(
        AddressLookup::new(query, 1, 1)
            .unwrap()
            .advance(&packet(query, &bytes), now)
            .unwrap(),
    );
    let dependency = lookup.question();
    assert_eq!(dependency, question("end.test", 1));
    let mut bytes = wire(dependency, true);
    address(&mut bytes, "end.test", 60, [192, 0, 2, 1]);
    let answer = complete(
        lookup
            .advance(&packet(dependency, &bytes), now + Duration::from_secs(5))
            .unwrap(),
    );
    assert_eq!(answer.question, query);
    assert_eq!(
        answer.addresses[0].expires_at,
        now + Duration::from_secs(2),
        "dependency I/O must not renew alias freshness"
    );
}

#[test]
fn duplicate_addresses_and_unequal_rrset_ttls_use_one_slot_and_minimum() {
    let query = question("sample.test", 1);
    let mut bytes = wire(query, true);
    address(&mut bytes, "sample.test", 20, [192, 0, 2, 1]);
    address(&mut bytes, "sample.test", 5, [192, 0, 2, 1]);
    address(&mut bytes, "sample.test", 10, [192, 0, 2, 2]);
    let now = Instant::now();
    let answer = complete(
        AddressLookup::new(query, 0, 2)
            .unwrap()
            .advance(&packet(query, &bytes), now)
            .unwrap(),
    );
    assert_eq!(answer.addresses.len(), 2);
    assert!(
        answer
            .addresses
            .iter()
            .all(|address| address.expires_at == now + Duration::from_secs(5))
    );
    assert!(matches!(
        AddressLookup::new(query, 0, 1)
            .unwrap()
            .advance(&packet(query, &bytes), now),
        Err(AddressError::ResourceLimit)
    ));
}

#[test]
fn zero_and_high_bit_ttls_have_zero_freshness() {
    let query = question("sample.test", 1);
    let now = Instant::now();
    for ttl in [0, 0x8000_0000, u32::MAX] {
        let mut bytes = wire(query, true);
        address(&mut bytes, "sample.test", ttl, [192, 0, 2, 1]);
        let answer = complete(
            AddressLookup::new(query, 0, 1)
                .unwrap()
                .advance(&packet(query, &bytes), now)
                .unwrap(),
        );
        assert_eq!(answer.addresses[0].expires_at, now, "TTL {ttl}");
    }
    let mut bytes = wire(query, true);
    alias(&mut bytes, "sample.test", "end.test", 0);
    address(&mut bytes, "end.test", 60, [192, 0, 2, 1]);
    let answer = complete(
        AddressLookup::new(query, 1, 1)
            .unwrap()
            .advance(&packet(query, &bytes), now)
            .unwrap(),
    );
    assert_eq!(answer.addresses[0].expires_at, now);
}

#[test]
fn ipv6_answers_preserve_family_and_ignore_other_record_types() {
    let query = question("sample.test", 28);
    let mut bytes = wire(query, true);
    address(&mut bytes, "sample.test", 1, [192, 0, 2, 1]);
    record(&mut bytes, 6, "sample.test", 16, 1, 1, b"\x04test");
    let ip: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
    record(&mut bytes, 6, "sample.test", 28, 1, 20, &ip.octets());
    let now = Instant::now();
    let answer = complete(
        AddressLookup::new(query, 0, 1)
            .unwrap()
            .advance(&packet(query, &bytes), now)
            .unwrap(),
    );
    assert_eq!(
        answer.addresses[..],
        [Address {
            ip: IpAddr::V6(ip),
            expires_at: now + Duration::from_secs(20)
        }]
    );
}

#[test]
fn valid_negatives_finish_without_an_address_or_followup() {
    let query = question("sample.test", 1);
    for code in [0, 2, 3, 5] {
        let mut bytes = wire(query, true);
        bytes[3] = code;
        if code != 0 {
            alias(&mut bytes, "sample.test", "end.test", 10);
        }
        let answer = complete(
            AddressLookup::new(query, 1, 1)
                .unwrap()
                .advance(&packet(query, &bytes), Instant::now())
                .unwrap(),
        );
        assert_eq!(answer.response_code, u16::from(code));
        assert!(answer.addresses.is_empty());
    }
    let mut bytes = wire(query, true);
    alias(&mut bytes, "sample.test", "end.test", 10);
    let lookup = followup(
        AddressLookup::new(query, 1, 1)
            .unwrap()
            .advance(&packet(query, &bytes), Instant::now())
            .unwrap(),
    );
    let query = lookup.question();
    let answer = complete(
        lookup
            .advance(&packet(query, &wire(query, true)), Instant::now())
            .unwrap(),
    );
    assert_eq!(answer.response_code, 0);
    assert!(answer.addresses.is_empty());
}

#[test]
fn conflicting_alias_targets_and_alias_address_coexistence_are_rejected() {
    let query = question("sample.test", 1);
    let now = Instant::now();
    for conflict in [0, 1, 2] {
        let mut bytes = wire(query, true);
        alias(&mut bytes, "sample.test", "end.test", 10);
        match conflict {
            0 => alias(&mut bytes, "sample.test", "other.test", 10),
            1 => address(&mut bytes, "sample.test", 10, [192, 0, 2, 1]),
            _ => record(&mut bytes, 6, "sample.test", 28, 1, 10, &[0; 16]),
        }
        assert!(
            matches!(
                AddressLookup::new(query, 2, 2)
                    .unwrap()
                    .advance(&packet(query, &bytes), now),
                Err(AddressError::Malformed)
            ),
            "case {conflict}"
        );
    }
    let mut bytes = wire(query, true);
    bytes[3] = 3;
    address(&mut bytes, "sample.test", 10, [192, 0, 2, 1]);
    assert!(matches!(
        AddressLookup::new(query, 1, 1)
            .unwrap()
            .advance(&packet(query, &bytes), now),
        Err(AddressError::Malformed)
    ));
}

#[test]
fn alias_loops_are_detected_within_and_across_responses() {
    let query = question("sample.test", 1);
    let now = Instant::now();
    for target in ["sample.test", "mid.test"] {
        let mut bytes = wire(query, true);
        alias(&mut bytes, "sample.test", "mid.test", 10);
        alias(&mut bytes, "mid.test", target, 10);
        assert!(matches!(
            AddressLookup::new(query, 8, 1)
                .unwrap()
                .advance(&packet(query, &bytes), now),
            Err(AddressError::AliasLoop)
        ));
    }
    let mut bytes = wire(query, true);
    alias(&mut bytes, "sample.test", "mid.test", 10);
    let lookup = followup(
        AddressLookup::new(query, 8, 1)
            .unwrap()
            .advance(&packet(query, &bytes), now)
            .unwrap(),
    );
    let query = lookup.question();
    let mut bytes = wire(query, true);
    alias(&mut bytes, "mid.test", "sample.test", 10);
    assert!(matches!(
        lookup.advance(&packet(query, &bytes), now),
        Err(AddressError::AliasLoop)
    ));
}

#[test]
fn alias_hop_limit_spans_packets_and_duplicate_aliases_do_not_add_hops() {
    let query = question("sample.test", 1);
    let now = Instant::now();
    let mut bytes = wire(query, true);
    alias(&mut bytes, "sample.test", "mid.test", 10);
    alias(&mut bytes, "sample.test", "MID.test", 5);
    let response = packet(query, &bytes);
    assert!(matches!(
        AddressLookup::new(query, 0, 1)
            .unwrap()
            .advance(&response, now),
        Err(AddressError::ResourceLimit)
    ));
    let lookup = followup(
        AddressLookup::new(query, 1, 1)
            .unwrap()
            .advance(&response, now)
            .unwrap(),
    );
    let query = lookup.question();
    let mut bytes = wire(query, true);
    alias(&mut bytes, "mid.test", "end.test", 10);
    assert!(matches!(
        lookup.advance(&packet(query, &bytes), now),
        Err(AddressError::ResourceLimit)
    ));
}

#[test]
fn invalid_questions_limits_and_wrong_response_are_rejected() {
    for (record_type, class) in [(16, 1), (1, 3)] {
        let mut query = question("sample.test", record_type);
        query.class = class;
        assert!(matches!(
            AddressLookup::new(query, 1, 1),
            Err(AddressError::InvalidQuestion)
        ));
    }
    let query = question("sample.test", 1);
    assert!(matches!(
        AddressLookup::new(query, 1, 0),
        Err(AddressError::InvalidLimits)
    ));
    let limits = Limits::new(4096, 16).unwrap();
    let request = Packet::request(&wire(query, false), limits).unwrap();
    assert!(matches!(
        AddressLookup::new(query, 1, 1)
            .unwrap()
            .advance(&request, Instant::now()),
        Err(AddressError::MismatchedResponse)
    ));
    let other = question("other.test", 1);
    assert!(matches!(
        AddressLookup::new(query, 1, 1)
            .unwrap()
            .advance(&packet(other, &wire(other, true)), Instant::now()),
        Err(AddressError::MismatchedResponse)
    ));
}

#[test]
fn diagnostics_do_not_expose_names_or_packet_data() {
    let query = question("private-name.test", 1);
    let lookup = AddressLookup::new(query, 1, 1).unwrap();
    assert!(!format!("{lookup:?}").contains("private-name"));
    for error in [
        AddressError::InvalidQuestion,
        AddressError::InvalidLimits,
        AddressError::MismatchedResponse,
        AddressError::Malformed,
        AddressError::AliasLoop,
        AddressError::ResourceLimit,
    ] {
        assert!(!error.to_string().contains("private-name"));
    }
}

#[test]
fn repeated_identical_aliases_share_one_hop_and_use_minimum_ttl() {
    let query = question("sample.test", 1);
    let mut bytes = wire(query, true);
    alias(&mut bytes, "sample.test", "end.test", 50);
    alias(&mut bytes, "sample.test", "END.test", 3);
    address(&mut bytes, "end.test", 60, [192, 0, 2, 1]);
    let now = Instant::now();
    let answer = complete(
        AddressLookup::new(query, 1, 1)
            .unwrap()
            .advance(&packet(query, &bytes), now)
            .unwrap(),
    );
    assert_eq!(answer.aliases[..], [name("end.test")]);
    assert_eq!(answer.addresses[0].expires_at, now + Duration::from_secs(3));
}
