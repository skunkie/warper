// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;

fn limits() -> Limits {
    Limits::new(4096, 16).unwrap()
}

fn request_wire() -> Vec<u8> {
    let mut bytes = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    bytes.extend_from_slice(b"\x08_service\x04_tcp\x07ExAmPlE\x04test\0\0\x01\0\x01");
    bytes
}

fn response_wire() -> Vec<u8> {
    let mut bytes = request_wire();
    bytes[2] = 0x81;
    bytes[3] = 0x80;
    bytes
}

fn answer(bytes: &mut Vec<u8>, kind: u16, ttl: u32, data: &[u8]) {
    bytes[7] += 1;
    bytes.extend_from_slice(&[0xc0, 0x0c]);
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&ttl.to_be_bytes());
    bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
    bytes.extend_from_slice(data);
}

#[test]
fn request_roundtrip_preserves_service_labels_and_case_on_wire() {
    let wire = request_wire();
    let request = Packet::request(&wire, limits()).unwrap();
    assert_eq!(request.id(), 0x1234);
    assert_eq!(
        request.question(),
        Question {
            name: Name::from_ascii("_service._tcp.example.test").unwrap(),
            record_type: 1,
            class: 1,
        }
    );
    assert_eq!(request.encode().unwrap(), wire);
    assert_eq!(format!("{request:?}"), "Packet([redacted])");
}

#[test]
fn wire_names_preserve_binary_labels_and_the_maximum_length() {
    let long = [b'a'; 63];
    for name in [
        Name::from_labels([b"\xff.\0".as_slice(), b"test"]).unwrap(),
        Name::from_labels([long.as_slice(), &long, &long, &[b'b'; 61]]).unwrap(),
        Name::from_ascii(".").unwrap(),
    ] {
        let mut wire = request_wire()[..12].to_vec();
        wire.extend_from_slice(name.wire());
        wire.extend_from_slice(&[0, 1, 0, 1]);
        let request = Packet::request(&wire, limits()).unwrap();
        assert_eq!(request.question().name, name);
        assert_eq!(request.encode().unwrap(), wire);
    }
}

#[test]
fn compressed_answers_and_valid_negatives_remain_distinct() {
    let request = Packet::request(&request_wire(), limits()).unwrap();
    let mut wire = response_wire();
    answer(&mut wire, 1, 0, &[192, 0, 2, 7]);
    let response = Packet::response(&wire, &request, limits()).unwrap();
    assert_eq!(response.message.answers.len(), 1);
    assert_eq!(response.message.answers[0].ttl, 0);
    assert_eq!(response.response_code(), 0);
    let encoded = response.encode().unwrap();
    assert_eq!(
        Packet::response(&encoded, &request, limits())
            .unwrap()
            .message,
        response.message
    );
    for code in [0, 2, 3, 5] {
        let mut wire = response_wire();
        wire[3] |= code;
        let response = Packet::response(&wire, &request, limits()).unwrap();
        assert_eq!(response.response_code(), u16::from(code));
        assert!(response.message.answers.is_empty());
    }
}

#[test]
fn response_aging_rounds_down_remaining_ttls_in_every_record_section() {
    use std::time::Duration;

    struct Case {
        id: &'static str,
        elapsed: Duration,
        expected: u32,
    }
    for case in [
        Case {
            id: "same_observation",
            elapsed: Duration::ZERO,
            expected: 3,
        },
        Case {
            id: "fraction",
            elapsed: Duration::from_nanos(1),
            expected: 2,
        },
        Case {
            id: "whole_second",
            elapsed: Duration::from_secs(1),
            expected: 2,
        },
        Case {
            id: "past_second",
            elapsed: Duration::from_millis(1001),
            expected: 1,
        },
        Case {
            id: "expired",
            elapsed: Duration::from_secs(3),
            expected: 0,
        },
        Case {
            id: "huge_delay",
            elapsed: Duration::MAX,
            expected: 0,
        },
    ] {
        let query = Packet::request(&request_wire(), limits()).unwrap();
        let mut bytes = response_wire();
        for ttl in [3, 0, 0x8000_0000] {
            answer(&mut bytes, 1, ttl, &[192, 0, 2, 7]);
        }
        let mut packet = Packet::response(&bytes, &query, limits()).unwrap();
        packet.message.authorities = packet.message.answers.clone();
        packet.message.additionals = packet.message.answers.clone();
        assert_eq!(
            packet.age_response(case.elapsed).unwrap(),
            Duration::from_secs(u64::from(case.expected)),
            "{}",
            case.id
        );
        let encoded = packet.encode().unwrap();
        let decoded = Packet::response(&encoded, &query, limits()).unwrap();
        for section in [
            &decoded.message.answers,
            &decoded.message.authorities,
            &decoded.message.additionals,
        ] {
            assert_eq!(
                section.iter().map(|record| record.ttl).collect::<Vec<_>>(),
                [case.expected, 0, 0],
                "{}",
                case.id
            );
        }
        packet.age_response(Duration::MAX).unwrap();
        assert!(
            packet.message.answers.iter().all(|record| record.ttl == 0),
            "{}",
            case.id
        );
    }
}

#[test]
fn response_aging_preserves_edns_headers_and_rrsig_signed_data() {
    let query = Packet::request(&request_wire(), limits()).unwrap();
    let mut bytes = response_wire();
    bytes[2] |= 4; // Existing AA and AD claims are preserved, never synthesized.
    bytes[3] |= 0x20;
    answer(&mut bytes, 1, 30, &[192, 0, 2, 7]);
    // Synthetic RRSIG: type A, algorithm 8, three labels, original TTL 300,
    // expiration/inception/key tag zero, root signer and one signature byte.
    let mut signature = vec![0, 1, 8, 3];
    signature.extend_from_slice(&300_u32.to_be_bytes());
    signature.extend_from_slice(&[0; 10]);
    signature.extend_from_slice(&[0, 7]);
    answer(&mut bytes, 46, 30, &signature);
    bytes[11] = 1;
    bytes.extend_from_slice(&[0, 0, 41, 4, 208, 1, 0, 128, 0, 0, 0]);
    let mut packet = Packet::response(&bytes, &query, limits()).unwrap();
    let metadata = packet.message.metadata;
    let edns = packet.message.edns.clone();
    let signed_data = packet.message.answers[1].data.clone();
    packet
        .age_response(std::time::Duration::from_millis(250))
        .unwrap();
    let decoded = Packet::response(&packet.encode().unwrap(), &query, limits()).unwrap();
    assert_eq!(decoded.message.metadata, metadata);
    assert_eq!(decoded.message.edns, edns);
    assert_eq!(decoded.message.answers[1].data, signed_data);
    assert_eq!(decoded.message.answers[0].ttl, 29);
    assert_eq!(decoded.message.answers[1].ttl, 29);
}

#[test]
fn response_aging_refuses_queries_and_transaction_signatures_before_mutation() {
    use hickory_proto::rr::{
        DNSClass, Record,
        rdata::{TSIG, tsig::TsigAlgorithm},
    };
    use std::time::Duration;

    let mut query = Packet::request(&request_wire(), limits()).unwrap();
    assert!(matches!(
        query.age_response(Duration::ZERO),
        Err(Error::UnsupportedOperation)
    ));
    let mut bytes = response_wire();
    answer(&mut bytes, 1, 30, &[192, 0, 2, 7]);
    let mut packet = Packet::response(&bytes, &query, limits()).unwrap();
    let mut signature = Record::from_rdata(
        hickory_proto::rr::Name::from_ascii("sample-key.test.").unwrap(),
        0,
        TSIG::new(
            TsigAlgorithm::HmacSha256,
            0,
            300,
            vec![7; 32],
            query.id(),
            None,
            Vec::new(),
        ),
    );
    signature.dns_class = DNSClass::ANY;
    packet.message.signature = Some(Box::new(signature));
    let encoded = packet.encode().unwrap();
    assert!(matches!(
        packet.age_response(Duration::from_secs(1)),
        Err(Error::UnsupportedOperation)
    ));
    assert_eq!(packet.encode().unwrap(), encoded);
    let mut parsed = Packet::response(&encoded, &query, limits()).unwrap();
    assert!(matches!(
        parsed.age_response(Duration::from_secs(1)),
        Err(Error::UnsupportedOperation)
    ));
    assert_eq!(parsed.encode().unwrap(), encoded);

    // A SIG(0) transaction signature may remain an ordinary Additional RR.
    bytes[11] = 1;
    bytes.extend_from_slice(&[0xc0, 0x0c, 0, 24, 0, 255, 0, 0, 0, 0, 0, 20]);
    bytes.extend_from_slice(&[0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7]);
    let mut packet = Packet::response(&bytes, &query, limits()).unwrap();
    let encoded = packet.encode().unwrap();
    assert!(matches!(
        packet.age_response(Duration::from_secs(1)),
        Err(Error::UnsupportedOperation)
    ));
    assert_eq!(packet.encode().unwrap(), encoded);
}

#[test]
#[ignore = "controlled packet-processing workload; run explicitly in release mode"]
fn response_aging_workload() {
    let query = Packet::request(&request_wire(), limits()).unwrap();
    let mut bytes = response_wire();
    for last in 1..=4 {
        answer(&mut bytes, 1, 5, &[192, 0, 2, last]);
    }
    for aging in [false, true] {
        let mut latencies = Vec::with_capacity(5000);
        let mut encoded_bytes = 0;
        let whole = std::time::Instant::now();
        for _ in 0..5000 {
            let mut packet = Packet::response(&bytes, &query, limits()).unwrap();
            let start = std::time::Instant::now();
            if aging {
                packet
                    .age_response(std::time::Duration::from_millis(1250))
                    .unwrap();
            }
            let encoded = packet.encode().unwrap();
            latencies.push(start.elapsed().as_nanos());
            encoded_bytes += encoded.len();
            assert_eq!(packet.message.answers[0].ttl, if aging { 3 } else { 5 });
        }
        latencies.sort_unstable();
        println!(
            "response_aging aging={aging} iterations=5000 records=4 concurrency=1 encoded_bytes={encoded_bytes} whole_ns={} p50_ns={} p95_ns={} p99_ns={}; serialization latency includes optional aging, whole time includes decoding; no sockets or packet-drop measurement",
            whole.elapsed().as_nanos(),
            latencies[2499],
            latencies[4749],
            latencies[4949]
        );
    }
}

#[test]
fn response_correlation_checks_id_name_type_class_and_direction() {
    let request = Packet::request(&request_wire(), limits()).unwrap();
    struct Case {
        id: &'static str,
        offset: usize,
        value: u8,
    }
    let length = response_wire().len();
    for case in [
        Case {
            id: "id",
            offset: 0,
            value: 0,
        },
        Case {
            id: "name",
            offset: 13,
            value: b'x',
        },
        Case {
            id: "type",
            offset: length - 3,
            value: 28,
        },
        Case {
            id: "class",
            offset: length - 1,
            value: 3,
        },
        Case {
            id: "direction",
            offset: 2,
            value: 1,
        },
    ] {
        let mut wire = response_wire();
        wire[case.offset] = case.value;
        assert!(
            matches!(
                Packet::response(&wire, &request, limits()),
                Err(Error::MismatchedResponse)
            ),
            "{}",
            case.id
        );
    }
    let mut wire = response_wire();
    let start = wire
        .windows(7)
        .position(|bytes| bytes == b"ExAmPlE")
        .unwrap();
    wire[start..start + 7].copy_from_slice(b"example");
    assert!(Packet::response(&wire, &request, limits()).is_ok());
    let response = Packet::response(&response_wire(), &request, limits()).unwrap();
    assert!(matches!(
        Packet::response(&response_wire(), &response, limits()),
        Err(Error::MismatchedResponse)
    ));
}

#[test]
fn correlated_truncation_requests_retry_without_accepting_partial_records() {
    let request = Packet::request(&request_wire(), limits()).unwrap();
    let mut wire = response_wire();
    wire[2] |= 2;
    wire[7] = 1;
    wire.extend_from_slice(&[0xc0]);
    assert!(matches!(
        Packet::response(&wire, &request, limits()),
        Err(Error::Truncated)
    ));
    wire[0] = 0;
    assert!(matches!(
        Packet::response(&wire, &request, limits()),
        Err(Error::MismatchedResponse)
    ));
    let mut query = request_wire();
    query[2] |= 2;
    assert!(matches!(
        Packet::request(&query, limits()),
        Err(Error::Malformed)
    ));
}

#[test]
fn malformed_names_records_counts_and_trailing_bytes_are_rejected() {
    let request = Packet::request(&request_wire(), limits()).unwrap();
    let mut cyclic = request_wire()[..12].to_vec();
    cyclic.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
    assert!(matches!(
        Packet::request(&cyclic, limits()),
        Err(Error::Malformed)
    ));
    let mut trailing = request_wire();
    trailing.push(0);
    assert!(matches!(
        Packet::request(&trailing, limits()),
        Err(Error::Malformed)
    ));
    for count in [0_u16, 2, u16::MAX] {
        let mut wire = request_wire();
        wire[4..6].copy_from_slice(&count.to_be_bytes());
        assert!(matches!(
            Packet::request(&wire, limits()),
            Err(Error::Malformed)
        ));
    }
    for size in 0..12 {
        assert!(matches!(
            Packet::request(&request_wire()[..size], limits()),
            Err(Error::Malformed)
        ));
    }
    let mut wire = response_wire();
    answer(&mut wire, 1, 1, &[192, 0, 2]);
    assert!(matches!(
        Packet::response(&wire, &request, limits()),
        Err(Error::Malformed)
    ));
    let mut wire = response_wire();
    answer(&mut wire, 5, 1, &[0xc0, 0xff]);
    assert!(matches!(
        Packet::response(&wire, &request, limits()),
        Err(Error::Malformed)
    ));
    let mut wire = request_wire();
    wire[7] = 1;
    assert!(matches!(
        Packet::request(&wire, limits()),
        Err(Error::Malformed)
    ));
    let mut wire = request_wire();
    wire[9] = 1;
    assert!(matches!(
        Packet::request(&wire, limits()),
        Err(Error::Malformed)
    ));
    assert!(matches!(
        Packet::request(&response_wire(), limits()),
        Err(Error::Malformed)
    ));
    let mut wire = request_wire();
    wire[2] |= 0x28;
    assert!(matches!(
        Packet::request(&wire, limits()),
        Err(Error::UnsupportedOperation)
    ));
}

#[test]
fn count_and_byte_admission_precedes_record_decoding() {
    for (wire_bytes, records) in [(11, 1), (65536, 1), (512, 0), (512, 4097)] {
        assert!(matches!(
            Limits::new(wire_bytes, records),
            Err(Error::InvalidLimits)
        ));
    }
    let wire = request_wire();
    assert!(Packet::request(&wire, Limits::new(wire.len(), 1).unwrap()).is_ok());
    assert!(matches!(
        Packet::request(&wire, Limits::new(wire.len() - 1, 1).unwrap()),
        Err(Error::ResourceLimit)
    ));
    for offset in [6, 8, 10] {
        let mut wire = response_wire();
        wire[offset..offset + 2].copy_from_slice(&u16::MAX.to_be_bytes());
        let request = Packet::request(&request_wire(), limits()).unwrap();
        assert!(matches!(
            Packet::response(&wire, &request, limits()),
            Err(Error::ResourceLimit)
        ));
    }
}

#[test]
fn output_limits_fail_instead_of_silently_truncating_records() {
    let request = Packet::request(&request_wire(), limits()).unwrap();
    for size in [0, 11, 4097] {
        assert!(matches!(
            request.encode_limited(size),
            Err(Error::InvalidLimits)
        ));
    }
    assert!(matches!(
        request.encode_limited(12),
        Err(Error::ResourceLimit)
    ));
    let mut wire = response_wire();
    answer(&mut wire, 1, 0, &[192, 0, 2, 7]);
    let response = Packet::response(&wire, &request, limits()).unwrap();
    assert!(matches!(
        response.encode_limited(response_wire().len()),
        Err(Error::ResourceLimit)
    ));
    assert_eq!(response.message.answers.len(), 1);
    assert!(Packet::response(&response.encode().unwrap(), &request, limits()).is_ok());
}

#[test]
fn edns_and_service_binding_parameters_survive_the_adapter() {
    let mut query = request_wire();
    query[11] = 1;
    query.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
    let request = Packet::request(&query, limits()).unwrap();
    assert_eq!(request.message.edns.as_ref().unwrap().max_payload(), 1232);
    for kind in [64, 65] {
        let mut wire = response_wire();
        // ServiceMode, effective owner target, IPv4 hint and unknown parameter.
        answer(
            &mut wire,
            kind,
            5,
            &[0, 1, 0, 0, 4, 0, 4, 192, 0, 2, 7, 0, 123, 0, 2, 9, 8],
        );
        let response = Packet::response(&wire, &request, limits()).unwrap();
        let encoded = response.encode().unwrap();
        let decoded = Packet::response(&encoded, &request, limits()).unwrap();
        assert_eq!(decoded.message, response.message);
        assert_eq!(decoded.message.answers[0].record_type(), kind.into());
    }
    let mut wire = response_wire();
    // Parameters must be strictly ordered by key.
    answer(
        &mut wire,
        65,
        5,
        &[0, 1, 0, 0, 123, 0, 0, 0, 4, 0, 4, 192, 0, 2, 7],
    );
    assert!(matches!(
        Packet::response(&wire, &request, limits()),
        Err(Error::Malformed)
    ));
}

#[test]
fn dependency_queries_preserve_rd_cd_and_edns_without_asserting_answer_flags() {
    let mut bytes = request_wire();
    bytes[2] |= 4;
    bytes[3] = 0xb0;
    bytes[11] = 1;
    // OPT: 1232-byte advertised UDP payload, DO, empty option set.
    bytes.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0]);
    let request = Packet::request(&bytes, limits()).unwrap();
    let question = Question {
        name: Name::from_ascii("target.example.test").unwrap(),
        record_type: 28,
        class: 1,
    };
    let dependency = request.dependency(question).unwrap();
    let encoded = dependency.encode().unwrap();
    assert_eq!(dependency.id(), request.id());
    assert_eq!(dependency.question(), question);
    assert_eq!(encoded[2], 1, "only RD remains in the first flags octet");
    assert_eq!(
        encoded[3], 0x10,
        "CD is preserved without AA, AD or RA assertions"
    );
    assert_eq!(dependency.message.edns, request.message.edns);
    assert_eq!(request.encode().unwrap(), bytes);
    assert_eq!(
        Packet::request(&encoded, limits()).unwrap().question(),
        question
    );
}

#[test]
fn dependency_synthesis_refuses_response_additional_records_and_oversize_names() {
    let request = Packet::request(&request_wire(), limits()).unwrap();
    let response = Packet::response(&response_wire(), &request, limits()).unwrap();
    assert!(matches!(
        response.dependency(request.question()),
        Err(Error::UnsupportedOperation)
    ));
    let mut bytes = request_wire();
    bytes[11] = 1;
    bytes.extend_from_slice(&[0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 0, 0, 2, 1, b'x']);
    let request = Packet::request(&bytes, limits()).unwrap();
    assert!(matches!(
        request.dependency(request.question()),
        Err(Error::UnsupportedOperation)
    ));
    let bytes = request_wire();
    let request = Packet::request(&bytes, Limits::new(bytes.len(), 1).unwrap()).unwrap();
    let question = Question {
        name: Name::from_ascii("longer-dependency-name.example.test").unwrap(),
        ..request.question()
    };
    assert!(matches!(
        request.dependency(question),
        Err(Error::ResourceLimit)
    ));
}

#[test]
fn dependency_synthesis_refuses_a_transaction_signature() {
    use hickory_proto::rr::{
        DNSClass, Record,
        rdata::{TSIG, tsig::TsigAlgorithm},
    };
    let mut request = Packet::request(&request_wire(), limits()).unwrap();
    let signature = TSIG::new(
        TsigAlgorithm::HmacSha256,
        0,
        300,
        vec![7; 32],
        request.id(),
        None,
        Vec::new(),
    );
    let mut record = Record::from_rdata(
        hickory_proto::rr::Name::from_ascii("sample-key.test.").unwrap(),
        0,
        signature,
    );
    record.dns_class = DNSClass::ANY;
    request.message.signature = Some(Box::new(record));
    assert!(matches!(
        request.dependency(request.question()),
        Err(Error::UnsupportedOperation)
    ));
    let encoded = request.encode().unwrap();
    let parsed = Packet::request(&encoded, limits()).unwrap();
    // With std-only Hickory, TSIG remains an Additional record. Either
    // representation must prevent copying a MAC onto a changed question.
    assert!(parsed.message.signature.is_some() || !parsed.message.additionals.is_empty());
    assert!(matches!(
        parsed.dependency(parsed.question()),
        Err(Error::UnsupportedOperation)
    ));
}
