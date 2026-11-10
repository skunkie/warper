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
fn local_replies_preserve_correlation_without_exposing_records_or_authority() {
    struct Case {
        id: &'static str,
        reply: LocalReply,
        expected_code: u16,
        expected_tc: bool,
    }
    for case in [
        Case {
            id: "failure",
            reply: LocalReply::ServFail,
            expected_code: 2,
            expected_tc: false,
        },
        Case {
            id: "tcp_retry",
            reply: LocalReply::Truncated,
            expected_code: 0,
            expected_tc: true,
        },
        Case {
            id: "disabled_ipv6",
            reply: LocalReply::DisabledIpv6,
            expected_code: 0,
            expected_tc: false,
        },
    ] {
        let mut bytes = request_wire();
        let question_end = bytes.len();
        bytes[question_end - 3] = 28;
        // Input assertions of AA/AD/RA must not survive synthesis.
        bytes[2] |= 4;
        bytes[3] = 0xb0;
        let request = Packet::request(&bytes, limits()).unwrap();
        let wire = request.local_reply(case.reply).unwrap();
        let mut decoder = BinDecoder::new(&wire);
        let message = Message::read(&mut decoder).unwrap();
        assert_eq!(decoder.index(), wire.len(), "{}", case.id);
        assert_eq!(message.id, request.id(), "{}", case.id);
        assert_eq!(
            u16::from(message.response_code),
            case.expected_code,
            "{}",
            case.id
        );
        assert_eq!(message.truncation, case.expected_tc, "{}", case.id);
        assert_eq!(wire[2] & !2, 0x81, "{}", case.id);
        assert_eq!(wire[3] & 0xf0, 0x90, "{}", case.id);
        assert_eq!(&wire[12..], &bytes[12..], "{}", case.id);
        assert!(
            message.answers.is_empty()
                && message.authorities.is_empty()
                && message.additionals.is_empty(),
            "{}",
            case.id
        );
        assert!(message.edns.is_none(), "{}", case.id);
        assert_eq!(request.encode().unwrap(), bytes, "{}", case.id);
    }
}

#[test]
fn local_edns_replies_negotiate_capacity_and_reject_unsupported_versions() {
    for capacity in [1_u16, 512, 1232, u16::MAX] {
        for version in [0, 1, 255] {
            let mut bytes = request_wire();
            bytes[11] = 1;
            bytes.extend_from_slice(&[0, 0, 41]);
            bytes.extend_from_slice(&capacity.to_be_bytes());
            // DO plus reserved flags and an unknown option with four bytes.
            bytes.extend_from_slice(&[0, version, 0x80, 1, 0, 8, 0xfd, 0xe8, 0, 4, 1, 2, 3, 4]);
            let request = Packet::request(&bytes, limits()).unwrap();
            assert_eq!(
                request.udp_payload_limit(),
                usize::from(capacity).clamp(512, 1232)
            );
            for reply in [LocalReply::ServFail, LocalReply::Truncated] {
                let wire = request.local_reply(reply).unwrap();
                assert!(wire.len() <= request.udp_payload_limit());
                let mut decoder = BinDecoder::new(&wire);
                let message = Message::read(&mut decoder).unwrap();
                let edns = message.edns.as_ref().unwrap();
                assert_eq!(edns.version(), 0);
                assert_eq!(edns.max_payload(), 1232);
                assert!(edns.flags().dnssec_ok);
                assert_eq!(edns.flags().z, 0);
                assert!(edns.options().as_ref().is_empty());
                assert_eq!(
                    u16::from(message.response_code),
                    if version != 0 {
                        16
                    } else if reply == LocalReply::ServFail {
                        2
                    } else {
                        0
                    }
                );
                assert_eq!(
                    message.truncation,
                    version == 0 && reply == LocalReply::Truncated
                );
            }
        }
    }
}

#[test]
fn local_reply_rejects_wrong_family_responses_and_unrelated_additional_data() {
    let request = Packet::request(&request_wire(), limits()).unwrap();
    assert!(matches!(
        request.local_reply(LocalReply::DisabledIpv6),
        Err(Error::UnsupportedOperation)
    ));
    let response = Packet::response(&response_wire(), &request, limits()).unwrap();
    assert!(matches!(
        response.local_reply(LocalReply::ServFail),
        Err(Error::UnsupportedOperation)
    ));
    let mut bytes = request_wire();
    bytes[11] = 1;
    bytes.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 192, 0, 2, 1]);
    let request = Packet::request(&bytes, limits()).unwrap();
    assert!(matches!(
        request.local_reply(LocalReply::ServFail),
        Err(Error::UnsupportedOperation)
    ));

    let bytes = request_wire();
    let request = Packet::request(&bytes, Limits::new(bytes.len(), 1).unwrap()).unwrap();
    assert_eq!(request.udp_payload_limit(), bytes.len());
    assert!(request.local_reply(LocalReply::ServFail).is_ok());
}

#[test]
fn local_reply_does_not_invent_request_flags_or_edns_capacity() {
    let mut bytes = request_wire();
    bytes[2] = 0;
    bytes[11] = 1;
    bytes.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
    let request = Packet::request(&bytes, Limits::new(512, 16).unwrap()).unwrap();
    let wire = request.local_reply(LocalReply::ServFail).unwrap();
    let mut decoder = BinDecoder::new(&wire);
    let message = Message::read(&mut decoder).unwrap();
    assert!(!message.recursion_desired && !message.checking_disabled);
    assert!(message.recursion_available);
    let edns = message.edns.as_ref().unwrap();
    assert!(!edns.flags().dnssec_ok);
    assert_eq!(edns.max_payload(), 512);
    assert_eq!(request.udp_payload_limit(), 512);

    let mut bytes = request_wire();
    let end = bytes.len();
    bytes[end - 3] = 28;
    bytes[end - 1] = 3;
    let request = Packet::request(&bytes, limits()).unwrap();
    assert!(matches!(
        request.local_reply(LocalReply::DisabledIpv6),
        Err(Error::UnsupportedOperation)
    ));
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
    assert!(matches!(
        request.local_reply(LocalReply::ServFail),
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
        request.local_reply(LocalReply::ServFail),
        Err(Error::UnsupportedOperation)
    ));
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
    assert!(matches!(
        parsed.local_reply(LocalReply::ServFail),
        Err(Error::UnsupportedOperation)
    ));
}

#[test]
fn decoded_reservations_follow_dependencies_responses_and_shared_packet_ownership() {
    let budget = crate::dns::memory::Budget::new(4 * 1024 * 1024).unwrap();
    let request = Packet::request_with_budget(&request_wire(), limits(), &budget).unwrap();
    let query_bytes = budget.used();
    assert!(query_bytes > request_wire().len());
    let dependency = request
        .dependency(Question {
            name: Name::from_ascii("dependency.example.test").unwrap(),
            ..request.question()
        })
        .unwrap();
    assert_eq!(budget.used(), 2 * query_bytes);
    drop(dependency);
    assert_eq!(budget.used(), query_bytes);
    let wire = request.local_reply(LocalReply::ServFail).unwrap();
    assert_eq!(budget.used(), query_bytes);
    assert_eq!(
        Packet::response(&wire, &request, limits())
            .unwrap()
            .response_code(),
        2
    );
    assert_eq!(budget.used(), query_bytes);
    let mut wire = response_wire();
    answer(&mut wire, 1, 0, &[192, 0, 2, 7]);
    let response = std::sync::Arc::new(Packet::response(&wire, &request, limits()).unwrap());
    let retained = budget.used();
    let shared = response.clone();
    drop(response);
    assert_eq!(budget.used(), retained);
    drop(shared);
    assert_eq!(budget.used(), query_bytes);
    drop(request);
    assert_eq!(budget.used(), 0);
}

#[test]
fn decoded_storage_shortages_and_failed_decode_preserve_existing_owners() {
    let budget = crate::dns::memory::Budget::new(4 * 1024 * 1024).unwrap();
    let request = Packet::request_with_budget(&request_wire(), limits(), &budget).unwrap();
    let used = budget.used();
    let short = crate::dns::memory::Budget::new(used - 1).unwrap();
    assert!(matches!(
        Packet::request_with_budget(&request_wire(), limits(), &short),
        Err(Error::ResourceLimit)
    ));
    assert_eq!(short.used(), 0);
    let competing = budget.reserve(budget.limit() - used).unwrap();
    assert!(matches!(
        request.dependency(request.question()),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        request.local_reply(LocalReply::ServFail),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        Packet::response(&response_wire(), &request, limits()),
        Err(Error::ResourceLimit)
    ));
    assert_eq!(budget.used(), budget.limit());
    drop(competing);
    let mut wire = response_wire();
    let owner = wire.len();
    answer(&mut wire, 1, 0, &[192, 0, 2, 7]);
    wire[owner + 1] = 255;
    assert!(matches!(
        Packet::response(&wire, &request, limits()),
        Err(Error::Malformed)
    ));
    assert_eq!(budget.used(), used);
    let mut mismatch = response_wire();
    mismatch[0] ^= 1;
    assert!(matches!(
        Packet::response(&mismatch, &request, limits()),
        Err(Error::MismatchedResponse)
    ));
    assert_eq!(budget.used(), used);
    for end in 0..request_wire().len() {
        assert!(
            Packet::request_with_budget(&request_wire()[..end], limits(), &budget).is_err(),
            "prefix {end}"
        );
        assert_eq!(budget.used(), used, "prefix {end}");
    }
    drop(request);
    assert_eq!(budget.used(), 0);
}

#[test]
fn budgeted_truncated_responses_correlate_before_inspecting_cut_record_data() {
    let budget = crate::dns::memory::Budget::new(1_048_576).unwrap();
    let request = Packet::request_with_budget(&request_wire(), limits(), &budget).unwrap();
    let used = budget.used();
    let mut wire = response_wire();
    answer(&mut wire, 1, 0, &[192, 0, 2, 7]);
    wire[2] |= 2;
    wire.pop();
    assert!(matches!(
        Packet::response(&wire, &request, limits()),
        Err(Error::Truncated)
    ));
    assert_eq!(budget.used(), used);
    wire[0] ^= 1;
    assert!(matches!(
        Packet::response(&wire, &request, limits()),
        Err(Error::MismatchedResponse)
    ));
    assert_eq!(budget.used(), used);
    drop(request);
    assert_eq!(budget.used(), 0);
}

#[test]
fn bitmap_expansion_is_reserved_before_decoding_and_released_on_error() {
    let budget = crate::dns::memory::Budget::new(4 * 1024 * 1024).unwrap();
    let request = Packet::request_with_budget(&request_wire(), limits(), &budget).unwrap();
    let used = budget.used();
    let mut sparse = response_wire();
    answer(&mut sparse, 62, 0, &[0, 0, 0, 0, 0, 0, 0, 1, 2]);
    let packet = Packet::response(&sparse, &request, limits()).unwrap();
    let sparse_bytes = budget.used() - used;
    drop(packet);
    let mut dense = sparse.clone();
    *dense.last_mut().unwrap() = 255;
    let packet = Packet::response(&dense, &request, limits()).unwrap();
    assert!(budget.used() - used > sparse_bytes);
    drop(packet);
    let length = dense.len();
    dense[length - 2] = 0;
    assert!(matches!(
        Packet::response(&dense, &request, limits()),
        Err(Error::Malformed)
    ));
    assert_eq!(budget.used(), used);
    drop(request);
    assert_eq!(budget.used(), 0);
}

#[test]
fn full_size_edns_requests_and_dependency_clones_fit_the_default_shared_budget() {
    let mut wire = request_wire();
    wire[11] = 1;
    let data = 65_535 - wire.len() - 11;
    wire.extend_from_slice(&[0, 0, 41, 16, 0, 0, 0, 0, 0]);
    wire.extend_from_slice(&(data as u16).to_be_bytes());
    wire.extend_from_slice(&12_u16.to_be_bytes());
    wire.extend_from_slice(&((data - 4) as u16).to_be_bytes());
    wire.resize(65_535, 0);
    let limits = Limits::new(65_535, 4096).unwrap();
    let budget = crate::dns::memory::Budget::new(64 * 1024 * 1024).unwrap();
    let packet = Packet::request_with_budget(&wire, limits, &budget).unwrap();
    let dependency = packet.dependency(packet.question()).unwrap();
    assert_eq!(dependency.encode().unwrap().len(), 65_535);
    assert!(budget.used() < budget.limit());
    drop(dependency);
    drop(packet);
    assert_eq!(budget.used(), 0);
}

#[test]
fn compressed_maximum_length_names_reserve_decoded_storage_before_release() {
    let budget = crate::dns::memory::Budget::new(1_048_576).unwrap();
    let mut wire = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for length in [63, 63, 63, 61] {
        wire.push(length);
        wire.extend(std::iter::repeat_n(b'a', usize::from(length)));
    }
    wire.extend_from_slice(&[0, 0, 1, 0, 1]);
    let request = Packet::request_with_budget(&wire, limits(), &budget).unwrap();
    let query_storage = budget.used();
    assert_eq!(request.question().name.wire().len(), 255);
    wire[2..4].copy_from_slice(&[0x81, 0x80]);
    for _ in 0..8 {
        answer(&mut wire, 5, 0, &[0xc0, 0x0c]);
    }
    let response = Packet::response(&wire, &request, limits()).unwrap();
    let response_storage = budget.used() - query_storage;
    assert!(response_storage > wire.len());
    assert_eq!(response.encode().unwrap(), wire);
    drop(response);
    let competing = budget
        .reserve(budget.limit() - query_storage - response_storage + 1)
        .unwrap();
    assert!(matches!(
        Packet::response(&wire, &request, limits()),
        Err(Error::ResourceLimit)
    ));
    drop(competing);
    assert_eq!(budget.used(), query_storage);
    drop(request);
    assert_eq!(budget.used(), 0);
}

#[test]
fn malformed_storage_envelopes_leave_existing_reservations_unchanged() {
    let budget = crate::dns::memory::Budget::new(1_048_576).unwrap();
    let request = Packet::request_with_budget(&request_wire(), limits(), &budget).unwrap();
    let used = budget.used();
    let mut name_code = request_wire();
    name_code[12] = 64;
    let mut trailing = request_wire();
    trailing.push(0);
    let mut bitmap_header = response_wire();
    answer(&mut bitmap_header, 62, 0, &[0, 0, 0, 0, 0, 0, 0]);
    struct Case {
        id: &'static str,
        input: Vec<u8>,
        is_response: bool,
    }
    for case in [
        Case {
            id: "reserved name code",
            input: name_code,
            is_response: false,
        },
        Case {
            id: "trailing data",
            input: trailing,
            is_response: false,
        },
        Case {
            id: "cut bitmap header",
            input: bitmap_header,
            is_response: true,
        },
    ] {
        let result = if case.is_response {
            Packet::response(&case.input, &request, limits())
        } else {
            Packet::request_with_budget(&case.input, limits(), &budget)
        };
        assert!(matches!(result, Err(Error::Malformed)), "{}", case.id);
        assert_eq!(budget.used(), used, "{}", case.id);
    }
    drop(request);
    assert_eq!(budget.used(), 0);
}
