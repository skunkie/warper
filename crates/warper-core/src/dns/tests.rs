// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;

#[test]
fn names_fold_ascii_case_and_preserve_wire_label_octets() {
    let name = Name::from_labels([b"_SeRvIcE".as_slice(), b"_TCP", b"ExAmPlE", b"test"]).unwrap();
    assert_eq!(
        name,
        Name::from_ascii("_service._tcp.EXAMPLE.test.").unwrap()
    );
    assert!(name.is_within(&Name::from_ascii("example.test").unwrap()));
    assert_eq!(name.wire(), b"\x08_service\x04_tcp\x07example\x04test\0");
    let binary = Name::from_labels([b"\xff.A\0".as_slice(), b"TEST"]).unwrap();
    assert_eq!(binary.wire(), b"\x04\xff.a\0\x04test\0");
    assert_eq!(format!("{name:?}"), "Name([redacted])");
    assert!(Name::from_ascii(".").unwrap().is_root());
    assert!(Name::from_labels(std::iter::empty()).unwrap().is_root());
}

#[test]
fn names_enforce_label_and_total_wire_lengths() {
    let label = [b'a'; 63];
    let final_label = [b'b'; 61];
    let maximum = Name::from_labels([label.as_slice(), &label, &label, &final_label]).unwrap();
    assert_eq!(maximum.wire().len(), 255);
    assert!(matches!(
        Name::from_labels([label.as_slice(), &label, &label, &[b'b'; 62]]),
        Err(Error::InvalidName)
    ));
    for value in ["", "..", "test..", "a..test", "é.test"] {
        assert!(
            matches!(Name::from_ascii(value), Err(Error::InvalidName)),
            "{value}"
        );
    }
    assert!(matches!(
        Name::from_labels([b"".as_slice()]),
        Err(Error::InvalidName)
    ));
    assert!(matches!(
        Name::from_labels([&[b'a'; 64][..]]),
        Err(Error::InvalidName)
    ));
    let presentation = format!(
        "{}.{}.{}.{}.",
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(63),
        "b".repeat(61)
    );
    assert_eq!(Name::from_ascii(&presentation).unwrap(), maximum);
    assert!(matches!(
        Name::from_ascii(&"a".repeat(255)),
        Err(Error::InvalidName)
    ));
}

#[test]
fn longest_domain_wins_at_label_boundaries_in_any_input_order() {
    let rules = [
        Rule::new("test", BackendId(1)).unwrap(),
        Rule::new("example.test", BackendId(2)).unwrap(),
        Rule::new("private.example.test", BackendId(3)).unwrap(),
        Rule::new("xn--bcher-kva.test", BackendId(4)).unwrap(),
    ];
    for rules in [rules.to_vec(), rules.into_iter().rev().collect()] {
        let policy = Policy::new(&rules, 4).unwrap();
        for (sample, expected) in [
            ("test", Some(1)),
            ("example.test", Some(2)),
            ("_service._tcp.EXAMPLE.test.", Some(2)),
            ("a.private.example.test", Some(3)),
            ("notexample.test", Some(1)),
            ("example.test.invalid", None),
            ("xn--bcher-kva.test", Some(4)),
            (".", None),
        ] {
            assert_eq!(
                policy.select(&Name::from_ascii(sample).unwrap()),
                expected.map(BackendId),
                "{sample}"
            );
        }
        let embedded_dot = Name::from_labels([b"not.example".as_slice(), b"test"]).unwrap();
        assert_eq!(policy.select(&embedded_dot), Some(BackendId(1)));
    }
    assert_eq!(
        Policy::new(&[], 1)
            .unwrap()
            .select(&Name::from_ascii("test").unwrap()),
        None
    );
}

#[test]
fn noncanonical_configuration_rules_are_rejected() {
    for domain in [
        "",
        ".",
        "TEST",
        "test.",
        "a..test",
        "_tcp.test",
        "*.test",
        "-a.test",
        "a-.test",
        "é.test",
        "192.0.2.1",
        "::1",
    ] {
        assert!(
            matches!(Rule::new(domain, BackendId(1)), Err(Error::InvalidDomain)),
            "{domain}"
        );
    }
    assert!(matches!(
        Rule::new(&"a".repeat(64), BackendId(1)),
        Err(Error::InvalidDomain)
    ));
}

#[test]
fn rule_admission_bounds_storage_and_rejects_duplicate_assignments() {
    let rule = Rule::new("example.test", BackendId(1)).unwrap();
    assert!(matches!(Policy::new(&[], 0), Err(Error::InvalidLimit)));
    assert!(matches!(
        Policy::new(&[rule; 2], 1),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        Policy::new(&[rule; 2], 2),
        Err(Error::DuplicateAssignment)
    ));
    let other = Rule::new("example.test", BackendId(2)).unwrap();
    assert!(matches!(
        Policy::new(&[rule, other], 2),
        Err(Error::ConflictingAssignment)
    ));
}
