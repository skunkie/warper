// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;

fn sample() -> RecordedOwner {
    RecordedOwner {
        boot: [1; 16],
        network: NamespaceId {
            device: 4,
            inode: 101,
        },
        pid_namespace: NamespaceId {
            device: 4,
            inode: 102,
        },
        instance: [2; 16],
        process: Process {
            pid: 123,
            start_ticks: 0,
        },
    }
}

#[test]
fn recorded_owner_round_trip_preserves_zero_start_ticks_without_native_authority() {
    let sample = sample();
    assert_eq!(RecordedOwner::decode(&sample.encode()), Ok(sample));
    assert_eq!(format!("{sample:?}"), "RecordedOwner(<redacted>)");
    let encoded = sample.encode();
    for end in 0..RECORD_LEN {
        assert_eq!(
            RecordedOwner::decode(&encoded[..end]),
            Err(Error::InvalidRecord)
        );
    }
    let mut extra = encoded.to_vec();
    extra.push(0);
    assert_eq!(RecordedOwner::decode(&extra), Err(Error::InvalidRecord));
    for (start, end) in [
        (0, 4),
        (4, 8),
        (8, 24),
        (32, 40),
        (48, 56),
        (56, 72),
        (72, 76),
    ] {
        let mut changed = encoded;
        changed[start..end].fill(0);
        assert_eq!(RecordedOwner::decode(&changed), Err(Error::InvalidRecord));
    }
    let mut changed = encoded;
    changed[84] = 1;
    assert_eq!(RecordedOwner::decode(&changed), Err(Error::InvalidRecord));
    let mut changed = encoded;
    changed[72..76].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(RecordedOwner::decode(&changed), Err(Error::InvalidRecord));
}

#[test]
fn prior_instances_and_foreign_scopes_never_become_current_owners() {
    let current = sample();
    assert_eq!(classify(&current, &current), Classification::Current);
    let mut old = current;
    old.instance[0] = 3;
    assert_eq!(classify(&current, &old), Classification::PreviousInstance);
    old = current;
    old.boot[0] = 3;
    assert_eq!(classify(&current, &old), Classification::ForeignBoot);
    old = current;
    old.network.inode += 1;
    assert_eq!(classify(&current, &old), Classification::ForeignNamespace);
    old = current;
    old.pid_namespace.inode += 1;
    assert_eq!(classify(&current, &old), Classification::ForeignNamespace);
    old = current;
    old.process.pid += 1;
    assert_eq!(classify(&current, &old), Classification::ConflictingOwner);
    old = current;
    old.process.start_ticks += 1;
    assert_eq!(classify(&current, &old), Classification::ConflictingOwner);
}

#[test]
fn stat_parser_handles_parentheses_spaces_and_non_ascii_process_names() {
    for name in [
        b"invented worker".as_slice(),
        b"invented ) ( worker",
        b"invented-\xff-worker",
    ] {
        for ticks in [0, 1, u64::MAX] {
            let mut bytes = b"123 (".to_vec();
            bytes.extend_from_slice(name);
            bytes.extend_from_slice(b") S ");
            for _ in 0..18 {
                bytes.extend_from_slice(b"0 ");
            }
            bytes.extend_from_slice(ticks.to_string().as_bytes());
            bytes.extend_from_slice(b" 0 0\n");
            assert!(parse_stat(&bytes, 123).is_ok_and(|process| process.start_ticks == ticks));
            assert!(matches!(
                parse_stat(&bytes, 124),
                Err(Error::InvalidEvidence)
            ));
        }
    }
    for bytes in [
        b"".as_slice(),
        b"123 worker",
        b"123 (worker)S 1",
        b"123 (worker) S 1",
    ] {
        assert!(matches!(
            parse_stat(bytes, 123),
            Err(Error::InvalidEvidence)
        ));
    }
}

#[test]
fn namespace_labels_and_numeric_fields_are_canonical_and_bounded() {
    assert_eq!(parse_namespace(b"net:[123]", "net"), Ok(123));
    for label in [
        b"net:[0]".as_slice(),
        b"net:[0123]",
        b"pid:[123]",
        b"net:[18446744073709551616]",
        b"net:[123]\n",
        b"net:[-1]",
    ] {
        assert_eq!(parse_namespace(label, "net"), Err(Error::InvalidEvidence));
    }
    assert_eq!(parse_namespace(b"pid:[123]", "pid"), Ok(123));
    assert_eq!(
        parse_namespace(b"pid:[123]", "user"),
        Err(Error::InvalidEvidence)
    );
    for bytes in [b"".as_slice(), b"1x", b"18446744073709551616"] {
        assert_eq!(decimal(bytes), Err(Error::InvalidEvidence));
    }
}

#[test]
fn native_scope_pins_match_repeated_current_process_observations() {
    let a = inspect_scope().unwrap();
    let b = inspect_scope().unwrap();
    assert_eq!(a.network.id, b.network.id);
    assert_eq!(a.pid.id, b.pid.id);
    assert_eq!(a.process, b.process);
    assert_eq!(a.process.pid, std::process::id());
    assert_ne!(a.network.id.inode, 0);
    assert_ne!(a.pid.id.inode, 0);
    let file = std::fs::File::open(".").unwrap();
    let fd: OwnedFd = file.into();
    assert!(namespace(&fd, "net").is_err());
}
