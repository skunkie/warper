// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;

#[test]
fn failure_envelope_is_bounded_and_contains_no_source_or_secret_text() {
    let encoded = encode(Err(Error::Credential));
    assert_eq!(encoded.expose(), b"WMIM\0\x01\0\x03\0\0\0\0");
    assert!(matches!(decode(encoded.expose()), Err(Error::Credential)));
    for end in 0..HEADER {
        assert!(decode(&encoded.expose()[..end]).is_err());
    }
    let mut changed = encoded.expose().to_vec();
    changed[6] = 1;
    assert!(matches!(decode(&changed), Err(Error::UnsafeChild)));
    let mut changed = encoded.expose().to_vec();
    changed[11] = 1;
    changed.push(0);
    assert!(matches!(decode(&changed), Err(Error::UnsafeChild)));
    assert!(matches!(
        decode(&vec![0; MAX + HEADER + 1]),
        Err(Error::TooLarge)
    ));
}
#[test]
fn successful_materialization_round_trips_a_valid_managed_snapshot() {
    use warper_core::configuration::paths::{Account, Paths};
    let paths = Paths::new(
        &Account {
            uid: 1000,
            name: "sample".into(),
            home: "/sample".into(),
        },
        Path::new("/sample"),
        None,
    )
    .unwrap();
    let encoded = Snapshot::import(b"tunnel: {ip: 198.18.0.1}\nprotocols: [{socks5: {host: '127.0.0.1:1080', ips: [198.18.0.2/32]}}]", &paths, Platform::Linux).unwrap().encode().unwrap();
    let expected = encoded.expose().to_vec();
    let response = encode(Ok(encoded));
    assert_eq!(decode(response.expose()).unwrap().expose(), &expected);
    let mut corrupt = response.expose().to_vec();
    corrupt[HEADER] = 0;
    assert!(matches!(decode(&corrupt), Err(Error::Schema)));
}

#[test]
fn identity_mismatch_rejects_before_source_path_resolution_or_file_reads() {
    let different = getuid().as_raw().checked_add(1).unwrap();
    assert!(matches!(
        import(different, getgid().as_raw(), &[]),
        Err(Error::UnsafeChild)
    ));
    assert_eq!(
        format!("{:?}", encode(Err(Error::Schema))),
        "ImportEnvelope(<redacted>)"
    );
}
