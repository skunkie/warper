// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use crate::runtime::{
    enrollment::tests::{record_path, store, write_record},
    tests::Fixture,
};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

fn pending(fixture: &Fixture, bytes: &[u8]) -> std::path::PathBuf {
    let path = fixture.path.join("var/lib/warper/owner.pending");
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path
}
#[test]
fn explicit_discard_preserves_committed_policy_for_empty_partial_and_complete_intent() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut store = store(&fixture);
    let committed = store.replace(&lease, 0, Some(1234)).unwrap();
    assert!(store.inspect().unwrap().is_none());
    for length in [0, 7, 24] {
        let proposal = encode(Enrollment {
            owner: Some(4321),
            revision: 2,
        });
        let path = pending(&fixture, &proposal[..length]);
        let inspection = store.inspect().unwrap().unwrap();
        assert_eq!(inspection.pending_len(), length);
        assert_eq!(inspection.committed(), committed);
        assert_eq!(format!("{inspection:?}"), "PendingInspection(<redacted>)");
        assert_eq!(store.read(&lease), Err(Error::RecoveryRequired));
        assert_eq!(
            store.discard(&lease, inspection, OwnerStore::sync),
            Ok(committed)
        );
        assert!(!path.exists());
        assert_eq!(store.read(&lease), Ok(committed));
    }
    assert_eq!(store.replace(&lease, 1, None).unwrap().revision(), 2);
}
#[test]
fn abandonment_and_changed_pending_bytes_identity_or_mode_preserve_recovery_state() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let store = store(&fixture);
    let path = pending(&fixture, b"initial");
    drop(store.inspect().unwrap().unwrap());
    assert_eq!(fs::read(&path).unwrap(), b"initial");
    let inspection = store.inspect().unwrap().unwrap();
    fs::write(&path, b"changed").unwrap();
    assert_eq!(
        store.discard(&lease, inspection, OwnerStore::sync),
        Err(Error::UnsafeState)
    );
    assert_eq!(fs::read(&path).unwrap(), b"changed");
    let inspection = store.inspect().unwrap().unwrap();
    fs::rename(&path, fixture.path.join("old-intent")).unwrap();
    pending(&fixture, b"new one");
    assert_eq!(
        store.discard(&lease, inspection, OwnerStore::sync),
        Err(Error::UnsafeState)
    );
    assert_eq!(fs::read(&path).unwrap(), b"new one");
    let inspection = store.inspect().unwrap().unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        store.discard(&lease, inspection, OwnerStore::sync),
        Err(Error::UnsafeState)
    );
    assert!(path.exists());
}
#[test]
fn changed_committed_revision_and_replaced_same_content_owner_prevent_discard() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut store = store(&fixture);
    store.replace(&lease, 0, Some(1234)).unwrap();
    let path = pending(&fixture, b"partial");
    let inspection = store.inspect().unwrap().unwrap();
    write_record(
        &fixture,
        &encode(Enrollment {
            owner: Some(4321),
            revision: 2,
        }),
    );
    assert_eq!(
        store.discard(&lease, inspection, OwnerStore::sync),
        Err(Error::RevisionConflict)
    );
    assert!(path.exists());
    let inspection = store.inspect().unwrap().unwrap();
    fs::rename(record_path(&fixture), fixture.path.join("old-owner")).unwrap();
    write_record(
        &fixture,
        &encode(Enrollment {
            owner: Some(4321),
            revision: 2,
        }),
    );
    assert_eq!(
        store.discard(&lease, inspection, OwnerStore::sync),
        Err(Error::UnsafeState)
    );
    assert!(path.exists());
}
#[test]
fn oversized_linked_symlink_and_nonregular_pending_records_are_never_removed() {
    let fixture = Fixture::new();
    let _lease = fixture.acquire().unwrap();
    let store = store(&fixture);
    let path = pending(&fixture, &[0; 25]);
    assert!(matches!(store.inspect(), Err(Error::UnsafeState)));
    assert!(path.exists());
    fs::remove_file(&path).unwrap();
    pending(&fixture, b"partial");
    fs::hard_link(&path, fixture.path.join("alias")).unwrap();
    assert!(matches!(store.inspect(), Err(Error::UnsafeState)));
    fs::remove_file(&path).unwrap();
    symlink(fixture.path.join("alias"), &path).unwrap();
    assert!(store.inspect().is_err());
    assert!(fs::symlink_metadata(&path).unwrap().is_symlink());
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(matches!(store.inspect(), Err(Error::UnsafeState)));
    assert!(path.is_dir());
}
#[test]
fn native_denial_precedes_any_recovery_record_inspection_or_mutation() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut store = store(&fixture);
    let path = pending(&fixture, b"partial");
    let inspection = store.inspect().unwrap().unwrap();
    let (peer, _client) = UnixStream::pair().unwrap();
    if fixture.owner != 0 {
        write_record(&fixture, b"invalid");
        assert!(matches!(
            store.inspect_pending(&lease, &peer),
            Err(Error::Peer(crate::Error::PermissionDenied))
        ));
        assert_eq!(
            store.discard_pending(&lease, &peer, inspection),
            Err(Error::Peer(crate::Error::PermissionDenied))
        );
        assert_eq!(fs::read(&path).unwrap(), b"partial");
    } else {
        drop(inspection);
        let inspection = store.inspect_pending(&lease, &peer).unwrap().unwrap();
        assert_eq!(
            store
                .discard_pending(&lease, &peer, inspection)
                .unwrap()
                .revision(),
            0
        );
    }
}
#[test]
fn post_unlink_sync_uncertainty_preserves_owner_and_requires_fresh_inspection() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut store = store(&fixture);
    let committed = store.replace(&lease, 0, Some(1234)).unwrap();
    pending(&fixture, b"partial");
    let inspection = store.inspect().unwrap().unwrap();
    assert_eq!(
        store.discard(&lease, inspection, |_| Err(Error::Io(io::ErrorKind::Other))),
        Err(Error::CommitUncertain(io::ErrorKind::Other))
    );
    assert!(store.inspect().unwrap().is_none());
    assert_eq!(store.read(&lease), Ok(committed));
}
#[test]
fn changed_runtime_ownership_prevents_recovery_mutation() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let store = store(&fixture);
    let path = pending(&fixture, b"partial");
    let inspection = store.inspect().unwrap().unwrap();
    fs::rename(fixture.lock_path(), fixture.path.join("old-lock")).unwrap();
    fs::write(fixture.lock_path(), b"").unwrap();
    fs::set_permissions(fixture.lock_path(), fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        store.discard(&lease, inspection, OwnerStore::sync),
        Err(Error::Runtime(crate::runtime::Error::UnsafeState))
    ));
    assert_eq!(fs::read(path).unwrap(), b"partial");
}
