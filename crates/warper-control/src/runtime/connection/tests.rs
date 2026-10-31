// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use crate::runtime::tests::Fixture;
use rustix::fs::open;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

fn store(fixture: &Fixture) -> ConnectionStore {
    fs::create_dir_all(fixture.path.join("var/lib/warper")).unwrap();
    for (name, mode) in [
        ("var", 0o755),
        ("var/lib", 0o755),
        ("var/lib/warper", 0o700),
    ] {
        fs::set_permissions(fixture.path.join(name), fs::Permissions::from_mode(mode)).unwrap();
    }
    let root = open(
        &fixture.path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    ConnectionStore {
        state: StateDirectory::open_at(root, fixture.owner).unwrap(),
        boot: BootId([1; 16]),
        instance: [2; 16],
        observed: Cell::new(None),
        uncertain: Cell::new(false),
    }
}
fn operation(revision: u64, nonce: u8) -> [u8; 16] {
    let mut operation = [nonce; 16];
    operation[..8].copy_from_slice(&revision.to_be_bytes());
    operation
}
fn request(store: &ConnectionStore, nonce: u8, revision: u64, desired: Desired) -> Request {
    Request {
        operation: operation(revision, nonce),
        expected_configuration: 7,
        expected_revision: revision,
        expected_instance: store.instance_id(),
        desired,
    }
}
fn path(fixture: &Fixture) -> std::path::PathBuf {
    fixture.path.join("var/lib/warper/connection")
}
fn pending(fixture: &Fixture) -> std::path::PathBuf {
    fixture.path.join("var/lib/warper/connection.pending")
}
fn snapshot(acceptance: Acceptance) -> Snapshot {
    match acceptance {
        Acceptance::Accepted(snapshot) | Acceptance::AlreadyAccepted(snapshot) => snapshot,
    }
}

#[test]
fn durable_acceptance_repeats_without_rewrite_and_old_evicted_requests_never_reapply() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut store = store(&fixture);
    assert_eq!(store.read(&lease), Ok(None));
    let connect = request(&store, 3, 0, Desired::Up);
    let accepted = snapshot(store.accept(&lease, 7, connect).unwrap());
    assert_eq!(accepted.revision(), 1);
    assert_eq!(accepted.desired(), Desired::Up);
    assert_eq!(accepted.configuration_generation(), 7);
    assert!(accepted.same_boot(&store.boot_id()));
    let inode = fs::metadata(path(&fixture)).unwrap();
    assert_eq!(
        store.accept_with_sync(&lease, 7, connect, |_| panic!(
            "an exact repeat must not rewrite or sync"
        )),
        Ok(Acceptance::AlreadyAccepted(accepted))
    );
    use std::os::unix::fs::MetadataExt;
    assert_eq!(fs::metadata(path(&fixture)).unwrap().ino(), inode.ino());
    let disconnect = request(&store, 4, 1, Desired::Down);
    let disconnected = snapshot(store.accept(&lease, 7, disconnect).unwrap());
    assert_eq!(disconnected.revision(), 2);
    assert_eq!(disconnected.desired(), Desired::Down);
    assert!(
        matches!(store.accept(&lease, 7,connect),Err(failure) if failure.primary==Error::Conflict)
    );
    assert_eq!(store.read(&lease), Ok(Some(disconnected)));
    assert!(!pending(&fixture).exists());
    assert_eq!(fs::metadata(path(&fixture)).unwrap().len(), 80);
}
#[test]
fn restart_preserves_intent_but_changes_the_instance_fence_and_never_resets_revision() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut original = store(&fixture);
    let old = request(&original, 3, 0, Desired::Up);
    original.accept(&lease, 7, old).unwrap();
    drop(original);
    let mut reopened = store(&fixture);
    reopened.instance = [9; 16];
    let stored = reopened.read(&lease).unwrap().unwrap();
    assert_eq!(stored.desired(), Desired::Up);
    assert_eq!(stored.revision(), 1);
    assert!(
        matches!(reopened.accept(&lease, 7,old),Err(failure) if failure.primary==Error::Conflict)
    );
    let new = request(&reopened, 4, 1, Desired::Down);
    assert_eq!(
        snapshot(reopened.accept(&lease, 7, new).unwrap()).revision(),
        2
    );
    reopened.boot = BootId([8; 16]);
    assert!(
        !reopened
            .read(&lease)
            .unwrap()
            .unwrap()
            .same_boot(&reopened.boot_id())
    );
    assert_eq!(
        reopened.read(&lease).unwrap().unwrap().desired(),
        Desired::Down
    );
}
#[test]
fn conflicting_operation_reuse_invalid_identity_and_exhaustion_preserve_current_state() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut store = store(&fixture);
    let sample = request(&store, 3, 0, Desired::Up);
    store.accept(&lease, 7, sample).unwrap();
    for changed in [
        Request {
            desired: Desired::Down,
            ..sample
        },
        Request {
            expected_configuration: 8,
            ..sample
        },
        Request {
            expected_revision: 1,
            ..sample
        },
        Request {
            operation: [0; 16],
            ..sample
        },
        Request {
            expected_instance: [0; 16],
            ..sample
        },
        Request {
            expected_configuration: 0,
            ..sample
        },
    ] {
        assert!(store.accept(&lease, 7, changed).is_err());
        assert_eq!(store.read(&lease).unwrap().unwrap().revision(), 1);
    }
    let current = Snapshot {
        revision: u64::MAX,
        operation: operation(u64::MAX - 1, 6),
        ..store.read(&lease).unwrap().unwrap()
    };
    fs::write(path(&fixture), encode(current)).unwrap();
    store.observed.set(None);
    let sample = request(&store, 7, u64::MAX, Desired::Down);
    assert!(
        matches!(store.accept(&lease, 7,sample),Err(failure) if failure.primary==Error::RevisionExhausted)
    );
    assert!(!pending(&fixture).exists());
}
#[test]
fn commit_uncertainty_blocks_acceptance_until_unchanged_state_is_explicitly_resynced() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut store = store(&fixture);
    let sample = request(&store, 3, 0, Desired::Up);
    assert_eq!(
        store.accept_with_sync(&lease, 7, sample, |_| Err(Error::Io(io::ErrorKind::Other))),
        Err(Failure {
            primary: Error::CommitUncertain(io::ErrorKind::Other),
            cleanup: None
        })
    );
    assert_eq!(store.read(&lease), Err(Error::RecoveryRequired));
    let inspected = store.inspect(&lease).unwrap().unwrap();
    assert_eq!(inspected.revision(), 1);
    assert!(
        matches!(store.accept(&lease, 7,sample),Err(failure) if failure.primary==Error::RecoveryRequired)
    );
    store.resync(&lease).unwrap();
    assert_eq!(store.read(&lease), Ok(Some(inspected)));
    assert_eq!(
        store.accept(&lease, 7, sample),
        Ok(Acceptance::AlreadyAccepted(inspected))
    );
    assert!(!pending(&fixture).exists());
}
#[test]
fn changed_or_deleted_committed_state_never_becomes_fresh_revision_zero() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut store = store(&fixture);
    store
        .accept(&lease, 7, request(&store, 3, 0, Desired::Up))
        .unwrap();
    let bytes = fs::read(path(&fixture)).unwrap();
    fs::rename(path(&fixture), fixture.path.join("old-intent")).unwrap();
    fs::write(path(&fixture), &bytes).unwrap();
    fs::set_permissions(path(&fixture), fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(store.read(&lease), Err(Error::UnsafeState));
    fs::remove_file(path(&fixture)).unwrap();
    assert_eq!(store.read(&lease), Err(Error::UnsafeState));
    assert!(
        matches!(store.accept(&lease, 7,request(&store,4,0,Desired::Down)),Err(failure) if failure.primary==Error::UnsafeState)
    );
    assert!(fixture.path.join("old-intent").exists());
}
#[test]
fn unsafe_and_pending_state_fail_closed_without_removal_or_file_io_on_special_objects() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut store = store(&fixture);
    fs::write(pending(&fixture), b"partial").unwrap();
    assert_eq!(store.read(&lease), Err(Error::RecoveryRequired));
    assert!(
        matches!(store.accept(&lease, 7,request(&store,3,0,Desired::Up)),Err(failure) if failure.primary==Error::RecoveryRequired)
    );
    assert_eq!(fs::read(pending(&fixture)).unwrap(), b"partial");
    fs::remove_file(pending(&fixture)).unwrap();
    fs::write(path(&fixture), [0; 81]).unwrap();
    fs::set_permissions(path(&fixture), fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(store.read(&lease), Err(Error::UnsafeState));
    fs::remove_file(path(&fixture)).unwrap();
    symlink(fixture.path.join("foreign"), path(&fixture)).unwrap();
    assert_eq!(store.read(&lease), Err(Error::UnsafeState));
    assert!(fs::symlink_metadata(path(&fixture)).unwrap().is_symlink());
}
#[test]
fn encoded_intent_is_exact_versioned_bounded_and_redacted() {
    let record = Snapshot {
        revision: 5,
        boot: BootId([1; 16]),
        instance: [2; 16],
        operation: operation(4, 3),
        configuration: 7,
        desired: Desired::Up,
    };
    let bytes = encode(record);
    assert_eq!(&bytes[..8], b"WCIN\0\0\0\x01");
    assert_eq!(&bytes[8..16], &5u64.to_be_bytes());
    assert_eq!(&bytes[16..32], &[1; 16]);
    assert_eq!(&bytes[32..48], &[2; 16]);
    assert_eq!(&bytes[48..64], &operation(4, 3));
    assert_eq!(&bytes[64..72], &7u64.to_be_bytes());
    assert_eq!(&bytes[72..], &[1, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(decode(&bytes), Ok(record));
    assert_eq!(format!("{record:?}"), "ConnectionSnapshot(<redacted>)");
    for length in 0..80 {
        assert_eq!(decode(&bytes[..length]), Err(Error::InvalidRecord));
    }
    for range in [0..4, 4..8, 8..16, 16..32, 32..48, 48..64, 64..72] {
        let mut sample = bytes;
        sample[range].fill(0);
        assert_eq!(decode(&sample), Err(Error::InvalidRecord));
    }
    let mut sample = bytes;
    sample[73] = 1;
    assert_eq!(decode(&sample), Err(Error::InvalidRecord));
    let mut sample = bytes;
    sample[72] = 2;
    assert_eq!(decode(&sample), Err(Error::InvalidRecord));
}

#[test]
fn staged_failures_preserve_primary_cleanup_and_foreign_replacement_state() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut store = store(&fixture);
    let first = request(&store, 3, 0, Desired::Up);
    store.accept(&lease, 7, first).unwrap();
    let before = fs::read(path(&fixture)).unwrap();
    let next = request(&store, 4, 1, Desired::Down);
    let failure = store
        .accept_staged(
            &lease,
            7,
            next,
            || Err(Error::Io(io::ErrorKind::Other)),
            ConnectionStore::sync,
        )
        .unwrap_err();
    assert_eq!(
        failure,
        Failure {
            primary: Error::Io(io::ErrorKind::Other),
            cleanup: None
        }
    );
    assert_eq!(fs::read(path(&fixture)).unwrap(), before);
    assert!(!pending(&fixture).exists());
    let failure = store
        .accept_staged(
            &lease,
            7,
            next,
            || {
                fs::rename(pending(&fixture), fixture.path.join("retired-pending")).unwrap();
                fs::write(pending(&fixture), b"foreign fixture state").unwrap();
                fs::set_permissions(pending(&fixture), fs::Permissions::from_mode(0o600)).unwrap();
                Err(Error::Io(io::ErrorKind::Other))
            },
            ConnectionStore::sync,
        )
        .unwrap_err();
    assert_eq!(
        failure,
        Failure {
            primary: Error::Io(io::ErrorKind::Other),
            cleanup: Some(Error::UnsafeState)
        }
    );
    assert_eq!(
        fs::read(pending(&fixture)).unwrap(),
        b"foreign fixture state"
    );
    assert_eq!(fs::read(path(&fixture)).unwrap(), before);
}
#[test]
fn changed_current_record_between_staging_and_publication_is_never_overwritten() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut store = store(&fixture);
    let first = request(&store, 3, 0, Desired::Up);
    let original = snapshot(store.accept(&lease, 7, first).unwrap());
    let next = request(&store, 4, 1, Desired::Down);
    let changed = Snapshot {
        revision: 2,
        operation: operation(1, 9),
        ..original
    };
    let failure = store
        .accept_staged(
            &lease,
            7,
            next,
            || {
                fs::write(path(&fixture), encode(changed)).unwrap();
                Ok(())
            },
            ConnectionStore::sync,
        )
        .unwrap_err();
    assert_eq!(failure.primary, Error::Conflict);
    assert_eq!(failure.cleanup, None);
    assert_eq!(fs::read(path(&fixture)).unwrap(), encode(changed));
    assert!(!pending(&fixture).exists());
    assert_eq!(store.read(&lease), Err(Error::UnsafeState));
}
#[test]
fn v2_frame_requests_preserve_fields_and_compare_the_approved_configuration() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut store = store(&fixture);
    let mut body = operation(0, 3).to_vec();
    body.extend_from_slice(&7u64.to_be_bytes());
    body.extend_from_slice(&0u64.to_be_bytes());
    body.extend_from_slice(&store.instance_id());
    let frame = crate::wire::Frame::new(crate::wire::Kind::Connect, 1, body).unwrap();
    let request = Request::from_frame(&frame).unwrap();
    assert_eq!(request.operation, operation(0, 3));
    assert_eq!(request.expected_revision, 0);
    assert_eq!(request.expected_configuration, 7);
    assert_eq!(request.expected_instance, store.instance_id());
    assert_eq!(request.desired, Desired::Up);
    assert!(
        matches!(store.accept(&lease,8,request),Err(failure) if failure.primary==Error::Conflict)
    );
    assert_eq!(store.read(&lease), Ok(None));
    assert!(matches!(
        store.accept(&lease, 7, request),
        Ok(Acceptance::Accepted(_))
    ));
    let frame = crate::wire::Frame::new(crate::wire::Kind::Status, 1, vec![]).unwrap();
    assert!(matches!(
        Request::from_frame(&frame),
        Err(Error::InvalidRequest)
    ));
}
#[test]
fn public_open_requires_actual_root_and_has_no_fixture_path_override() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    if fixture.owner != 0 {
        assert!(matches!(
            ConnectionStore::open(&lease),
            Err(Error::Runtime(super::super::Error::PrivilegeRequired))
        ));
    }
}

#[test]
fn pending_discard_preserves_committed_intent_for_empty_partial_and_complete_writes() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut store = store(&fixture);
    let sample = request(&store, 3, 0, Desired::Up);
    let committed = snapshot(store.accept(&lease, 7, sample).unwrap());
    for length in [0, 8, 80] {
        fs::write(pending(&fixture), &encode(committed)[..length]).unwrap();
        fs::set_permissions(pending(&fixture), fs::Permissions::from_mode(0o600)).unwrap();
        let inspection = store.inspect_pending(&lease).unwrap().unwrap();
        assert_eq!(inspection.pending_len(), length);
        assert_eq!(inspection.committed(), Some(committed));
        assert_eq!(
            format!("{inspection:?}"),
            "ConnectionPendingInspection(<redacted>)"
        );
        store.discard_pending(&lease, inspection).unwrap();
        assert_eq!(store.read(&lease), Ok(Some(committed)));
    }
    assert!(store.inspect_pending(&lease).unwrap().is_none());
}
#[test]
fn changed_pending_or_committed_inspection_is_preserved_and_unlink_uncertainty_requires_resync() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut store = store(&fixture);
    let sample = request(&store, 3, 0, Desired::Up);
    let committed = snapshot(store.accept(&lease, 7, sample).unwrap());
    fs::write(pending(&fixture), b"partial").unwrap();
    fs::set_permissions(pending(&fixture), fs::Permissions::from_mode(0o600)).unwrap();
    let inspection = store.inspect_pending(&lease).unwrap().unwrap();
    fs::write(pending(&fixture), b"changed").unwrap();
    assert_eq!(
        store.discard_pending(&lease, inspection),
        Err(Error::UnsafeState)
    );
    assert_eq!(fs::read(pending(&fixture)).unwrap(), b"changed");
    let inspection = store.inspect_pending(&lease).unwrap().unwrap();
    assert_eq!(
        store.discard_with_sync(&lease, inspection, |_| Err(Error::Io(io::ErrorKind::Other))),
        Err(Error::CommitUncertain(io::ErrorKind::Other))
    );
    assert_eq!(store.read(&lease), Err(Error::RecoveryRequired));
    assert_eq!(store.inspect(&lease), Ok(Some(committed)));
    store.resync(&lease).unwrap();
    assert_eq!(store.read(&lease), Ok(Some(committed)));
    fs::write(pending(&fixture), b"partial").unwrap();
    fs::set_permissions(pending(&fixture), fs::Permissions::from_mode(0o600)).unwrap();
    let inspection = store.inspect_pending(&lease).unwrap().unwrap();
    fs::write(
        path(&fixture),
        encode(Snapshot {
            revision: 2,
            operation: operation(1, 4),
            ..committed
        }),
    )
    .unwrap();
    assert_eq!(
        store.discard_pending(&lease, inspection),
        Err(Error::UnsafeState)
    );
    assert!(pending(&fixture).exists());
}

#[test]
fn evicted_operation_cannot_be_replayed_by_refreshing_its_revision_fields() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut store = store(&fixture);
    let connect = request(&store, 3, 0, Desired::Up);
    store.accept(&lease, 7, connect).unwrap();
    let disconnect = request(&store, 4, 1, Desired::Down);
    let stopped = snapshot(store.accept(&lease, 7, disconnect).unwrap());
    let refreshed = Request {
        expected_revision: 2,
        ..connect
    };
    assert!(
        matches!(store.accept(&lease,7,refreshed),Err(failure) if failure.primary==Error::Conflict)
    );
    assert_eq!(store.read(&lease), Ok(Some(stopped)));
}

#[test]
fn disconnect_without_configuration_persists_and_resync_never_promotes_pending_intent() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut store = store(&fixture);
    let down = Request {
        expected_configuration: 0,
        ..request(&store, 3, 0, Desired::Down)
    };
    let committed = snapshot(store.accept(&lease, 0, down).unwrap());
    assert_eq!(committed.configuration_generation(), 0);
    assert_eq!(committed.desired(), Desired::Down);
    fs::write(pending(&fixture), b"partial").unwrap();
    fs::set_permissions(pending(&fixture), fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(store.resync(&lease), Err(Error::RecoveryRequired));
    assert_eq!(fs::read(pending(&fixture)).unwrap(), b"partial");
    let inspection = store.inspect_pending(&lease).unwrap().unwrap();
    store.discard_pending(&lease, inspection).unwrap();
    assert_eq!(store.read(&lease), Ok(Some(committed)));
}
