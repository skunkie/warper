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

fn store(fixture: &Fixture) -> NetworkJournal {
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
    NetworkJournal::new(StateDirectory::open_at(root, fixture.owner).unwrap()).unwrap()
}
fn path(fixture: &Fixture) -> std::path::PathBuf {
    fixture.path.join("var/lib/warper/network.journal")
}
fn pending(fixture: &Fixture) -> std::path::PathBuf {
    fixture.path.join("var/lib/warper/network.pending")
}
fn stage(fixture: &Fixture, bytes: &[u8]) {
    fs::write(pending(fixture), bytes).unwrap();
    fs::set_permissions(pending(fixture), fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn durable_revisioned_snapshots_survive_reopen_and_refuse_stale_replacement() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut journal = store(&fixture);
    assert_eq!(journal.read(&lease), Ok(None));
    assert!(journal.inspect_pending(&lease).unwrap().is_none());
    let first = journal
        .replace(&lease, 0, b"invented initial native metadata")
        .unwrap();
    assert_eq!(first.revision(), 1);
    assert_eq!(first.payload(), b"invented initial native metadata");
    assert_eq!(journal.read(&lease), Ok(Some(first.clone())));
    assert_eq!(
        journal.replace(&lease, 0, b"stale data"),
        Err(Error::Conflict)
    );
    assert!(!pending(&fixture).exists());
    let second = journal
        .replace(&lease, 1, b"invented committed metadata")
        .unwrap();
    assert_eq!(second.revision(), 2);
    drop(journal);
    let reopened = store(&fixture);
    assert_eq!(reopened.read(&lease), Ok(Some(second)));
    assert_eq!(format!("{first:?}"), "JournalSnapshot(<redacted>)");
    assert_eq!(format!("{reopened:?}"), "NetworkJournal(<redacted>)");
}

#[test]
fn payload_and_envelope_boundaries_fail_before_staging() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut journal = store(&fixture);
    assert_eq!(journal.replace(&lease, 0, b""), Err(Error::InvalidRecord));
    assert_eq!(
        journal.replace(&lease, 0, &vec![0; MAX_PAYLOAD + 1]),
        Err(Error::ResourceLimit)
    );
    assert!(!pending(&fixture).exists());
    let maximum = journal
        .replace(&lease, 0, &vec![b'x'; MAX_PAYLOAD])
        .unwrap();
    assert_eq!(maximum.payload().len(), MAX_PAYLOAD);
    assert_eq!(journal.read(&lease).unwrap().unwrap(), maximum);
    let bytes = encode(&Snapshot {
        revision: 1,
        payload: b"invented".to_vec(),
    });
    for end in 0..HEADER + 1 {
        assert_eq!(decode(&bytes[..end]), Err(Error::InvalidRecord));
    }
    for (offset, value) in [(0, 0), (4, 0), (8, 0), (16, 0), (20, 1)] {
        let mut invalid = bytes.clone();
        if offset == 8 {
            invalid[8..16].fill(0)
        } else {
            invalid[offset..offset + 4].copy_from_slice(&(value as u32).to_be_bytes())
        }
        assert_eq!(decode(&invalid), Err(Error::InvalidRecord));
    }
    let mut extra = bytes;
    extra.push(0);
    assert_eq!(decode(&extra), Err(Error::InvalidRecord));
}

#[test]
fn changed_or_deleted_observed_state_never_resets_the_revision() {
    for changed in [true, false] {
        let fixture = Fixture::new();
        let lease = fixture.acquire().unwrap();
        let mut journal = store(&fixture);
        journal.replace(&lease, 0, b"original").unwrap();
        if changed {
            fs::write(
                path(&fixture),
                encode(&Snapshot {
                    revision: 1,
                    payload: b"modified".to_vec(),
                }),
            )
            .unwrap();
        } else {
            fs::remove_file(path(&fixture)).unwrap();
        }
        assert_eq!(journal.read(&lease), Err(Error::UnsafeState));
        assert_eq!(
            journal.replace(&lease, 0, b"replacement"),
            Err(Error::UnsafeState)
        );
        assert!(!pending(&fixture).exists());
    }
}

#[test]
fn failed_stage_is_preserved_and_requires_explicit_inspected_discard() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut journal = store(&fixture);
    let first = journal.replace(&lease, 0, b"original").unwrap();
    assert_eq!(
        journal.replace_with(
            &lease,
            1,
            b"new intent",
            || Err(Error::Io(io::ErrorKind::Other)),
            |journal| journal.sync()
        ),
        Err(Error::Io(io::ErrorKind::Other))
    );
    assert_eq!(journal.read(&lease), Err(Error::RecoveryRequired));
    assert_eq!(journal.inspect(&lease), Ok(Some(first.clone())));
    let token = journal.inspect_pending(&lease).unwrap().unwrap();
    assert_eq!(token.committed(), Some(&first));
    assert_eq!(token.staged_length(), HEADER + 10);
    assert_eq!(format!("{token:?}"), "JournalPendingInspection(<redacted>)");
    journal.discard_pending(&lease, token).unwrap();
    assert_eq!(journal.read(&lease), Ok(Some(first)));
    assert!(!pending(&fixture).exists());
}

#[test]
fn append_after_staging_cannot_publish_a_valid_prefix_with_a_tail() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut journal = store(&fixture);
    let result = journal.replace_with(
        &lease,
        0,
        b"new intent",
        || {
            fs::OpenOptions::new()
                .append(true)
                .open(pending(&fixture))
                .unwrap()
                .write_all(b"tail")
                .unwrap();
            Ok(())
        },
        |journal| journal.sync(),
    );
    assert_eq!(result, Err(Error::UnsafeState));
    assert!(!path(&fixture).exists());
    assert!(pending(&fixture).exists());
}

#[test]
fn post_rename_sync_uncertainty_blocks_writes_until_unchanged_resync() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut journal = store(&fixture);
    assert_eq!(
        journal.replace_with(
            &lease,
            0,
            b"intent",
            || Ok(()),
            |_| Err(Error::Io(io::ErrorKind::Other))
        ),
        Err(Error::CommitUncertain(io::ErrorKind::Other))
    );
    assert_eq!(journal.read(&lease), Err(Error::RecoveryRequired));
    let committed = journal.inspect(&lease).unwrap().unwrap();
    assert_eq!(committed.revision(), 1);
    assert_eq!(
        journal.replace(&lease, 1, b"next"),
        Err(Error::RecoveryRequired)
    );
    journal.resync(&lease).unwrap();
    assert_eq!(journal.read(&lease), Ok(Some(committed)));
}

#[test]
fn partial_empty_and_full_pending_files_are_never_promoted() {
    for bytes in [
        vec![],
        vec![b'W'],
        encode(&Snapshot {
            revision: 77,
            payload: b"invented".to_vec(),
        }),
    ] {
        let fixture = Fixture::new();
        let lease = fixture.acquire().unwrap();
        let mut journal = store(&fixture);
        stage(&fixture, &bytes);
        let token = journal.inspect_pending(&lease).unwrap().unwrap();
        assert_eq!(token.staged_length(), bytes.len());
        assert_eq!(token.committed(), None);
        assert_eq!(
            journal.replace(&lease, 0, b"new"),
            Err(Error::RecoveryRequired)
        );
        journal.discard_pending(&lease, token).unwrap();
        assert_eq!(journal.read(&lease), Ok(None));
    }
}

#[test]
fn changed_pending_prior_state_or_store_preserves_recovery_evidence() {
    for change in 0..4 {
        let fixture = Fixture::new();
        let lease = fixture.acquire().unwrap();
        let mut journal = store(&fixture);
        journal.replace(&lease, 0, b"original").unwrap();
        stage(&fixture, b"staged");
        let token = journal.inspect_pending(&lease).unwrap().unwrap();
        match change {
            0 => fs::write(pending(&fixture), b"edited").unwrap(),
            1 => {
                fs::rename(pending(&fixture), pending(&fixture).with_extension("saved")).unwrap();
                stage(&fixture, b"staged");
            }
            2 => fs::write(
                path(&fixture),
                encode(&Snapshot {
                    revision: 1,
                    payload: b"modified".to_vec(),
                }),
            )
            .unwrap(),
            _ => {
                let mut reopened = store(&fixture);
                assert_eq!(
                    reopened.discard_pending(&lease, token),
                    Err(Error::Conflict)
                );
                assert!(pending(&fixture).exists());
                continue;
            }
        }
        assert_eq!(
            journal.discard_pending(&lease, token),
            Err(Error::UnsafeState)
        );
        assert!(pending(&fixture).exists());
    }
}

#[test]
fn discard_sync_uncertainty_requires_resync_without_accepting_intent() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut journal = store(&fixture);
    stage(&fixture, b"partial");
    let token = journal.inspect_pending(&lease).unwrap().unwrap();
    assert_eq!(
        journal.discard_with(&lease, token, |_| Err(Error::Io(io::ErrorKind::Other))),
        Err(Error::CommitUncertain(io::ErrorKind::Other))
    );
    assert!(!pending(&fixture).exists());
    assert_eq!(journal.read(&lease), Err(Error::RecoveryRequired));
    journal.resync(&lease).unwrap();
    assert_eq!(journal.read(&lease), Ok(None));
}

#[test]
fn unsafe_files_and_runtime_replacement_are_rejected_without_removal() {
    for kind in 0..5 {
        let fixture = Fixture::new();
        let lease = fixture.acquire().unwrap();
        let journal = store(&fixture);
        match kind {
            0 => symlink("unrelated", pending(&fixture)).unwrap(),
            1 => {
                stage(&fixture, b"pending");
                fs::set_permissions(pending(&fixture), fs::Permissions::from_mode(0o644)).unwrap();
            }
            2 => {
                stage(&fixture, b"pending");
                fs::hard_link(
                    pending(&fixture),
                    pending(&fixture).with_extension("linked"),
                )
                .unwrap();
            }
            3 => stage(&fixture, &vec![0; MAX_FILE + 1]),
            _ => {
                stage(&fixture, b"pending");
                fs::rename(
                    fixture.path.join("run/warper"),
                    fixture.path.join("run/moved"),
                )
                .unwrap();
                fs::create_dir(fixture.path.join("run/warper")).unwrap();
            }
        }
        assert!(journal.inspect_pending(&lease).is_err());
        assert!(pending(&fixture).symlink_metadata().is_ok());
    }
}

#[test]
fn exhausted_revisions_and_changed_prior_state_never_publish_staging() {
    {
        let fixture = Fixture::new();
        let lease = fixture.acquire().unwrap();
        let mut journal = store(&fixture);
        fs::write(
            path(&fixture),
            encode(&Snapshot {
                revision: u64::MAX,
                payload: b"old".to_vec(),
            }),
        )
        .unwrap();
        fs::set_permissions(path(&fixture), fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            journal.replace(&lease, u64::MAX, b"new"),
            Err(Error::ResourceLimit)
        );
        assert!(!pending(&fixture).exists());
    }
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut journal = store(&fixture);
    let before = journal.replace(&lease, 0, b"old").unwrap();
    assert_eq!(
        journal.replace_with(
            &lease,
            1,
            b"new",
            || {
                fs::rename(path(&fixture), path(&fixture).with_extension("saved")).unwrap();
                fs::write(path(&fixture), encode(&before)).unwrap();
                fs::set_permissions(path(&fixture), fs::Permissions::from_mode(0o600)).unwrap();
                Ok(())
            },
            |journal| journal.sync()
        ),
        Err(Error::UnsafeState)
    );
    assert!(pending(&fixture).exists());
}

#[test]
fn a_same_length_staged_rewrite_never_becomes_committed_metadata() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut journal = store(&fixture);
    assert_eq!(
        journal.replace_with(
            &lease,
            0,
            b"original",
            || {
                fs::write(
                    pending(&fixture),
                    encode(&Snapshot {
                        revision: 1,
                        payload: b"modified".to_vec(),
                    }),
                )
                .unwrap();
                Ok(())
            },
            |journal| journal.sync()
        ),
        Err(Error::UnsafeState)
    );
    assert!(!path(&fixture).exists());
    assert!(pending(&fixture).exists());
}
