// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;

fn managed(fixture: &Fixture) -> FixedStore {
    fs::create_dir_all(fixture.path.join("etc/warper")).unwrap();
    for (name, mode) in [("etc", 0o755), ("etc/warper", 0o700)] {
        fs::set_permissions(fixture.path.join(name), fs::Permissions::from_mode(mode)).unwrap();
    }
    let anchor = open(
        &fixture.path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    FixedStore::with_slot(
        StateDirectory::open_at_location(anchor, fixture.owner, true).unwrap(),
        Slot::Managed,
    )
    .unwrap()
}
fn current(fixture: &Fixture) -> std::path::PathBuf {
    fixture.path.join("etc/warper/configuration")
}
fn staged(fixture: &Fixture) -> std::path::PathBuf {
    fixture.path.join("etc/warper/configuration.pending")
}
fn partial(fixture: &Fixture) {
    fs::write(staged(fixture), b"invented interrupted managed write").unwrap();
    fs::set_permissions(staged(fixture), fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn managed_capacity_and_generations_are_independent_of_network_journal() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut config = managed(&fixture);
    let network = store(&fixture);
    assert_eq!(config.read(&lease), Ok(None));
    assert_eq!(
        config.replace(&lease, 0, &vec![0; 1_048_577]),
        Err(Error::ResourceLimit)
    );
    assert!(!staged(&fixture).exists());
    let bytes = vec![b'x'; 1_048_576];
    let first = config.replace(&lease, 0, &bytes).unwrap();
    assert_eq!(first.revision(), 1);
    assert_eq!(first.payload(), bytes);
    assert_eq!(&fs::read(current(&fixture)).unwrap()[..4], b"WCFG");
    assert_eq!(config.replace(&lease, 0, b"stale"), Err(Error::Conflict));
    drop(config);
    let mut reopened = managed(&fixture);
    assert_eq!(reopened.read(&lease), Ok(Some(first)));
    assert_eq!(
        reopened
            .replace(&lease, 1, b"replacement managed bytes")
            .unwrap()
            .revision(),
        2
    );
    assert_eq!(network.read(&lease), Ok(None));
    assert!(!path(&fixture).exists());
}

#[test]
fn pending_tokens_cannot_cross_fixed_slots_and_discard_never_promotes_bytes() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut config = managed(&fixture);
    let mut network = store(&fixture);
    let committed = config
        .replace(&lease, 0, b"approved managed bytes")
        .unwrap();
    partial(&fixture);
    stage(&fixture, b"interrupted network bytes");
    assert_eq!(config.read(&lease), Err(Error::RecoveryRequired));
    let network_token = network.inspect_pending(&lease).unwrap().unwrap();
    assert_eq!(
        config.discard_pending(&lease, network_token),
        Err(Error::Conflict)
    );
    let config_token = config.inspect_pending(&lease).unwrap().unwrap();
    assert_eq!(
        network.discard_pending(&lease, config_token),
        Err(Error::Conflict)
    );
    assert!(pending(&fixture).exists());
    assert!(staged(&fixture).exists());
    let token = config.inspect_pending(&lease).unwrap().unwrap();
    assert_eq!(token.committed(), Some(&committed));
    config.discard_pending(&lease, token).unwrap();
    assert_eq!(config.read(&lease), Ok(Some(committed)));
    assert!(pending(&fixture).exists());
}

#[test]
fn wrong_slot_magic_and_foreign_replacements_are_preserved() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut config = managed(&fixture);
    let mut network = store(&fixture);
    config.replace(&lease, 0, b"managed bytes").unwrap();
    network.replace(&lease, 0, b"network metadata").unwrap();
    let config_bytes = fs::read(current(&fixture)).unwrap();
    let network_bytes = fs::read(path(&fixture)).unwrap();
    fs::write(current(&fixture), &network_bytes).unwrap();
    assert_eq!(config.read(&lease), Err(Error::InvalidRecord));
    assert_eq!(fs::read(current(&fixture)).unwrap(), network_bytes);
    fs::write(path(&fixture), &config_bytes).unwrap();
    assert_eq!(network.read(&lease), Err(Error::InvalidRecord));
    assert_eq!(fs::read(path(&fixture)).unwrap(), config_bytes);
}

#[test]
fn managed_commit_uncertainty_requires_resync_of_unchanged_state() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut config = managed(&fixture);
    assert_eq!(
        config.replace_with(
            &lease,
            0,
            b"approved bytes",
            || Ok(()),
            |_| Err(Error::Io(io::ErrorKind::Other))
        ),
        Err(Error::CommitUncertain(io::ErrorKind::Other))
    );
    assert_eq!(config.read(&lease), Err(Error::RecoveryRequired));
    assert_eq!(
        config.replace(&lease, 1, b"new bytes"),
        Err(Error::RecoveryRequired)
    );
    assert_eq!(config.inspect(&lease).unwrap().unwrap().revision(), 1);
    config.resync(&lease).unwrap();
    assert_eq!(
        config.read(&lease).unwrap().unwrap().payload(),
        b"approved bytes"
    );
    config.replace(&lease, 1, b"new bytes").unwrap();
}

#[test]
fn changed_configuration_parents_are_never_repaired_or_used() {
    let fixture = Fixture::new();
    let lease = fixture.acquire().unwrap();
    let mut config = managed(&fixture);
    config.replace(&lease, 0, b"approved bytes").unwrap();
    fs::rename(fixture.path.join("etc"), fixture.path.join("previous-etc")).unwrap();
    fs::create_dir_all(fixture.path.join("etc/warper")).unwrap();
    fs::set_permissions(
        fixture.path.join("etc/warper"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert_eq!(config.read(&lease), Err(Error::UnsafeState));
    assert_eq!(
        config.replace(&lease, 1, b"new bytes"),
        Err(Error::UnsafeState)
    );
    assert!(!current(&fixture).exists());
    assert!(
        fixture
            .path
            .join("previous-etc/warper/configuration")
            .exists()
    );
}
