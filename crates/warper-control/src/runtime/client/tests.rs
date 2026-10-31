// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use crate::runtime::{endpoint::ControlEndpoint, tests::Fixture};
use std::{
    fs,
    io::Read,
    os::unix::{
        fs::{FileTypeExt, PermissionsExt, symlink},
        net::UnixListener,
    },
    time::Duration,
};

fn inspect(fixture: &Fixture) -> Result<Endpoint, Error> {
    let root = open(
        &fixture.path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    Endpoint::open_at(root, fixture.owner)
}
#[tokio::test]
async fn pinned_endpoint_connects_without_payload_and_checks_real_service_identity() {
    let fixture = Fixture::new();
    let endpoint = ControlEndpoint::bind(fixture.acquire().unwrap()).unwrap();
    let pinned = inspect(&fixture).unwrap();
    let (_owner, cancel) = watch::channel(false);
    let result = pinned
        .connect(Instant::now() + Duration::from_secs(1), cancel)
        .await;
    if fixture.owner == 0 {
        drop(result.unwrap());
    } else {
        assert!(matches!(
            result,
            Err(Error::Admission(crate::Error::PermissionDenied))
        ));
    }
    let mut accepted = endpoint
        .accept(&crate::OwnerPolicy::new(Some(fixture.owner)).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(accepted.stream.read(&mut [0]).unwrap(), 0);
    endpoint.close().unwrap();
}

#[tokio::test]
async fn stale_socket_connection_failure_preserves_the_pathname() {
    let fixture = Fixture::new();
    let socket = fixture.path.join("run/warper/control.sock");
    drop(UnixListener::bind(&socket).unwrap());
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o666)).unwrap();
    let pinned = inspect(&fixture).unwrap();
    let (_owner, cancel) = watch::channel(false);
    assert!(matches!(
        pinned
            .connect(Instant::now() + Duration::from_secs(1), cancel)
            .await,
        Err(Error::Io(io::ErrorKind::ConnectionRefused))
    ));
    assert!(
        fs::symlink_metadata(socket)
            .unwrap()
            .file_type()
            .is_socket()
    );
}
#[tokio::test]
async fn expired_or_cancelled_admission_does_not_connect_or_inspect_fixed_paths() {
    let (owner, cancel) = watch::channel(false);
    assert!(matches!(
        connect(Instant::now(), cancel.clone()).await,
        Err(Error::Timeout)
    ));
    owner.send(true).unwrap();
    assert!(matches!(
        connect(Instant::now() + Duration::from_secs(1), cancel.clone()).await,
        Err(Error::Cancelled)
    ));
    owner.send(false).unwrap();
    drop(owner);
    assert!(matches!(
        connect(Instant::now() + Duration::from_secs(1), cancel).await,
        Err(Error::Cancelled)
    ));
}
#[test]
fn endpoint_metadata_and_namespace_changes_are_rejected_without_repair() {
    let fixture = Fixture::new();
    let endpoint = ControlEndpoint::bind(fixture.acquire().unwrap()).unwrap();
    let pinned = inspect(&fixture).unwrap();
    let socket = fixture.path.join("run/warper/control.sock");
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(inspect(&fixture), Err(Error::UnsafeEndpoint)));
    assert_eq!(pinned.verify(), Err(Error::UnsafeEndpoint));
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o666)).unwrap();
    fs::rename(&socket, fixture.path.join("old-socket")).unwrap();
    let replacement = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o666)).unwrap();
    assert_eq!(pinned.verify(), Err(Error::UnsafeEndpoint));
    drop(replacement);
    fs::remove_file(&socket).unwrap();
    symlink(fixture.path.join("old-socket"), &socket).unwrap();
    assert!(inspect(&fixture).is_err());
    assert!(fs::symlink_metadata(&socket).unwrap().is_symlink());
    fs::remove_file(&socket).unwrap();
    fs::rename(fixture.path.join("old-socket"), &socket).unwrap();
    let directory = fixture.path.join("run/warper");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(pinned.verify(), Err(Error::UnsafeEndpoint));
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
    fs::rename(&directory, fixture.path.join("old-directory")).unwrap();
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(pinned.verify(), Err(Error::UnsafeEndpoint));
    fs::remove_dir(&directory).unwrap();
    fs::rename(fixture.path.join("old-directory"), &directory).unwrap();
    endpoint.close().unwrap();
}
