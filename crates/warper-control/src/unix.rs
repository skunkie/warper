// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Kernel credential boundary. No payload is read, written, or authenticated
//! here; protected listener paths and a versioned protocol remain separate gates.

use std::os::unix::net::UnixStream;

use crate::{Access, Error, OwnerPolicy, PeerCredentials, Role, require_service};

pub fn authenticate_client(
    stream: &UnixStream,
    policy: &OwnerPolicy,
    access: Access,
) -> Result<Role, Error> {
    let peer = peer_credentials(stream)?;
    policy.authorize(&peer, access)
}

/// Required before credential material is sent, alongside trusted receiver
/// namespace/protected endpoint verification and protocol negotiation. This is
/// not a complete service handshake or a proof of initial-namespace host root.
pub fn authenticate_service(stream: &UnixStream) -> Result<(), Error> {
    let peer = peer_credentials(stream)?;
    require_service(&peer)
}

#[cfg(target_os = "linux")]
pub fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials, Error> {
    use std::os::fd::AsRawFd;

    use nix::sys::socket::{
        AddressFamily, SockType, SockaddrLike, SockaddrStorage, getsockname, getsockopt, sockopt,
    };

    crate::namespace::require_initial_user_namespace()?;
    let socket_type = getsockopt(stream, sockopt::SockType).map_err(credential_error)?;
    let address: SockaddrStorage = getsockname(stream.as_raw_fd()).map_err(credential_error)?;
    if socket_type != SockType::Stream || address.family() != Some(AddressFamily::Unix) {
        return Err(Error::InvalidTransport);
    }
    stream
        .peer_addr()
        .map_err(|error| Error::PeerCredentials(error.kind()))?;
    let credentials = getsockopt(stream, sockopt::PeerCredentials).map_err(credential_error)?;
    let uid = credentials.uid();
    if uid == u32::MAX {
        return Err(Error::InvalidIdentity);
    }
    Ok(PeerCredentials { uid })
}

#[cfg(not(target_os = "linux"))]
pub fn peer_credentials(_stream: &UnixStream) -> Result<PeerCredentials, Error> {
    // UID-only authorization cannot satisfy ADR 0005 on macOS.
    Err(Error::UnsupportedIntegration)
}

#[cfg(target_os = "linux")]
fn credential_error(error: nix::errno::Errno) -> Error {
    Error::PeerCredentials(std::io::Error::from_raw_os_error(error as i32).kind())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_pair_credentials_authorize_the_owner_and_verify_the_service_side() {
        let (client, service) = UnixStream::pair().unwrap();
        let uid = nix::unistd::geteuid().as_raw();
        assert_eq!(peer_credentials(&client).unwrap().uid(), uid);
        assert_eq!(peer_credentials(&service).unwrap().uid(), uid);
        let policy = OwnerPolicy::new(Some(uid)).unwrap();
        let expected = if uid == 0 {
            Role::Administrator
        } else {
            Role::Owner
        };
        for access in [Access::Observe, Access::Operate] {
            assert_eq!(authenticate_client(&service, &policy, access), Ok(expected));
        }
        let expected_admin = if uid == 0 {
            Ok(Role::Administrator)
        } else {
            Err(Error::PermissionDenied)
        };
        assert_eq!(
            authenticate_client(&service, &policy, Access::Administer),
            expected_admin
        );
        let expected_service = if uid == 0 {
            Ok(())
        } else {
            Err(Error::PermissionDenied)
        };
        assert_eq!(authenticate_service(&client), expected_service);
        let foreign_uid = if uid == 1234 { 4321 } else { 1234 };
        let policy = OwnerPolicy::new(Some(foreign_uid)).unwrap();
        assert_eq!(
            authenticate_client(&service, &policy, Access::Observe),
            if uid == 0 {
                Ok(Role::Administrator)
            } else {
                Err(Error::PermissionDenied)
            }
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptors_that_are_not_connected_unix_streams_fail_closed() {
        use std::os::{fd::OwnedFd, unix::net::UnixDatagram};

        let datagram: OwnedFd = UnixDatagram::unbound().unwrap().into();
        let stream = UnixStream::from(datagram);
        assert!(matches!(
            peer_credentials(&stream),
            Err(Error::InvalidTransport)
        ));
        let (read, write) = nix::unistd::pipe().unwrap();
        let stream = UnixStream::from(read);
        assert!(matches!(
            peer_credentials(&stream),
            Err(Error::PeerCredentials(_))
        ));
        drop(write);
        let socket = nix::sys::socket::socket(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::Stream,
            nix::sys::socket::SockFlag::SOCK_CLOEXEC,
            None,
        )
        .unwrap();
        let stream = UnixStream::from(socket);
        assert!(matches!(
            peer_credentials(&stream),
            Err(Error::PeerCredentials(std::io::ErrorKind::NotConnected))
        ));
        let socket = nix::sys::socket::socket(
            nix::sys::socket::AddressFamily::Inet,
            nix::sys::socket::SockType::Stream,
            nix::sys::socket::SockFlag::SOCK_CLOEXEC,
            None,
        )
        .unwrap();
        let stream = UnixStream::from(socket);
        assert!(matches!(
            peer_credentials(&stream),
            Err(Error::InvalidTransport)
        ));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn uid_only_adapter_is_unavailable_on_other_unix_platforms() {
        let (client, service) = UnixStream::pair().unwrap();
        let policy = OwnerPolicy::new(None).unwrap();
        assert!(matches!(
            peer_credentials(&service),
            Err(Error::UnsupportedIntegration)
        ));
        assert_eq!(
            authenticate_client(&service, &policy, Access::Observe),
            Err(Error::UnsupportedIntegration)
        );
        assert_eq!(
            authenticate_service(&client),
            Err(Error::UnsupportedIntegration)
        );
    }
}
