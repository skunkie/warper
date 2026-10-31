// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Local-control authorization primitives, not a running control service.
//! Owner UIDs must come from protected service state, never request payloads.
//! Linux UID authorization does not satisfy macOS code-identity requirements.
//! UID snapshots are admitted only in the initial Linux user namespace. The
//! adapter repeats that check before creating a credential snapshot. Protected
//! endpoints, enrollment and versioned messaging are still separate gates.

use std::{fmt, io};

pub mod namespace;
#[cfg(target_os = "linux")]
pub mod runtime;
#[cfg(unix)]
pub mod unix;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Access {
    Observe,
    Operate,
    Administer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Owner,
    Administrator,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidOwner,
    InvalidTransport,
    PeerCredentials(io::ErrorKind),
    InvalidIdentity,
    PermissionDenied,
    UnsupportedIntegration,
    NamespaceInspection(io::ErrorKind),
    InvalidNamespaceEvidence,
    UntrustedNamespace,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOwner => "InvalidConfig: enrolled owner must not use the reserved UID value",
            Self::InvalidTransport => "PermissionDenied: peer authentication requires a connected Unix stream",
            Self::PeerCredentials(_) => "Authentication: cannot obtain kernel peer credentials",
            Self::InvalidIdentity => "PermissionDenied: kernel peer UID is invalid",
            Self::PermissionDenied => "PermissionDenied: peer is not authorized for this operation",
            Self::UnsupportedIntegration => "UnsupportedIntegration: native control identity verification is unavailable in this environment",
            Self::NamespaceInspection(_) => "Authentication: cannot inspect trusted user-namespace evidence",
            Self::InvalidNamespaceEvidence => "Authentication: user-namespace evidence is not a verified procfs namespace link",
            Self::UntrustedNamespace => "UnsupportedIntegration: control authentication requires the initial Linux user namespace",
        })
    }
}

impl std::error::Error for Error {}

/// A kernel credential snapshot. No public constructor or deserializer accepts
/// a caller's claimed identity. It is not a liveness or signing-identity proof.
///
/// ```compile_fail
/// use warper_control::PeerCredentials;
/// let claimed_root = PeerCredentials { uid: 0 };
/// ```
pub struct PeerCredentials {
    uid: u32,
}

impl PeerCredentials {
    pub fn uid(&self) -> u32 {
        self.uid
    }
}

impl fmt::Debug for PeerCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerCredentials(<redacted>)")
    }
}

/// Immutable Linux access policy supplied by a trusted service-state loader.
/// Construction neither enrolls an owner nor verifies persistent storage.
/// Consumers must use native authentication, which enforces namespace admission:
///
/// ```compile_fail
/// use warper_control::{Access, OwnerPolicy, PeerCredentials};
/// fn bypass(policy: &OwnerPolicy, peer: &PeerCredentials) {
///     let _ = policy.authorize(peer, Access::Administer);
/// }
/// ```
pub struct OwnerPolicy {
    owner: Option<u32>,
}

impl OwnerPolicy {
    pub fn new(enrolled_owner: Option<u32>) -> Result<Self, Error> {
        if enrolled_owner == Some(u32::MAX) {
            return Err(Error::InvalidOwner);
        }
        Ok(Self {
            owner: enrolled_owner,
        })
    }

    pub(crate) fn authorize(&self, peer: &PeerCredentials, access: Access) -> Result<Role, Error> {
        if peer.uid == u32::MAX {
            return Err(Error::InvalidIdentity);
        }
        if peer.uid == 0 {
            return Ok(Role::Administrator);
        }
        if self.owner == Some(peer.uid) && access != Access::Administer {
            return Ok(Role::Owner);
        }
        Err(Error::PermissionDenied)
    }
}

impl fmt::Debug for OwnerPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnerPolicy(<redacted>)")
    }
}

#[cfg(any(unix, test))]
fn require_service(peer: &PeerCredentials) -> Result<(), Error> {
    if peer.uid == u32::MAX {
        return Err(Error::InvalidIdentity);
    }
    if peer.uid != 0 {
        return Err(Error::PermissionDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_and_root_authorization_fails_closed_for_every_access_class() {
        struct Case {
            id: &'static str,
            access: Access,
            owner: Option<u32>,
            peer_uid: u32,
            expected: Result<Role, Error>,
        }
        let cases = [
            Case {
                id: "owner observes",
                access: Access::Observe,
                owner: Some(1234),
                peer_uid: 1234,
                expected: Ok(Role::Owner),
            },
            Case {
                id: "owner controls",
                access: Access::Operate,
                owner: Some(1234),
                peer_uid: 1234,
                expected: Ok(Role::Owner),
            },
            Case {
                id: "owner cannot administer",
                access: Access::Administer,
                owner: Some(1234),
                peer_uid: 1234,
                expected: Err(Error::PermissionDenied),
            },
            Case {
                id: "foreign cannot observe",
                access: Access::Observe,
                owner: Some(1234),
                peer_uid: 4321,
                expected: Err(Error::PermissionDenied),
            },
            Case {
                id: "foreign cannot control",
                access: Access::Operate,
                owner: Some(1234),
                peer_uid: 4321,
                expected: Err(Error::PermissionDenied),
            },
            Case {
                id: "foreign cannot administer",
                access: Access::Administer,
                owner: Some(1234),
                peer_uid: 4321,
                expected: Err(Error::PermissionDenied),
            },
            Case {
                id: "unenrolled cannot observe",
                access: Access::Observe,
                owner: None,
                peer_uid: 1234,
                expected: Err(Error::PermissionDenied),
            },
            Case {
                id: "unenrolled cannot control",
                access: Access::Operate,
                owner: None,
                peer_uid: 1234,
                expected: Err(Error::PermissionDenied),
            },
            Case {
                id: "unenrolled cannot self-enroll",
                access: Access::Administer,
                owner: None,
                peer_uid: 1234,
                expected: Err(Error::PermissionDenied),
            },
            Case {
                id: "root observes",
                access: Access::Observe,
                owner: Some(1234),
                peer_uid: 0,
                expected: Ok(Role::Administrator),
            },
            Case {
                id: "root controls",
                access: Access::Operate,
                owner: Some(1234),
                peer_uid: 0,
                expected: Ok(Role::Administrator),
            },
            Case {
                id: "root administers",
                access: Access::Administer,
                owner: Some(1234),
                peer_uid: 0,
                expected: Ok(Role::Administrator),
            },
            Case {
                id: "root bootstrap",
                access: Access::Administer,
                owner: None,
                peer_uid: 0,
                expected: Ok(Role::Administrator),
            },
            Case {
                id: "reserved peer UID",
                access: Access::Observe,
                owner: Some(1234),
                peer_uid: u32::MAX,
                expected: Err(Error::InvalidIdentity),
            },
        ];
        for case in cases {
            let policy = OwnerPolicy::new(case.owner).unwrap();
            let peer = PeerCredentials { uid: case.peer_uid };
            assert_eq!(
                policy.authorize(&peer, case.access),
                case.expected,
                "{}",
                case.id
            );
            assert!(
                !format!("{policy:?} {peer:?}").contains("1234"),
                "{}",
                case.id
            );
        }
        assert!(matches!(
            OwnerPolicy::new(Some(u32::MAX)),
            Err(Error::InvalidOwner)
        ));
        let peer = PeerCredentials { uid: u32::MAX - 1 };
        let policy = OwnerPolicy::new(Some(peer.uid())).unwrap();
        assert_eq!(policy.authorize(&peer, Access::Observe), Ok(Role::Owner));
        assert_eq!(
            policy.authorize(&peer, Access::Administer),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn service_verification_requires_root_without_exposing_identity_values() {
        assert_eq!(require_service(&PeerCredentials { uid: 0 }), Ok(()));
        assert_eq!(
            require_service(&PeerCredentials { uid: 1234 }),
            Err(Error::PermissionDenied)
        );
        assert_eq!(
            require_service(&PeerCredentials { uid: u32::MAX }),
            Err(Error::InvalidIdentity)
        );
        for error in [
            Error::InvalidOwner,
            Error::InvalidTransport,
            Error::PeerCredentials(io::ErrorKind::NotConnected),
            Error::InvalidIdentity,
            Error::PermissionDenied,
            Error::UnsupportedIntegration,
        ] {
            assert!(!error.to_string().contains("1234"));
        }
    }
}
