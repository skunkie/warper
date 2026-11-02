// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Fixed recovery intent. Invalid or legacy data never grants unlink authority.

use super::Error;
use rustix::fs::{FileType, Stat};

pub(super) const LENGTH: usize = 160;

// Access time is excluded: inspection must not invalidate owned state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Identity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    changed: i64,
    changed_ns: u64,
    modified: i64,
    modified_ns: u64,
    size: i64,
}
impl Identity {
    pub(super) fn of(stat: &Stat) -> Self {
        Self {
            dev: stat.st_dev,
            ino: stat.st_ino,
            uid: stat.st_uid,
            gid: stat.st_gid,
            mode: stat.st_mode,
            links: link_count(stat.st_nlink),
            changed: stat.st_ctime,
            changed_ns: stat.st_ctime_nsec,
            modified: stat.st_mtime,
            modified_ns: stat.st_mtime_nsec,
            size: stat.st_size,
        }
    }
    pub(super) fn valid_socket(self, owner: u32) -> bool {
        FileType::from_raw_mode(self.mode) == FileType::Socket
            && self.ino != 0
            && self.uid == owner
            && self.gid != u32::MAX
            && self.mode & 0o7777 == 0o666
            && self.links == 1
            && self.size >= 0
            && (0..1_000_000_000).contains(&self.changed_ns)
            && (0..1_000_000_000).contains(&self.modified_ns)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Record {
    lock_dev: u64,
    lock_ino: u64,
    pub(super) socket: Option<Identity>,
}
impl Record {
    pub(super) fn prepared(lock: &Stat) -> Self {
        Self {
            lock_dev: lock.st_dev,
            lock_ino: lock.st_ino,
            socket: None,
        }
    }
    pub(super) fn matches_lock(self, lock: &Stat) -> bool {
        self.lock_dev == lock.st_dev && self.lock_ino == lock.st_ino
    }
    pub(super) fn encode(self) -> [u8; LENGTH] {
        let mut bytes = [0; LENGTH];
        bytes[..4].copy_from_slice(b"WCTL");
        bytes[4..8].copy_from_slice(&1u32.to_be_bytes());
        bytes[16..24].copy_from_slice(&self.lock_dev.to_be_bytes());
        bytes[24..32].copy_from_slice(&self.lock_ino.to_be_bytes());
        if let Some(socket) = self.socket {
            bytes[8] = 1;
            bytes[32..40].copy_from_slice(&socket.dev.to_be_bytes());
            bytes[40..48].copy_from_slice(&socket.ino.to_be_bytes());
            bytes[48..52].copy_from_slice(&socket.uid.to_be_bytes());
            bytes[52..56].copy_from_slice(&socket.gid.to_be_bytes());
            bytes[56..60].copy_from_slice(&socket.mode.to_be_bytes());
            bytes[64..72].copy_from_slice(&socket.links.to_be_bytes());
            bytes[72..80].copy_from_slice(&socket.changed.to_be_bytes());
            bytes[80..88].copy_from_slice(&socket.changed_ns.to_be_bytes());
            bytes[88..96].copy_from_slice(&socket.modified.to_be_bytes());
            bytes[96..104].copy_from_slice(&socket.modified_ns.to_be_bytes());
            bytes[104..112].copy_from_slice(&socket.size.to_be_bytes());
        }
        bytes
    }
    pub(super) fn decode(bytes: &[u8], owner: u32) -> Result<Self, Error> {
        if bytes.len() != LENGTH
            || bytes[..4] != *b"WCTL"
            || bytes[4..8] != 1u32.to_be_bytes()
            || bytes[8] > 1
            || bytes[9..16].iter().any(|byte| *byte != 0)
            || bytes[60..64].iter().any(|byte| *byte != 0)
            || bytes[112..].iter().any(|byte| *byte != 0)
        {
            return Err(Error::RecoveryRequired);
        }
        let number = |start| -> Result<u64, Error> {
            Ok(u64::from_be_bytes(
                bytes[start..start + 8]
                    .try_into()
                    .map_err(|_| Error::RecoveryRequired)?,
            ))
        };
        let word = |start| -> Result<u32, Error> {
            Ok(u32::from_be_bytes(
                bytes[start..start + 4]
                    .try_into()
                    .map_err(|_| Error::RecoveryRequired)?,
            ))
        };
        let socket = if bytes[8] == 0 {
            if bytes[32..].iter().any(|byte| *byte != 0) {
                return Err(Error::RecoveryRequired);
            }
            None
        } else {
            let socket = Identity {
                dev: number(32)?,
                ino: number(40)?,
                uid: word(48)?,
                gid: word(52)?,
                mode: word(56)?,
                links: number(64)?,
                changed: number(72)? as i64,
                changed_ns: number(80)?,
                modified: number(88)? as i64,
                modified_ns: number(96)?,
                size: number(104)? as i64,
            };
            if !socket.valid_socket(owner) {
                return Err(Error::RecoveryRequired);
            }
            Some(socket)
        };
        let record = Self {
            lock_dev: number(16)?,
            lock_ino: number(24)?,
            socket,
        };
        if record.lock_ino == 0 {
            return Err(Error::RecoveryRequired);
        }
        Ok(record)
    }
}

// Linux stat link-count width differs between supported architectures.
fn link_count(value: impl Into<u64>) -> u64 {
    value.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{named, tests::Fixture};
    use std::{
        fs,
        os::unix::{fs::PermissionsExt, net::UnixListener},
    };

    #[test]
    fn fixed_intent_rejects_truncation_reserved_fields_and_invalid_socket_ownership() {
        let fixture = Fixture::new();
        let lease = fixture.acquire().unwrap();
        let path = fixture.path.join("run/warper/record.sock");
        let _socket = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        let mut record = Record::prepared(&fstat_lock(&lease));
        let prepared = record.encode();
        assert_eq!(Record::decode(&prepared, fixture.owner), Ok(record));
        record.socket = Some(Identity::of(
            &named(&lease.directory, "record.sock").unwrap(),
        ));
        let bound = record.encode();
        assert_eq!(Record::decode(&bound, fixture.owner), Ok(record));
        for length in 0..LENGTH {
            assert_eq!(
                Record::decode(&bound[..length], fixture.owner),
                Err(Error::RecoveryRequired)
            );
        }
        let mut trailing = bound.to_vec();
        trailing.push(0);
        assert_eq!(
            Record::decode(&trailing, fixture.owner),
            Err(Error::RecoveryRequired)
        );
        for index in [0, 4, 8, 9, 60, 112] {
            let mut invalid = bound;
            invalid[index] ^= 1;
            assert_eq!(
                Record::decode(&invalid, fixture.owner),
                Err(Error::RecoveryRequired),
                "offset {index}"
            );
        }
        for (start, value) in [
            (24, 0u64),
            (40, 0),
            (64, 2),
            (80, 1_000_000_000),
            (96, u64::MAX),
        ] {
            let mut invalid = bound;
            invalid[start..start + 8].copy_from_slice(&value.to_be_bytes());
            assert_eq!(
                Record::decode(&invalid, fixture.owner),
                Err(Error::RecoveryRequired),
                "offset {start}"
            );
        }
        let mut invalid = bound;
        invalid[48..52].copy_from_slice(&fixture.owner.wrapping_add(1).to_be_bytes());
        assert_eq!(
            Record::decode(&invalid, fixture.owner),
            Err(Error::RecoveryRequired)
        );
        let mut invalid = prepared;
        invalid[32] = 1;
        assert_eq!(
            Record::decode(&invalid, fixture.owner),
            Err(Error::RecoveryRequired)
        );
    }
    fn fstat_lock(lease: &crate::runtime::RuntimeLease) -> Stat {
        rustix::fs::fstat(&lease.lock).unwrap()
    }
}
