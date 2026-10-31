// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::{Error, MTU, RecordedOwner};
use std::fmt;

const LENGTH: usize = 160;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Stage {
    Prepared = 1,
    Allocated = 2,
    Renaming = 3,
    Named = 4,
    Retiring = 5,
    Retired = 6,
}
#[derive(Clone, Eq, PartialEq)]
pub(super) struct Identity {
    pub(super) name: String,
    pub(super) index: u32,
}
impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TunIdentity(<redacted>)")
    }
}
#[derive(Clone)]
pub(super) struct Record {
    pub(super) owner: RecordedOwner,
    pub(super) stage: Stage,
    pub(super) requested: Option<String>,
    pub(super) identity: Option<Identity>,
}
impl Record {
    pub(super) fn encode(&self) -> [u8; LENGTH] {
        let mut bytes = [0; LENGTH];
        bytes[..4].copy_from_slice(b"WTUN");
        bytes[4..8].copy_from_slice(&1u32.to_be_bytes());
        bytes[8..96].copy_from_slice(&self.owner.encode());
        bytes[96] = self.stage as u8;
        bytes[98..100].copy_from_slice(&MTU.to_be_bytes());
        if let Some(name) = &self.requested {
            bytes[100..100 + name.len()].copy_from_slice(name.as_bytes());
        }
        if let Some(identity) = &self.identity {
            bytes[116..116 + identity.name.len()].copy_from_slice(identity.name.as_bytes());
            bytes[132..136].copy_from_slice(&identity.index.to_be_bytes());
        }
        bytes
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != LENGTH
            || &bytes[..4] != b"WTUN"
            || bytes[4..8] != 1u32.to_be_bytes()
            || bytes[97] != 0
            || bytes[98..100] != MTU.to_be_bytes()
            || bytes[136..] != [0; 24]
        {
            return Err(Error::InvalidRecord);
        }
        let owner = RecordedOwner::decode(&bytes[8..96]).map_err(|_| Error::InvalidRecord)?;
        let stage = match bytes[96] {
            1 => Stage::Prepared,
            2 => Stage::Allocated,
            3 => Stage::Renaming,
            4 => Stage::Named,
            5 => Stage::Retiring,
            6 => Stage::Retired,
            _ => return Err(Error::InvalidRecord),
        };
        let requested = parse_name(&bytes[100..116])?;
        let actual = parse_name(&bytes[116..132])?;
        let index = u32::from_be_bytes(
            bytes[132..136]
                .try_into()
                .map_err(|_| Error::InvalidRecord)?,
        );
        let identity = match (actual, index) {
            (None, 0) => None,
            (Some(name), index) if index > 0 && index <= i32::MAX as u32 => {
                Some(Identity { name, index })
            }
            _ => return Err(Error::InvalidRecord),
        };
        if (stage == Stage::Prepared && identity.is_some())
            || (matches!(stage, Stage::Allocated | Stage::Renaming | Stage::Named)
                && identity.is_none())
            || (stage == Stage::Renaming && requested.is_none())
            || (stage == Stage::Named
                && requested.as_deref() != identity.as_ref().map(|identity| identity.name.as_str()))
        {
            return Err(Error::InvalidRecord);
        }
        Ok(Self {
            owner,
            stage,
            requested,
            identity,
        })
    }
}
pub(super) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name.is_ascii()
        && !matches!(name, "." | "..")
        && !name
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || matches!(byte, 0 | b'/' | b':'))
}
fn parse_name(bytes: &[u8]) -> Result<Option<String>, Error> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(Error::InvalidRecord)?;
    if bytes[end..].iter().any(|byte| *byte != 0) {
        return Err(Error::InvalidRecord);
    }
    if end == 0 {
        return Ok(None);
    }
    let name = std::str::from_utf8(&bytes[..end]).map_err(|_| Error::InvalidRecord)?;
    if !valid_name(name) {
        return Err(Error::InvalidRecord);
    }
    Ok(Some(name.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn owner() -> RecordedOwner {
        let mut bytes = [0; 88];
        bytes[..4].copy_from_slice(b"WNOC");
        bytes[4..8].copy_from_slice(&1u32.to_be_bytes());
        bytes[8..24].fill(1);
        bytes[32..40].copy_from_slice(&10u64.to_be_bytes());
        bytes[48..56].copy_from_slice(&11u64.to_be_bytes());
        bytes[56..72].fill(2);
        bytes[72..76].copy_from_slice(&123u32.to_be_bytes());
        RecordedOwner::decode(&bytes).unwrap()
    }
    #[test]
    fn every_reachable_lifecycle_stage_round_trips_with_bounded_identity() {
        for stage in [
            Stage::Prepared,
            Stage::Allocated,
            Stage::Renaming,
            Stage::Named,
            Stage::Retiring,
            Stage::Retired,
        ] {
            let identity = if stage == Stage::Prepared {
                None
            } else {
                Some(Identity {
                    name: "warper-test".into(),
                    index: 9,
                })
            };
            let record = Record {
                owner: owner(),
                stage,
                requested: Some("warper-test".into()),
                identity,
            };
            let decoded = Record::decode(&record.encode()).unwrap();
            assert_eq!(decoded.stage, stage);
            assert_eq!(decoded.requested, record.requested);
            assert_eq!(decoded.identity, record.identity);
        }
    }
    #[test]
    fn inconsistent_names_and_indices_cannot_become_owned_records() {
        let mut record = Record {
            owner: owner(),
            stage: Stage::Allocated,
            requested: None,
            identity: Some(Identity {
                name: "warper-test".into(),
                index: 9,
            }),
        };
        let bytes = record.encode();
        let mut extra = bytes.to_vec();
        extra.push(0);
        assert!(matches!(Record::decode(&extra), Err(Error::InvalidRecord)));
        let mut changed = bytes;
        changed[132..136].fill(0);
        assert!(matches!(
            Record::decode(&changed),
            Err(Error::InvalidRecord)
        ));
        let mut changed = bytes;
        changed[132..136].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            Record::decode(&changed),
            Err(Error::InvalidRecord)
        ));
        let mut changed = bytes;
        changed[116..132].fill(b'x');
        assert!(matches!(
            Record::decode(&changed),
            Err(Error::InvalidRecord)
        ));
        record.stage = Stage::Renaming;
        assert!(matches!(
            Record::decode(&record.encode()),
            Err(Error::InvalidRecord)
        ));
        record.stage = Stage::Named;
        record.requested = Some("another-name".into());
        assert!(matches!(
            Record::decode(&record.encode()),
            Err(Error::InvalidRecord)
        ));
    }

    #[test]
    fn malformed_and_inconsistent_native_records_require_recovery() {
        let record = Record {
            owner: owner(),
            stage: Stage::Prepared,
            requested: None,
            identity: None,
        };
        let bytes = record.encode();
        for end in 0..LENGTH {
            assert!(matches!(
                Record::decode(&bytes[..end]),
                Err(Error::InvalidRecord)
            ));
        }
        for (offset, value) in [(0, 0), (7, 0), (96, 0), (97, 1), (98, 0), (136, 1)] {
            let mut changed = bytes;
            changed[offset] = value;
            assert!(matches!(
                Record::decode(&changed),
                Err(Error::InvalidRecord)
            ));
        }
        let mut changed = bytes;
        changed[96] = Stage::Allocated as u8;
        assert!(matches!(
            Record::decode(&changed),
            Err(Error::InvalidRecord)
        ));
        for name in [
            "",
            ".",
            "..",
            "bad name",
            "bad/name",
            "bad:name",
            "1234567890123456",
            "invented-狐",
        ] {
            assert!(!valid_name(name));
        }
        let mut changed = bytes;
        changed[100..104].copy_from_slice(b"x\0y\0");
        assert!(matches!(
            Record::decode(&changed),
            Err(Error::InvalidRecord)
        ));
    }
}
