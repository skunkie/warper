// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::{
    Error, MTU, RecordedOwner,
    capture::{MAX_PREFIXES, Plan, Prefix},
};
use std::{fmt, net::Ipv4Addr};

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
    Addressing = 7,
    Addressed = 8,
    Enabling = 9,
    Enabled = 10,
    Routing = 11,
    Captured = 12,
    RoutesRetiring = 13,
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
    pub(super) address: Option<Ipv4Addr>,
    pub(super) capture: Option<Plan>,
}
impl Record {
    pub(super) fn encode(&self) -> Vec<u8> {
        let count = self.capture.as_ref().map_or(0, |plan| plan.prefixes.len());
        let mut bytes = vec![0; LENGTH + 8 * count];
        bytes[..4].copy_from_slice(b"WTUN");
        bytes[4..8].copy_from_slice(&4u32.to_be_bytes());
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
        if let Some(address) = self.address {
            bytes[136..140].copy_from_slice(&address.octets());
        }
        if let Some(plan) = &self.capture {
            bytes[140..142].copy_from_slice(&(count as u16).to_be_bytes());
            bytes[144..148].copy_from_slice(&plan.metric.to_be_bytes());
            for (prefix, entry) in plan
                .prefixes
                .iter()
                .zip(bytes[LENGTH..].as_chunks_mut::<8>().0.iter_mut())
            {
                entry[..4].copy_from_slice(&prefix.network.octets());
                entry[4] = prefix.length;
            }
        }
        bytes
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < LENGTH
            || bytes.len() > LENGTH + 8 * MAX_PREFIXES
            || &bytes[..4] != b"WTUN"
            || !matches!(
                &bytes[4..8],
                [0, 0, 0, 1] | [0, 0, 0, 2] | [0, 0, 0, 3] | [0, 0, 0, 4]
            )
            || bytes[97] != 0
            || bytes[98..100] != MTU.to_be_bytes()
            || (bytes[4..8] != 4u32.to_be_bytes()
                && (bytes.len() != LENGTH || bytes[140..LENGTH] != [0; 20]))
            || bytes[142..144] != [0; 2]
            || bytes[148..LENGTH] != [0; 12]
            || (bytes[4..8] == 1u32.to_be_bytes() && bytes[136..140] != [0; 4])
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
            7 if bytes[4..8] != 1u32.to_be_bytes() => Stage::Addressing,
            8 if bytes[4..8] != 1u32.to_be_bytes() => Stage::Addressed,
            9 if matches!(&bytes[4..8], [0, 0, 0, 3] | [0, 0, 0, 4]) => Stage::Enabling,
            10 if matches!(&bytes[4..8], [0, 0, 0, 3] | [0, 0, 0, 4]) => Stage::Enabled,
            11 if bytes[4..8] == 4u32.to_be_bytes() => Stage::Routing,
            12 if bytes[4..8] == 4u32.to_be_bytes() => Stage::Captured,
            13 if bytes[4..8] == 4u32.to_be_bytes() => Stage::RoutesRetiring,
            _ => return Err(Error::InvalidRecord),
        };
        let count = usize::from(u16::from_be_bytes([bytes[140], bytes[141]]));
        if count > MAX_PREFIXES || bytes.len() != LENGTH + 8 * count {
            return Err(Error::InvalidRecord);
        }
        let metric = u32::from_be_bytes([bytes[144], bytes[145], bytes[146], bytes[147]]);
        let capture = if count == 0 {
            if metric != 0 {
                return Err(Error::InvalidRecord);
            }
            None
        } else {
            let mut prefixes = Vec::with_capacity(count);
            for entry in bytes[LENGTH..].as_chunks::<8>().0 {
                if entry[5..] != [0; 3] {
                    return Err(Error::InvalidRecord);
                }
                prefixes.push(Prefix {
                    network: Ipv4Addr::new(entry[0], entry[1], entry[2], entry[3]),
                    length: entry[4],
                });
            }
            let plan = Plan { prefixes, metric };
            plan.validate().map_err(|_| Error::InvalidRecord)?;
            Some(plan)
        };
        if (matches!(
            stage,
            Stage::Routing | Stage::Captured | Stage::RoutesRetiring
        ) && capture.is_none())
            || (!matches!(
                stage,
                Stage::Routing
                    | Stage::Captured
                    | Stage::RoutesRetiring
                    | Stage::Retiring
                    | Stage::Retired
            ) && capture.is_some())
        {
            return Err(Error::InvalidRecord);
        }
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
        let address = if bytes[136..140] == [0; 4] {
            None
        } else {
            Some(Ipv4Addr::new(
                bytes[136], bytes[137], bytes[138], bytes[139],
            ))
        };
        if (capture.is_some() && (address.is_none() || identity.is_none()))
            || address.is_some_and(|address| !valid_address(address))
            || (matches!(
                stage,
                Stage::Prepared | Stage::Allocated | Stage::Renaming | Stage::Named
            ) && address.is_some())
            || (matches!(
                stage,
                Stage::Addressing
                    | Stage::Addressed
                    | Stage::Enabling
                    | Stage::Enabled
                    | Stage::Routing
                    | Stage::Captured
                    | Stage::RoutesRetiring
            ) && (address.is_none() || identity.is_none()))
        {
            return Err(Error::InvalidRecord);
        }
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
            address,
            capture,
        })
    }
}
pub(super) fn valid_address(address: Ipv4Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && !address.is_broadcast()
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
            Stage::Addressing,
            Stage::Addressed,
            Stage::Enabling,
            Stage::Enabled,
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
                address: matches!(
                    stage,
                    Stage::Addressing | Stage::Addressed | Stage::Enabling | Stage::Enabled
                )
                .then_some(Ipv4Addr::new(198, 18, 0, 9)),
                capture: None,
            };
            let decoded = Record::decode(&record.encode()).unwrap();
            assert_eq!(decoded.stage, stage);
            assert_eq!(decoded.requested, record.requested);
            assert_eq!(decoded.identity, record.identity);
            assert_eq!(decoded.address, record.address);
        }
    }
    #[test]
    fn legacy_retired_records_remain_readable_and_address_states_fail_closed() {
        let mut record = Record {
            owner: owner(),
            stage: Stage::Retired,
            requested: None,
            identity: Some(Identity {
                name: "warper-test".into(),
                index: 9,
            }),
            address: None,
            capture: None,
        };
        let mut legacy = record.encode();
        legacy[4..8].copy_from_slice(&1u32.to_be_bytes());
        assert_eq!(Record::decode(&legacy).unwrap().stage, Stage::Retired);
        legacy[136] = 198;
        assert!(matches!(Record::decode(&legacy), Err(Error::InvalidRecord)));
        record.stage = Stage::Addressed;
        assert!(matches!(
            Record::decode(&record.encode()),
            Err(Error::InvalidRecord)
        ));
        for address in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
        ] {
            record.address = Some(address);
            assert!(matches!(
                Record::decode(&record.encode()),
                Err(Error::InvalidRecord)
            ));
        }
        record.address = Some(Ipv4Addr::new(198, 18, 0, 9));
        assert_eq!(
            Record::decode(&record.encode()).unwrap().address,
            record.address
        );
        let mut version_two = record.encode();
        version_two[4..8].copy_from_slice(&2u32.to_be_bytes());
        assert_eq!(
            Record::decode(&version_two).unwrap().stage,
            Stage::Addressed
        );
        version_two[96] = Stage::Enabled as u8;
        assert!(matches!(
            Record::decode(&version_two),
            Err(Error::InvalidRecord)
        ));
        record.stage = Stage::Enabled;
        assert_eq!(
            Record::decode(&record.encode()).unwrap().stage,
            Stage::Enabled
        );
        record.identity = None;
        assert!(matches!(
            Record::decode(&record.encode()),
            Err(Error::InvalidRecord)
        ));
        record.stage = Stage::Prepared;
        assert!(matches!(
            Record::decode(&record.encode()),
            Err(Error::InvalidRecord)
        ));
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
            address: None,
            capture: None,
        };
        let bytes = record.encode();
        let mut extra = bytes.to_vec();
        extra.push(0);
        assert!(matches!(Record::decode(&extra), Err(Error::InvalidRecord)));
        let mut changed = bytes.clone();
        changed[132..136].fill(0);
        assert!(matches!(
            Record::decode(&changed),
            Err(Error::InvalidRecord)
        ));
        let mut changed = bytes.clone();
        changed[132..136].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            Record::decode(&changed),
            Err(Error::InvalidRecord)
        ));
        let mut changed = bytes.clone();
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
    fn capture_records_round_trip_and_reject_incomplete_or_ambiguous_batches() {
        let mut record = Record {
            owner: owner(),
            stage: Stage::Routing,
            requested: None,
            identity: Some(Identity {
                name: "warper-test".into(),
                index: 9,
            }),
            address: Some(Ipv4Addr::new(198, 18, 0, 1)),
            capture: Some(Plan {
                prefixes: vec![Prefix {
                    network: Ipv4Addr::new(198, 18, 0, 2),
                    length: 32,
                }],
                metric: 0x80000001,
            }),
        };
        for stage in [
            Stage::Routing,
            Stage::Captured,
            Stage::RoutesRetiring,
            Stage::Retiring,
            Stage::Retired,
        ] {
            record.stage = stage;
            let bytes = record.encode();
            assert_eq!(bytes.len(), LENGTH + 8);
            let decoded = Record::decode(&bytes).unwrap();
            assert_eq!(decoded.stage, stage);
            assert!(decoded.capture == record.capture);
        }
        record.stage = Stage::Captured;
        let bytes = record.encode();
        for end in 0..bytes.len() {
            assert!(matches!(
                Record::decode(&bytes[..end]),
                Err(Error::InvalidRecord)
            ));
        }
        for (offset, value) in [
            (7, 3),
            (96, Stage::Enabled as u8),
            (141, 2),
            (142, 1),
            (144, 0),
            (148, 1),
            (164, 33),
            (165, 1),
        ] {
            let mut changed = bytes.clone();
            changed[offset] = value;
            assert!(
                matches!(Record::decode(&changed), Err(Error::InvalidRecord)),
                "invalid field {offset}"
            );
        }
        record.capture.as_mut().unwrap().prefixes = (0..MAX_PREFIXES)
            .map(|index| Prefix {
                network: Ipv4Addr::from(0xc6120000 + index as u32),
                length: 32,
            })
            .collect();
        let bytes = record.encode();
        assert_eq!(bytes.len(), 32928);
        assert!(Record::decode(&bytes).is_ok());
        record.capture.as_mut().unwrap().prefixes.reverse();
        assert!(matches!(
            Record::decode(&record.encode()),
            Err(Error::InvalidRecord)
        ));
        record.capture = None;
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
            address: None,
            capture: None,
        };
        let bytes = record.encode();
        for end in 0..LENGTH {
            assert!(matches!(
                Record::decode(&bytes[..end]),
                Err(Error::InvalidRecord)
            ));
        }
        for (offset, value) in [(0, 0), (7, 0), (96, 0), (97, 1), (98, 0), (140, 1)] {
            let mut changed = bytes.clone();
            changed[offset] = value;
            assert!(matches!(
                Record::decode(&changed),
                Err(Error::InvalidRecord)
            ));
        }
        let mut changed = bytes.clone();
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
        let mut changed = bytes.clone();
        changed[100..104].copy_from_slice(b"x\0y\0");
        assert!(matches!(
            Record::decode(&changed),
            Err(Error::InvalidRecord)
        ));
    }
}
