// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded native boot identity and nonblocking service-instance randomness.

use super::Error;
use rustix::fs::{FileType, Mode, OFlags, ResolveFlags, fstat, fstatfs, open, openat2};
use std::{
    fmt,
    fs::File,
    io::{self, Read},
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BootId(pub(super) [u8; 16]);
impl BootId {
    pub fn current() -> Result<Self, Error> {
        crate::namespace::require_initial_user_namespace().map_err(Error::Identity)?;
        let proc = open(
            "/proc",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(os_error)?;
        if fstatfs(&proc).map_err(os_error)?.f_type as u64 != 0x9fa0 {
            return Err(Error::InvalidBoot);
        }
        let fd = openat2(
            &proc,
            "sys/kernel/random/boot_id",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )
        .map_err(os_error)?;
        if fstatfs(&fd).map_err(os_error)?.f_type as u64 != 0x9fa0
            || FileType::from_raw_mode(fstat(&fd).map_err(os_error)?.st_mode)
                != FileType::RegularFile
        {
            return Err(Error::InvalidBoot);
        }
        let mut bytes = Vec::with_capacity(38);
        File::from(fd)
            .take(38)
            .read_to_end(&mut bytes)
            .map_err(|e| Error::Io(e.kind()))?;
        parse_boot(&bytes)
    }
    /// Serialize native boot evidence into protected platform metadata. Recorded
    /// bytes cannot construct this native-only type or bypass namespace checks.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}
impl fmt::Debug for BootId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BootId(<redacted>)")
    }
}

pub(super) fn instance() -> Result<[u8; 16], Error> {
    fill_instance(|bytes| {
        rustix::rand::getrandom(bytes, rustix::rand::GetRandomFlags::NONBLOCK)
            .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()).kind())
    })
}
fn fill_instance(
    fill: impl FnOnce(&mut [u8; 16]) -> Result<usize, io::ErrorKind>,
) -> Result<[u8; 16], Error> {
    let mut bytes = [0; 16];
    let count = fill(&mut bytes).map_err(Error::Entropy)?;
    if count != 16 || bytes.iter().all(|byte| *byte == 0) {
        return Err(Error::EntropyIncomplete);
    }
    Ok(bytes)
}
fn parse_boot(bytes: &[u8]) -> Result<BootId, Error> {
    if bytes.len() != 37 || bytes[36] != b'\n' {
        return Err(Error::InvalidBoot);
    }
    let mut id = [0u8; 16];
    let mut digit = 0;
    for (index, byte) in bytes[..36].iter().copied().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if byte != b'-' {
                return Err(Error::InvalidBoot);
            }
            continue;
        }
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => return Err(Error::InvalidBoot),
        };
        id[digit / 2] = (id[digit / 2] << 4) | nibble;
        digit += 1;
    }
    if id.iter().all(|byte| *byte == 0) {
        return Err(Error::InvalidBoot);
    }
    Ok(BootId(id))
}
fn os_error(error: rustix::io::Errno) -> Error {
    Error::Io(io::Error::from_raw_os_error(error.raw_os_error()).kind())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boot_identity_parsing_is_exact_bounded_and_redacted() {
        let sample = b"12345678-1234-1234-1234-123456789abc\n";
        let parsed = parse_boot(sample).unwrap();
        assert_eq!(format!("{parsed:?}"), "BootId(<redacted>)");
        assert_eq!(
            parsed.0,
            [
                0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78,
                0x9a, 0xbc
            ]
        );
        for bytes in [
            &sample[..36],
            b"00000000-0000-0000-0000-000000000000\n",
            b"12345678_1234-1234-1234-123456789abc\n",
            b"12345678-1234-1234-1234-123456789abC\n",
        ] {
            assert_eq!(parse_boot(bytes), Err(Error::InvalidBoot));
        }
        let mut oversized = sample.to_vec();
        oversized.push(0);
        assert_eq!(parse_boot(&oversized), Err(Error::InvalidBoot));
    }
    #[test]
    fn instance_entropy_errors_and_short_or_zero_reads_never_fall_back() {
        assert_eq!(
            fill_instance(|_| Err(io::ErrorKind::WouldBlock)),
            Err(Error::Entropy(io::ErrorKind::WouldBlock))
        );
        assert_eq!(fill_instance(|_| Ok(15)), Err(Error::EntropyIncomplete));
        assert_eq!(fill_instance(|_| Ok(16)), Err(Error::EntropyIncomplete));
        assert_eq!(
            fill_instance(|bytes| {
                bytes.fill(3);
                Ok(16)
            }),
            Ok([3; 16])
        );
    }
    #[test]
    fn native_boot_identity_is_stable_and_service_instances_are_native() {
        assert_eq!(BootId::current().unwrap(), BootId::current().unwrap());
        assert!(instance().unwrap().iter().any(|byte| *byte != 0));
    }
}
