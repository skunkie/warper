// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Native entropy, without a configured seed or a weaker fallback.

use std::{fmt, io};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Unavailable(io::ErrorKind),
    Incomplete,
    UnsupportedPlatform,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable(_) => "Entropy: native randomness is unavailable",
            Self::Incomplete => "Entropy: native randomness returned an incomplete seed",
            Self::UnsupportedPlatform => {
                "UnsupportedIntegration: native stack entropy is unavailable"
            }
        })
    }
}
impl std::error::Error for Error {}

pub struct Seed(u64);
impl Seed {
    #[cfg(target_os = "linux")]
    pub fn generate() -> Result<Self, Error> {
        read_seed(|bytes| {
            rustix::rand::getrandom(bytes, rustix::rand::GetRandomFlags::NONBLOCK)
                .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()).kind())
        })
    }
    #[cfg(not(target_os = "linux"))]
    pub fn generate() -> Result<Self, Error> {
        Err(Error::UnsupportedPlatform)
    }
    pub(crate) fn into_raw(self) -> u64 {
        self.0
    }
    #[cfg(test)]
    pub(crate) fn fixture() -> Self {
        Self(91)
    }
}
impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(<redacted>)")
    }
}
#[cfg(any(target_os = "linux", test))]
fn read_seed(
    fill: impl FnOnce(&mut [u8; 8]) -> Result<usize, io::ErrorKind>,
) -> Result<Seed, Error> {
    let mut bytes = [0; 8];
    let length = fill(&mut bytes).map_err(Error::Unavailable)?;
    if length != bytes.len() {
        return Err(Error::Incomplete);
    }
    Ok(Seed(u64::from_ne_bytes(bytes)))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_seed_errors_are_typed_and_never_fall_back() {
        assert!(matches!(
            read_seed(|_| Err(io::ErrorKind::WouldBlock)),
            Err(Error::Unavailable(io::ErrorKind::WouldBlock))
        ));
        assert!(matches!(read_seed(|_| Ok(7)), Err(Error::Incomplete)));
        let seed = read_seed(|bytes| {
            bytes.fill(3);
            Ok(8)
        })
        .unwrap();
        assert_eq!(format!("{seed:?}"), "Seed(<redacted>)");
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn native_linux_entropy_can_prepare_a_stack_seed() {
        Seed::generate().unwrap();
    }
}
