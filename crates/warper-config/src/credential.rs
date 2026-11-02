// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Ordinary-client secret import. Never call with privileged RPC file paths.
//! File I/O is synchronous; callers retain and join their blocking workers.

use std::{fmt, io};

use crate::schema::Secret;

pub const MAX_SECRET_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Open(io::ErrorKind),
    Metadata(io::ErrorKind),
    Read(io::ErrorKind),
    NotRegular,
    ForeignOwner,
    UnsafePermissions,
    Changed,
    TooLarge,
    InvalidUtf8,
    Empty,
    UnsupportedPlatform,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Open(_) => "InvalidConfig: cannot open credential file",
            Self::Metadata(_) => "InvalidConfig: cannot inspect credential file",
            Self::Read(_) => "InvalidConfig: cannot read credential file",
            Self::NotRegular => "InvalidConfig: credential file must be regular",
            Self::ForeignOwner => {
                "InvalidConfig: credential file must belong to this account or root"
            }
            Self::UnsafePermissions => {
                "InvalidConfig: credential file permits group or other access"
            }
            Self::Changed => "Conflict: credential file changed during import",
            Self::TooLarge => "ResourceLimit: credential file exceeds 16 KiB",
            Self::InvalidUtf8 => "InvalidConfig: credential file must contain UTF-8",
            Self::Empty => "InvalidConfig: credential file must not be empty",
            Self::UnsupportedPlatform => {
                "UnsupportedCapability: credential file import is unavailable"
            }
        })
    }
}

impl std::error::Error for Error {}

/// Open first, then validate and read the same descriptor. Symlinks are allowed;
/// changing their target cannot redirect this already opened read. No path or
/// contents are included in diagnostics. This does not authorize installation.
#[cfg(unix)]
pub fn read_secret(path: &std::path::Path) -> Result<Secret<String>, Error> {
    use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
        .open(path)
        .map_err(|error| Error::Open(error.kind()))?;
    let before = file
        .metadata()
        .map_err(|error| Error::Metadata(error.kind()))?;
    validate_metadata(&before, nix::unistd::geteuid().as_raw())?;
    let bytes = read_bounded(&file)?;
    let after = file
        .metadata()
        .map_err(|error| Error::Metadata(error.kind()))?;
    verify_unchanged(&before, &after)?;
    decode(bytes)
}

#[cfg(not(unix))]
pub fn read_secret(_path: &std::path::Path) -> Result<Secret<String>, Error> {
    Err(Error::UnsupportedPlatform)
}

#[cfg(unix)]
fn validate_metadata(metadata: &std::fs::Metadata, owner: u32) -> Result<(), Error> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.is_file() {
        return Err(Error::NotRegular);
    }
    if metadata.uid() != owner && metadata.uid() != 0 {
        return Err(Error::ForeignOwner);
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(Error::UnsafePermissions);
    }
    if metadata.len() > MAX_SECRET_BYTES as u64 {
        return Err(Error::TooLarge);
    }
    Ok(())
}

#[cfg(unix)]
fn verify_unchanged(before: &std::fs::Metadata, after: &std::fs::Metadata) -> Result<(), Error> {
    use std::os::unix::fs::MetadataExt;

    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.uid() != after.uid()
        || before.gid() != after.gid()
        || before.mode() != after.mode()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(Error::Changed);
    }
    Ok(())
}

#[cfg(any(unix, test))]
fn read_bounded(reader: impl io::Read) -> Result<Vec<u8>, Error> {
    use io::Read;

    let mut bytes = Vec::new();
    reader
        .take(MAX_SECRET_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| Error::Read(error.kind()))?;
    if bytes.len() > MAX_SECRET_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(bytes)
}

#[cfg(any(unix, test))]
fn decode(mut bytes: Vec<u8>) -> Result<Secret<String>, Error> {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    let text = String::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
    if text.is_empty() {
        return Err(Error::Empty);
    }
    Ok(Secret::new(text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn secret_import_removes_exactly_one_line_ending_and_preserves_other_characters() {
        struct Case {
            id: &'static str,
            sample: &'static [u8],
            expected: Result<&'static str, Error>,
        }
        for case in [
            Case {
                id: "plain_unicode",
                sample: "秘密-test".as_bytes(),
                expected: Ok("秘密-test"),
            },
            Case {
                id: "lf",
                sample: b"sample\n",
                expected: Ok("sample"),
            },
            Case {
                id: "crlf",
                sample: b"sample\r\n",
                expected: Ok("sample"),
            },
            Case {
                id: "two_lines",
                sample: b"sample\n\n",
                expected: Ok("sample\n"),
            },
            Case {
                id: "preserve_cr",
                sample: b"sample\r",
                expected: Ok("sample\r"),
            },
            Case {
                id: "preserve_spaces",
                sample: b"  sample \n",
                expected: Ok("  sample "),
            },
            Case {
                id: "empty",
                sample: b"",
                expected: Err(Error::Empty),
            },
            Case {
                id: "empty_lf",
                sample: b"\n",
                expected: Err(Error::Empty),
            },
            Case {
                id: "empty_crlf",
                sample: b"\r\n",
                expected: Err(Error::Empty),
            },
            Case {
                id: "invalid_utf8",
                sample: b"\xff\n",
                expected: Err(Error::InvalidUtf8),
            },
        ] {
            let result = decode(case.sample.to_vec());
            assert_eq!(
                result
                    .as_ref()
                    .map(|secret| secret.expose().as_str())
                    .map_err(|error| *error),
                case.expected,
                "{}",
                case.id
            );
            if let Ok(secret) = result {
                assert_eq!(format!("{secret:?}"), "<redacted>");
            }
        }
    }

    #[test]
    fn bounded_secret_reads_reject_growth_and_io_errors() {
        assert_eq!(
            read_bounded(io::repeat(b'x').take(MAX_SECRET_BYTES as u64))
                .unwrap()
                .len(),
            MAX_SECRET_BYTES
        );
        assert_eq!(read_bounded(io::repeat(b'x')), Err(Error::TooLarge));
        struct FailedReader;
        impl io::Read for FailedReader {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::Other.into())
            }
        }
        assert_eq!(
            read_bounded(FailedReader),
            Err(Error::Read(io::ErrorKind::Other))
        );
    }

    #[cfg(unix)]
    mod files {
        use super::*;
        use std::{
            fs,
            os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink},
            path::PathBuf,
            sync::atomic::{AtomicU64, Ordering},
        };

        struct Fixture(PathBuf);
        impl Fixture {
            fn new() -> Self {
                static NEXT: AtomicU64 = AtomicU64::new(0);
                for _ in 0..128 {
                    let path = std::env::temp_dir().join(format!(
                        "warper-secret-{}-{}",
                        std::process::id(),
                        NEXT.fetch_add(1, Ordering::Relaxed)
                    ));
                    match fs::DirBuilder::new().mode(0o700).create(&path) {
                        Ok(()) => return Self(path),
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                        Err(error) => panic!("create secret fixture: {error}"),
                    }
                }
                panic!("secret fixture names exhausted");
            }
            fn secret(&self, name: &str, bytes: &[u8]) -> PathBuf {
                use io::Write;
                let path = self.0.join(name);
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .unwrap();
                file.write_all(bytes).unwrap();
                path
            }
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                fs::remove_dir_all(&self.0).unwrap();
            }
        }

        #[test]
        fn secret_file_checks_permissions_type_symlinks_and_size_before_import() {
            let fixture = Fixture::new();
            let path = fixture.secret("secret", b"sample-password\r\n");
            assert_eq!(read_secret(&path).unwrap().expose(), "sample-password");
            let alias = fixture.0.join("alias");
            symlink(&path, &alias).unwrap();
            assert_eq!(read_secret(&alias).unwrap().expose(), "sample-password");
            for mode in [0o640, 0o604, 0o610, 0o601] {
                fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
                assert_eq!(read_secret(&path).unwrap_err(), Error::UnsafePermissions);
            }
            assert_eq!(read_secret(&fixture.0).unwrap_err(), Error::NotRegular);
            let fifo = fixture.0.join("fifo");
            nix::unistd::mkfifo(
                &fifo,
                nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
            )
            .unwrap();
            assert_eq!(read_secret(&fifo).unwrap_err(), Error::NotRegular);
            assert_eq!(
                read_secret(&fixture.0.join("absent")).unwrap_err(),
                Error::Open(io::ErrorKind::NotFound)
            );
            let exact = fixture.secret("exact", &vec![b'x'; MAX_SECRET_BYTES]);
            assert_eq!(
                read_secret(&exact).unwrap().expose().len(),
                MAX_SECRET_BYTES
            );
            let oversized = fixture.secret("oversized", &vec![b'x'; MAX_SECRET_BYTES + 1]);
            assert_eq!(read_secret(&oversized).unwrap_err(), Error::TooLarge);
        }

        #[test]
        fn changed_opened_secret_metadata_is_rejected_without_modifying_the_file() {
            let fixture = Fixture::new();
            let path = fixture.secret("secret", b"sample");
            let before = fs::metadata(&path).unwrap();
            verify_unchanged(&before, &before).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
            assert_eq!(
                verify_unchanged(&before, &fs::metadata(&path).unwrap()),
                Err(Error::Changed)
            );
            assert_eq!(fs::read(&path).unwrap(), b"sample");
            fs::write(&path, b"sample changed").unwrap();
            assert_eq!(
                verify_unchanged(&before, &fs::metadata(&path).unwrap()),
                Err(Error::Changed)
            );
            use std::os::unix::fs::MetadataExt;
            if before.uid() != 0 {
                assert_eq!(
                    validate_metadata(&before, before.uid().wrapping_add(1)),
                    Err(Error::ForeignOwner)
                );
            }
        }
    }
}
