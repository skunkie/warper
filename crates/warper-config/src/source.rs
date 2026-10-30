// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded source-file loading for ordinary-user offline diagnostics/import.
//! This does not implement credential-file ownership, permission, or size rules.

use std::{fmt, path::Path};

#[cfg(any(unix, test))]
use std::io::{self, Read};

#[cfg(any(unix, test))]
use crate::yaml::MAX_SOURCE_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    NotFound,
    PermissionDenied,
    Open,
    Metadata,
    NotRegular,
    Read,
    TooLarge,
    UnsupportedPlatform,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotFound => "configuration source was not found; check --config",
            Self::PermissionDenied => "configuration source is not readable by this account",
            Self::Open => "cannot open configuration source",
            Self::Metadata => "cannot inspect the opened configuration source",
            Self::NotRegular => "configuration source must be a regular file",
            Self::Read => "cannot read configuration source",
            Self::TooLarge => "configuration source exceeds 1 MiB",
            Self::UnsupportedPlatform => "source loading is unavailable on this platform",
        })
    }
}

impl std::error::Error for Error {}

/// Inspect the opened descriptor, then bound reads even if metadata is stale.
/// A leading symlink is allowed; no credential/trust files are opened here.
#[cfg(unix)]
pub fn read_source(path: &Path) -> Result<Vec<u8>, Error> {
    use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
        .open(path)
        .map_err(open_error)?;
    let metadata = file.metadata().map_err(|_| Error::Metadata)?;
    if !metadata.is_file() {
        return Err(Error::NotRegular);
    }
    if metadata.len() > MAX_SOURCE_BYTES as u64 {
        return Err(Error::TooLarge);
    }
    read_bounded(file)
}

#[cfg(not(unix))]
pub fn read_source(_path: &Path) -> Result<Vec<u8>, Error> {
    Err(Error::UnsupportedPlatform)
}

#[cfg(any(unix, test))]
fn open_error(error: io::Error) -> Error {
    match error.kind() {
        io::ErrorKind::NotFound => Error::NotFound,
        io::ErrorKind::PermissionDenied => Error::PermissionDenied,
        _ => Error::Open,
    }
}

#[cfg(any(unix, test))]
fn read_bounded(reader: impl io::Read) -> Result<Vec<u8>, Error> {
    let mut source = Vec::new();
    reader
        .take(MAX_SOURCE_BYTES as u64 + 1)
        .read_to_end(&mut source)
        .map_err(|_| Error::Read)?;
    if source.len() > MAX_SOURCE_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(source)
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::{
        fs,
        os::unix::fs::DirBuilderExt,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    #[cfg(unix)]
    struct TestDirectory {
        path: PathBuf,
    }

    #[cfg(unix)]
    impl TestDirectory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            for _ in 0..128 {
                let id = NEXT.fetch_add(1, Ordering::Relaxed);
                let path =
                    std::env::temp_dir().join(format!("warper-source-{}-{id}", std::process::id()));
                match fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => return Self { path },
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("create controlled source directory: {error}"),
                }
            }
            panic!("no unused controlled source directory found");
        }
    }

    #[cfg(unix)]
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).expect("remove owned source fixtures");
        }
    }

    #[test]
    fn bounded_reader_accepts_exact_limit_and_rejects_growth_and_read_failure() {
        assert_eq!(
            read_bounded(io::repeat(b'a').take(MAX_SOURCE_BYTES as u64))
                .unwrap()
                .len(),
            MAX_SOURCE_BYTES
        );
        assert_eq!(read_bounded(io::repeat(b'a')), Err(Error::TooLarge));
        struct FailedReader;
        impl io::Read for FailedReader {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::PermissionDenied.into())
            }
        }
        assert_eq!(read_bounded(FailedReader), Err(Error::Read));
        for (kind, expected) in [
            (io::ErrorKind::NotFound, Error::NotFound),
            (io::ErrorKind::PermissionDenied, Error::PermissionDenied),
            (io::ErrorKind::InvalidInput, Error::Open),
        ] {
            assert_eq!(open_error(kind.into()), expected);
        }
    }

    #[cfg(unix)]
    #[test]
    fn source_reader_checks_opened_files_and_allows_source_symlinks() {
        let directory = TestDirectory::new();
        let path = directory.path.join("source.yaml");
        fs::write(&path, b"sample").unwrap();
        assert_eq!(read_source(&path).unwrap(), b"sample");
        let link = directory.path.join("link.yaml");
        std::os::unix::fs::symlink("source.yaml", &link).unwrap();
        assert_eq!(read_source(&link).unwrap(), b"sample");
        assert_eq!(read_source(&directory.path), Err(Error::NotRegular));
        assert_eq!(
            read_source(&directory.path.join("missing.yaml")),
            Err(Error::NotFound)
        );
        let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(MAX_SOURCE_BYTES as u64 + 1).unwrap();
        drop(file);
        assert_eq!(read_source(&path), Err(Error::TooLarge));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_fifo_is_rejected_without_waiting_for_a_writer() {
        use std::{
            fs::OpenOptions, os::unix::fs::OpenOptionsExt, sync::mpsc, thread, time::Duration,
        };

        let directory = TestDirectory::new();
        let path = directory.path.join("source.fifo");
        nix::unistd::mkfifo(
            &path,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        let worker_path = path.clone();
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            sender.send(read_source(&worker_path)).unwrap();
        });
        let early = receiver.recv_timeout(Duration::from_secs(2));
        // Rescue a regressed blocking open so the worker is always joined before
        // asserting the timeout. Dropping the rescue descriptor also supplies EOF
        // if a regression removes the regular-file guard as well.
        if matches!(early, Err(mpsc::RecvTimeoutError::Timeout)) {
            let rescue = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
                .open(&path)
                .unwrap();
            drop(rescue);
        }
        worker.join().unwrap();
        assert_eq!(
            early.expect("source open must complete without a FIFO writer"),
            Err(Error::NotRegular)
        );
    }
}
