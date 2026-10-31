// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Current-thread namespace admission. No caller-supplied procfs path or cached
//! namespace token can bypass the native peer-credential check.

use crate::Error;

/// Require the initial Linux user namespace before interpreting kernel peer UIDs.
/// Missing kernel/procfs capabilities fail closed. This does not admit socket
/// paths, owner records, mount/network namespaces, or privileged operations.
#[cfg(target_os = "linux")]
pub fn require_initial_user_namespace() -> Result<(), Error> {
    use rustix::fs::{Mode, OFlags, open};

    let proc = open(
        "/proc",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(inspection_error)?;
    inspect_proc(&proc)
}

#[cfg(not(target_os = "linux"))]
pub fn require_initial_user_namespace() -> Result<(), Error> {
    Err(Error::UnsupportedIntegration)
}

#[cfg(target_os = "linux")]
fn inspect_proc(proc: &impl std::os::fd::AsFd) -> Result<(), Error> {
    use rustix::fs::{
        FileType, Mode, OFlags, PROC_SUPER_MAGIC, ResolveFlags, fstat, fstatfs, openat2,
        readlinkat_raw,
    };

    if fstatfs(proc).map_err(inspection_error)?.f_type as rustix::fs::FsWord != PROC_SUPER_MAGIC {
        return Err(Error::InvalidNamespaceEvidence);
    }
    let directory = fstat(proc).map_err(inspection_error)?;
    if FileType::from_raw_mode(directory.st_mode) != FileType::Directory {
        return Err(Error::InvalidNamespaceEvidence);
    }
    // O_PATH|NOFOLLOW intentionally opens the final magic link itself. All
    // preceding lookup remains beneath real procfs, without submounts or magic
    // link traversal. readlinkat("", fd) then reads that same checked link.
    let link = openat2(
        proc,
        "thread-self/ns/user",
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_XDEV | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(inspection_error)?;
    let metadata = fstat(&link).map_err(inspection_error)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Symlink
        || metadata.st_dev != directory.st_dev
        || fstatfs(&link).map_err(inspection_error)?.f_type as rustix::fs::FsWord
            != PROC_SUPER_MAGIC
    {
        return Err(Error::InvalidNamespaceEvidence);
    }
    let mut target = [0; 64];
    let count = readlinkat_raw(&link, "", &mut target).map_err(inspection_error)?;
    if count == target.len() {
        return Err(Error::InvalidNamespaceEvidence);
    }
    classify_link(&target[..count])
}

#[cfg(any(target_os = "linux", test))]
fn classify_link(target: &[u8]) -> Result<(), Error> {
    // Linux PROC_USER_INIT_INO / USER_NS_INIT_INO = 0xEFFFFFFD. This reserved
    // identifier is also used by systemd; unknown identifiers fail closed.
    if target == b"user:[4026531837]" {
        return Ok(());
    }
    let valid = target
        .strip_prefix(b"user:[")
        .and_then(|value| value.strip_suffix(b"]"))
        .is_some_and(|value| !value.is_empty() && value.iter().all(u8::is_ascii_digit));
    if valid {
        Err(Error::UntrustedNamespace)
    } else {
        Err(Error::InvalidNamespaceEvidence)
    }
}

#[cfg(target_os = "linux")]
fn inspection_error(error: rustix::io::Errno) -> Error {
    if error == rustix::io::Errno::NOSYS {
        return Error::UnsupportedIntegration;
    }
    Error::NamespaceInspection(std::io::Error::from_raw_os_error(error.raw_os_error()).kind())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_identifiers_accept_only_the_initial_user_namespace() {
        assert_eq!(classify_link(b"user:[4026531837]"), Ok(()));
        for value in [
            b"user:[0]".as_slice(),
            b"user:[4026531838]",
            b"user:[18446744073709551615]",
        ] {
            assert_eq!(classify_link(value), Err(Error::UntrustedNamespace));
        }
        for value in [
            b"".as_slice(),
            b"pid:[4026531837]",
            b"user:[4026531837]\n",
            b"user:[04026531837]garbage",
            b"user:[]",
            b"user:[-1]",
            b"user:[sample-secret]",
        ] {
            assert_eq!(classify_link(value), Err(Error::InvalidNamespaceEvidence));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn namespace_probe_rejects_non_procfs_descriptors_and_keeps_error_kinds() {
        let directory = std::fs::File::open(".").unwrap();
        assert_eq!(
            inspect_proc(&directory),
            Err(Error::InvalidNamespaceEvidence)
        );
        assert_eq!(
            inspection_error(rustix::io::Errno::NOSYS),
            Error::UnsupportedIntegration
        );
        assert_eq!(
            inspection_error(rustix::io::Errno::ACCESS),
            Error::NamespaceInspection(std::io::ErrorKind::PermissionDenied)
        );
    }
}
