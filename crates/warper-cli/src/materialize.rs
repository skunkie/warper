// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Native import under the invoking account. Secret bytes only cross a pipe.

use nix::unistd::{Gid, Uid, User, getegid, geteuid, getgid, getgrouplist, getgroups, getuid};
use std::{
    ffi::{CString, OsString},
    fmt,
    io::{self, Read, Write},
    path::Path,
    process::{Command, Stdio},
};
use warper_config::{
    managed::Snapshot,
    schema::{Platform, Secret},
    source,
};

const HEADER: usize = 12;
const MAX: usize = 1_048_576;

#[derive(Debug)]
pub enum Error {
    PermissionDenied,
    Identity,
    UnsafeChild,
    Source,
    Schema,
    Credential,
    TooLarge,
    Unsupported,
    ChildFailed,
    Io(io::ErrorKind),
    Cleanup {
        primary: Box<Error>,
        kill: Option<io::ErrorKind>,
        reap: io::ErrorKind,
    },
}
impl Error {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Source | Self::Schema | Self::Credential | Self::TooLarge => 2,
            Self::Cleanup { primary, .. } => primary.exit_code(),
            _ => 1,
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PermissionDenied => "PermissionDenied: administrative command requires explicit OS elevation",
            Self::Identity => "InvokingIdentity: cannot resolve import account and primary group",
            Self::UnsafeChild => "Authentication: import child identity or private pipe is invalid",
            Self::Source => "ConfigurationSource: invoking account cannot read the selected YAML source",
            Self::Schema => "InvalidConfig: managed source validation failed; use check-config for offline diagnostics",
            Self::Credential => "InvalidConfig: invoking account could not import selected credentials",
            Self::TooLarge => "ResourceLimit: managed import exceeds its bounded envelope",
            Self::Unsupported => "UnsupportedCapability: managed import currently requires SOCKS5 backends",
            Self::ChildFailed => "WorkerFailed: native configuration import child failed",
            Self::Io(_) => "NativeIo: configuration import pipe or process operation failed",
            Self::Cleanup { primary, .. } => { write!(f, "{primary}; import child cleanup also failed")?; return Ok(()); },
        })
    }
}
impl std::error::Error for Error {}
fn io_error(error: io::Error) -> Error {
    Error::Io(error.kind())
}

pub(crate) fn require_admin() -> Result<(), crate::Error> {
    if !geteuid().is_root() {
        return Err(crate::Error::Import(Error::PermissionDenied));
    }
    Ok(())
}
pub(crate) fn owner_uid(uid: Option<u32>) -> Result<u32, crate::Error> {
    require_admin()?;
    let uid = match uid {
        Some(uid) => uid,
        None => crate::invoking_identity(&crate::NativeEnvironment)?.uid,
    };
    if uid == u32::MAX {
        return Err(crate::Error::Import(Error::Identity));
    }
    Ok(uid)
}

/// Materialize under the validated invoking account. The calling executable
/// must dispatch its private `--native-materialize` entry point to [`child`].
pub fn prepare(path: Option<&Path>) -> Result<Secret<Vec<u8>>, crate::Error> {
    require_admin()?;
    let account = crate::invoking_identity(&crate::NativeEnvironment)?;
    let user = User::from_uid(Uid::from_raw(account.uid))
        .map_err(|_| crate::Error::Import(Error::Identity))?
        .filter(|user| user.name == account.name && user.dir == account.home)
        .ok_or(crate::Error::Import(Error::Identity))?;
    let executable =
        std::env::current_exe().map_err(|error| crate::Error::Import(io_error(error)))?;
    let mut command = Command::new("/usr/bin/setpriv");
    command
        .arg("--reuid")
        .arg(account.uid.to_string())
        .arg("--regid")
        .arg(user.gid.as_raw().to_string())
        .arg("--init-groups")
        .arg("--no-new-privs");
    if account.uid != 0 {
        command.args([
            "--ambient-caps=-all",
            "--inh-caps=-all",
            "--bounding-set=-all",
        ]);
    }
    command
        .arg("--")
        .arg(executable)
        .arg("--native-materialize")
        .arg(account.uid.to_string())
        .arg(user.gid.as_raw().to_string());
    if let Some(path) = path {
        command.arg("--config").arg(path);
    }
    // The OS helper initializes only the invoking account's normal groups and
    // drops privileges before executing our parser. No parent/thread identity
    // is changed; ordinary accounts inherit no administrative groups or caps.
    command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", profile);
    }
    collect(command).map_err(crate::Error::Import)
}
fn collect(mut command: Command) -> Result<Secret<Vec<u8>>, Error> {
    let mut child = command.spawn().map_err(io_error)?;
    let read = match child.stdout.take() {
        Some(stdout) => {
            let mut bytes = Vec::new();
            match stdout
                .take((MAX + HEADER + 1) as u64)
                .read_to_end(&mut bytes)
            {
                Ok(_) => decode(&bytes),
                Err(error) => Err(io_error(error)),
            }
        }
        None => Err(Error::UnsafeChild),
    };
    let mut secondary = None;
    if read.is_err()
        && let Err(error) = child.kill()
    {
        // A child that already exited still must be reaped below. Its exit
        // result is authoritative; an unsuccessful kill alone is not repair.
        secondary = Some(error.kind());
    }
    let waited = child.wait();
    match (read, waited) {
        (Ok(bytes), Ok(status)) if status.success() => Ok(bytes),
        (Ok(_), Ok(_)) => Err(Error::ChildFailed),
        (Ok(_), Err(error)) => Err(io_error(error)),
        (Err(primary), Ok(_)) => Err(primary),
        (Err(primary), Err(error)) => Err(Error::Cleanup {
            primary: Box::new(primary),
            kill: secondary,
            reap: error.kind(),
        }),
    }
}

/// Private executable entry point. It never emits secret material to a terminal
/// or regular output file; callers receive only the bounded pipe protocol.
pub fn child(arguments: &[OsString]) -> Result<(), crate::Error> {
    let [uid, gid, rest @ ..] = arguments else {
        return Err(crate::Error::Import(Error::UnsafeChild));
    };
    let number = |value: &OsString| {
        value
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|value| *value != u32::MAX)
            .ok_or(Error::UnsafeChild)
    };
    let uid = number(uid).map_err(crate::Error::Import)?;
    let gid = number(gid).map_err(crate::Error::Import)?;
    let stat =
        rustix::fs::fstat(io::stdout()).map_err(|_| crate::Error::Import(Error::UnsafeChild))?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Fifo {
        return Err(crate::Error::Import(Error::UnsafeChild));
    }
    let result = import(uid, gid, rest);
    let bytes = encode(result);
    io::stdout()
        .lock()
        .write_all(bytes.expose())
        .map_err(|error| crate::Error::Import(io_error(error)))
}
fn import(uid: u32, gid: u32, arguments: &[OsString]) -> Result<Secret<Vec<u8>>, Error> {
    if getuid() != Uid::from_raw(uid)
        || geteuid() != Uid::from_raw(uid)
        || getgid() != Gid::from_raw(gid)
        || getegid() != Gid::from_raw(gid)
    {
        return Err(Error::UnsafeChild);
    }
    let user = User::from_uid(Uid::from_raw(uid))
        .map_err(|_| Error::UnsafeChild)?
        .ok_or(Error::UnsafeChild)?;
    if user.gid != Gid::from_raw(gid) {
        return Err(Error::UnsafeChild);
    }
    let name = CString::new(user.name).map_err(|_| Error::UnsafeChild)?;
    let mut expected = getgrouplist(&name, Gid::from_raw(gid)).map_err(|_| Error::UnsafeChild)?;
    let mut actual = getgroups().map_err(|_| Error::UnsafeChild)?;
    expected.sort_unstable_by_key(|group| group.as_raw());
    expected.dedup();
    actual.sort_unstable_by_key(|group| group.as_raw());
    actual.dedup();
    if actual != expected {
        return Err(Error::UnsafeChild);
    }
    let mut args = vec![OsString::from("check-config")];
    args.extend_from_slice(arguments);
    let crate::args::Command::CheckConfig { path } =
        crate::args::parse(&args).map_err(|_| Error::Schema)?
    else {
        return Err(Error::Schema);
    };
    let paths = crate::resolve_paths(path.as_deref(), &crate::NativeEnvironment)
        .map_err(|_| Error::Identity)?;
    let bytes = source::read_source(paths.config_file()).map_err(|_| Error::Source)?;
    Snapshot::import(&bytes, &paths, Platform::Linux)
        .map_err(|error| match error {
            warper_config::managed::Error::Credential(_) => Error::Credential,
            warper_config::managed::Error::ResourceLimit => Error::TooLarge,
            warper_config::managed::Error::UnsupportedBackend => Error::Unsupported,
            _ => Error::Schema,
        })?
        .encode()
        .map_err(|_| Error::TooLarge)
}
struct Envelope(Vec<u8>);
impl Envelope {
    fn expose(&self) -> &[u8] {
        &self.0
    }
}
impl fmt::Debug for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ImportEnvelope(<redacted>)")
    }
}
fn encode(result: Result<Secret<Vec<u8>>, Error>) -> Envelope {
    let (status, data) = match result {
        Ok(data) => (0u16, Some(data)),
        Err(error) => (
            match error {
                Error::Source => 1,
                Error::Schema => 2,
                Error::Credential => 3,
                Error::TooLarge => 4,
                Error::Identity => 5,
                Error::Unsupported => 7,
                _ => 6,
            },
            None,
        ),
    };
    let payload = data
        .as_ref()
        .map_or(&[][..], |data| data.expose().as_slice());
    let mut bytes = Vec::with_capacity(HEADER + payload.len());
    bytes.extend_from_slice(b"WMIM");
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&status.to_be_bytes());
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    Envelope(bytes)
}
fn decode(bytes: &[u8]) -> Result<Secret<Vec<u8>>, Error> {
    if bytes.len() > MAX + HEADER {
        return Err(Error::TooLarge);
    }
    if bytes.len() < HEADER || &bytes[..4] != b"WMIM" || bytes[4..6] != 1u16.to_be_bytes() {
        return Err(Error::UnsafeChild);
    }
    let status = u16::from_be_bytes([bytes[6], bytes[7]]);
    let length =
        u32::from_be_bytes(bytes[8..12].try_into().map_err(|_| Error::UnsafeChild)?) as usize;
    if length > MAX || bytes.len() != HEADER + length {
        return Err(Error::UnsafeChild);
    }
    if status != 0 && length != 0 {
        return Err(Error::UnsafeChild);
    }
    match status {
        0 => Snapshot::decode(&bytes[HEADER..], Platform::Linux)
            .map_err(|_| Error::Schema)?
            .encode()
            .map_err(|_| Error::TooLarge),
        1 => Err(Error::Source),
        2 => Err(Error::Schema),
        3 => Err(Error::Credential),
        4 => Err(Error::TooLarge),
        5 => Err(Error::Identity),
        6 => Err(Error::UnsafeChild),
        7 => Err(Error::Unsupported),
        _ => Err(Error::UnsafeChild),
    }
}

#[cfg(test)]
mod tests;
