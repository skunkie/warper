// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Strict command forms; errors never retain arbitrary argument text.

use std::{ffi::OsString, fmt, path::PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Help,
    Version,
    CheckConfig { path: Option<PathBuf> },
    Service(ServiceCommand),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceCommand {
    Status { json: bool },
    Up { wait: Wait },
    Down { wait: Wait },
    Routes,
    Connections,
    Logs,
    Explain,
    InstallConfig { path: Option<PathBuf> },
    Enroll { uid: Option<u32> },
    ClearOwner,
    Recover { inspect: bool },
}

/// Client observation policy; dropping observation never cancels accepted work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Wait {
    None,
    Milliseconds(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Usage,
    MissingConfigPath,
    DuplicateConfig,
    InvalidConfigPath,
    InvalidWait,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Usage => "use a documented command form; run warper --help",
            Self::MissingConfigPath => {
                "provide PATH after --config; prefix leading-hyphen filenames with ./"
            }
            Self::DuplicateConfig => "provide --config only once",
            Self::InvalidConfigPath => {
                "configuration path must be nonempty and contain no NUL bytes"
            }
            Self::InvalidWait => "provide one positive integer after --wait-ms, or use --no-wait",
        })
    }
}

impl std::error::Error for Error {}

pub fn parse(args: &[OsString]) -> Result<Command, Error> {
    let Some((first, rest)) = args.split_first() else {
        return Ok(Command::Service(ServiceCommand::Status { json: false }));
    };
    match first.to_str() {
        Some("--help" | "-h") if rest.is_empty() => Ok(Command::Help),
        Some("--version" | "-V") if rest.is_empty() => Ok(Command::Version),
        Some("check-config") if single_flag(rest, "--help") || single_flag(rest, "-h") => {
            Ok(Command::Help)
        }
        Some("check-config") => Ok(Command::CheckConfig {
            path: config_path(rest)?,
        }),
        Some("status" | "routes" | "connections")
            if rest.is_empty() || single_flag(rest, "--json") =>
        {
            let command = match first.to_str() {
                Some("routes") => ServiceCommand::Routes,
                Some("connections") => ServiceCommand::Connections,
                _ => ServiceCommand::Status {
                    json: !rest.is_empty(),
                },
            };
            Ok(Command::Service(command))
        }
        Some("up" | "down") => {
            let wait = wait_options(rest)?;
            Ok(Command::Service(if first == "up" {
                ServiceCommand::Up { wait }
            } else {
                ServiceCommand::Down { wait }
            }))
        }
        Some("logs") if rest.is_empty() || single_flag(rest, "--follow") => {
            Ok(Command::Service(ServiceCommand::Logs))
        }
        Some("recover") if rest.is_empty() || single_flag(rest, "--inspect") => {
            Ok(Command::Service(ServiceCommand::Recover {
                inspect: !rest.is_empty(),
            }))
        }
        Some("explain")
            if (rest.len() == 1 || (rest.len() == 2 && rest[1] == "--json"))
                && !rest[0].is_empty()
                && !rest[0].as_encoded_bytes().starts_with(b"-") =>
        {
            Ok(Command::Service(ServiceCommand::Explain))
        }
        Some("owner") if single_flag(rest, "clear") => {
            Ok(Command::Service(ServiceCommand::ClearOwner))
        }
        Some("owner") if rest.first().is_some_and(|arg| arg == "enroll") => {
            let uid = match &rest[1..] {
                [] => None,
                [flag, uid] if flag == "--uid" => Some(parse_uid(uid)?),
                _ => return Err(Error::Usage),
            };
            Ok(Command::Service(ServiceCommand::Enroll { uid }))
        }
        Some("config") if rest.first().is_some_and(|arg| arg == "install") => {
            Ok(Command::Service(ServiceCommand::InstallConfig {
                path: config_path(&rest[1..])?,
            }))
        }
        _ => Err(Error::Usage),
    }
}

fn parse_uid(value: &std::ffi::OsStr) -> Result<u32, Error> {
    let value = value.to_str().ok_or(Error::Usage)?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::Usage);
    }
    value
        .parse::<u32>()
        .ok()
        .filter(|uid| *uid != u32::MAX)
        .ok_or(Error::Usage)
}

fn single_flag(args: &[OsString], flag: &str) -> bool {
    args.len() == 1 && args[0] == flag
}

fn config_path(args: &[OsString]) -> Result<Option<PathBuf>, Error> {
    let mut path = None;
    let mut arguments = args.iter();
    while let Some(argument) = arguments.next() {
        if argument != "--config" {
            return Err(Error::Usage);
        }
        if path.is_some() {
            return Err(Error::DuplicateConfig);
        }
        let value = arguments.next().ok_or(Error::MissingConfigPath)?;
        if value.as_encoded_bytes().starts_with(b"-") {
            return Err(Error::MissingConfigPath);
        }
        if value.is_empty() || value.as_encoded_bytes().contains(&0) {
            return Err(Error::InvalidConfigPath);
        }
        path = Some(PathBuf::from(value));
    }
    Ok(path)
}

fn wait_options(args: &[OsString]) -> Result<Wait, Error> {
    if args.is_empty() {
        return Ok(Wait::Milliseconds(30_000));
    }
    if single_flag(args, "--no-wait") {
        return Ok(Wait::None);
    }
    if args.len() == 2 && args[0] == "--wait-ms" {
        if let Some(value) = args[1].to_str()
            && !value.is_empty()
            && value.bytes().all(|byte| byte.is_ascii_digit())
            && value.parse::<u64>().is_ok_and(|value| value > 0)
        {
            return Ok(Wait::Milliseconds(
                value.parse().map_err(|_| Error::InvalidWait)?,
            ));
        }
        return Err(Error::InvalidWait);
    }
    Err(Error::Usage)
}
