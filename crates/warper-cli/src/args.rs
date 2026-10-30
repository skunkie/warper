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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceCommand {
    Status,
    Up,
    Down,
    Routes,
    Connections,
    Logs,
    Explain,
    InstallConfig,
    Recover,
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
        return Ok(Command::Service(ServiceCommand::Status));
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
                _ => ServiceCommand::Status,
            };
            Ok(Command::Service(command))
        }
        Some("up" | "down") => {
            wait_options(rest)?;
            Ok(Command::Service(if first == "up" {
                ServiceCommand::Up
            } else {
                ServiceCommand::Down
            }))
        }
        Some("logs") if rest.is_empty() || single_flag(rest, "--follow") => {
            Ok(Command::Service(ServiceCommand::Logs))
        }
        Some("recover") if rest.is_empty() || single_flag(rest, "--inspect") => {
            Ok(Command::Service(ServiceCommand::Recover))
        }
        Some("explain")
            if (rest.len() == 1 || (rest.len() == 2 && rest[1] == "--json"))
                && !rest[0].is_empty()
                && !rest[0].as_encoded_bytes().starts_with(b"-") =>
        {
            Ok(Command::Service(ServiceCommand::Explain))
        }
        Some("config") if rest.first().is_some_and(|arg| arg == "install") => {
            config_path(&rest[1..])?;
            Ok(Command::Service(ServiceCommand::InstallConfig))
        }
        _ => Err(Error::Usage),
    }
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

fn wait_options(args: &[OsString]) -> Result<(), Error> {
    if args.is_empty() || single_flag(args, "--no-wait") {
        return Ok(());
    }
    if args.len() == 2 && args[0] == "--wait-ms" {
        if let Some(value) = args[1].to_str()
            && !value.is_empty()
            && value.bytes().all(|byte| byte.is_ascii_digit())
            && value.parse::<u64>().is_ok_and(|value| value > 0)
        {
            return Ok(());
        }
        return Err(Error::InvalidWait);
    }
    Err(Error::Usage)
}
