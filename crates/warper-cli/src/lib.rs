// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Thin offline CLI flow. Service control remains explicitly unavailable.

use std::{
    ffi::OsString,
    fmt,
    io::{self, Write},
    path::{Path, PathBuf},
};

use warper_config::{
    schema::{self, Config, Platform},
    source,
};
use warper_core::configuration::paths::{self, IdentityProvider, Paths, invoking_account};

pub mod args;

use args::{Command, ServiceCommand};

pub const HELP: &str = "warper — selective tunnel client\n\nUsage:\n  warper check-config [--config PATH]\n  warper --help\n  warper --version\n\ncheck-config validates offline without opening credential/trust files.\nService control commands are unavailable in this build.\n";
pub const VERSION: &str = concat!("warper ", env!("CARGO_PKG_VERSION"), "\n");

pub struct SudoIdentity {
    pub uid: Option<OsString>,
    pub user: Option<OsString>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvironmentError {
    WorkingDirectory,
}

/// Passed explicitly so offline tests never depend on the developer's account,
/// resolver, HOME, working directory, or process-global environment mutations.
pub trait Environment: IdentityProvider {
    fn original_cwd(&self) -> Result<PathBuf, EnvironmentError>;
    fn sudo_identity(&self) -> SudoIdentity;
    fn platform(&self) -> Option<Platform>;
}

pub trait SourceReader {
    fn read(&mut self, path: &Path) -> Result<Vec<u8>, source::Error>;
}

pub struct FileSource;

impl SourceReader for FileSource {
    fn read(&mut self, path: &Path) -> Result<Vec<u8>, source::Error> {
        source::read_source(path)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Output {
    Help,
    Version,
    ConfigValid,
}

#[derive(Debug)]
pub enum Error {
    Arguments(args::Error),
    Identity(paths::Error),
    SudoEncoding,
    Environment(EnvironmentError),
    Paths(paths::Error),
    Source(source::Error),
    Config(schema::Error),
    UnsupportedCapability(ServiceCommand),
    UnsupportedPlatform,
    Output(io::ErrorKind),
}

impl Error {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Arguments(_) | Self::SudoEncoding | Self::Config(_) => 2,
            Self::Identity(paths::Error::InconsistentSudoIdentity) => 2,
            Self::Paths(
                paths::Error::InvalidAccount
                | paths::Error::RelativeWorkingDirectory
                | paths::Error::IdentityLookup,
            ) => 1,
            Self::Paths(_) => 2,
            Self::Source(source::Error::UnsupportedPlatform) => 1,
            Self::Source(_) => 2,
            _ => 1,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arguments(error) => write!(formatter, "InvalidArguments: {error}"),
            Self::Identity(error) => write!(formatter, "InvokingIdentity: {error}"),
            Self::SudoEncoding => {
                formatter.write_str("InvokingIdentity: elevated sudo identity fields must be UTF-8")
            }
            Self::Environment(_) => {
                formatter.write_str("Environment: cannot determine the original working directory")
            }
            Self::Paths(error) => write!(formatter, "ConfigurationPath: {error}"),
            Self::Source(error @ source::Error::TooLarge) => {
                write!(formatter, "ResourceLimit at --config: {error}")
            }
            Self::Source(source::Error::UnsupportedPlatform) => formatter.write_str(
                "UnsupportedIntegration: source loading is unavailable on this platform",
            ),
            Self::Source(error) => write!(formatter, "ConfigurationSource at --config: {error}"),
            Self::Config(error) => fmt::Display::fmt(error, formatter),
            Self::UnsupportedCapability(_) => formatter.write_str(
                "UnsupportedCapability: service control is not implemented in this build",
            ),
            Self::UnsupportedPlatform => formatter.write_str(
                "UnsupportedIntegration: offline source loading supports Linux and macOS",
            ),
            Self::Output(_) => formatter.write_str("Output: cannot write command result"),
        }
    }
}

impl std::error::Error for Error {}

pub fn execute(
    command: Command,
    environment: &impl Environment,
    source: &mut impl SourceReader,
) -> Result<Output, Error> {
    let config_path = match command {
        Command::Help => return Ok(Output::Help),
        Command::Version => return Ok(Output::Version),
        Command::Service(command) => return Err(Error::UnsupportedCapability(command)),
        Command::CheckConfig { path } => path,
    };
    let platform = environment.platform().ok_or(Error::UnsupportedPlatform)?;
    let cwd = environment.original_cwd().map_err(Error::Environment)?;
    let account = if environment.effective_uid() == 0 {
        let sudo = environment.sudo_identity();
        let uid = sudo
            .uid
            .as_deref()
            .map(|value| value.to_str().ok_or(Error::SudoEncoding))
            .transpose()?;
        let user = sudo
            .user
            .as_deref()
            .map(|value| value.to_str().ok_or(Error::SudoEncoding))
            .transpose()?;
        invoking_account(environment, uid, user)
    } else {
        invoking_account(environment, None, None)
    }
    .map_err(Error::Identity)?;
    let paths =
        Paths::with_config_path(&account, &cwd, config_path.as_deref()).map_err(Error::Paths)?;
    let bytes = source.read(paths.config_file()).map_err(Error::Source)?;
    Config::parse(&bytes, &paths, platform).map_err(Error::Config)?;
    Ok(Output::ConfigValid)
}

pub fn write_output(output: Output, stdout: &mut impl Write) -> Result<(), Error> {
    let text = match output {
        Output::Help => HELP,
        Output::Version => VERSION,
        Output::ConfigValid => "Configuration is valid (offline).\n",
    };
    stdout
        .write_all(text.as_bytes())
        .map_err(|error| Error::Output(error.kind()))
}

#[derive(Debug)]
pub struct Failure {
    pub primary: Error,
    pub diagnostic: Option<io::ErrorKind>,
}

impl Failure {
    pub fn exit_code(&self) -> u8 {
        self.primary.exit_code()
    }
}

/// If stderr is unavailable, retain the primary error and exit classification.
pub fn report_error(primary: Error, stderr: &mut impl Write) -> Failure {
    let diagnostic = writeln!(stderr, "{primary}")
        .err()
        .map(|error| error.kind());
    Failure {
        primary,
        diagnostic,
    }
}

#[cfg(unix)]
pub fn run_native(command: Command) -> Result<Output, Error> {
    execute(command, &NativeEnvironment, &mut FileSource)
}

#[cfg(not(unix))]
pub fn run_native(command: Command) -> Result<Output, Error> {
    match command {
        Command::Help => Ok(Output::Help),
        Command::Version => Ok(Output::Version),
        Command::Service(command) => Err(Error::UnsupportedCapability(command)),
        Command::CheckConfig { .. } => Err(Error::UnsupportedPlatform),
    }
}

#[cfg(unix)]
struct NativeEnvironment;

#[cfg(unix)]
impl IdentityProvider for NativeEnvironment {
    fn effective_uid(&self) -> u32 {
        warper_config::identity::UnixIdentity.effective_uid()
    }
    fn account_by_uid(&self, uid: u32) -> Result<paths::Account, paths::Error> {
        warper_config::identity::UnixIdentity.account_by_uid(uid)
    }
}

#[cfg(unix)]
impl Environment for NativeEnvironment {
    fn original_cwd(&self) -> Result<PathBuf, EnvironmentError> {
        std::env::current_dir().map_err(|_| EnvironmentError::WorkingDirectory)
    }
    fn sudo_identity(&self) -> SudoIdentity {
        SudoIdentity {
            uid: std::env::var_os("SUDO_UID"),
            user: std::env::var_os("SUDO_USER"),
        }
    }
    fn platform(&self) -> Option<Platform> {
        if cfg!(target_os = "linux") {
            Some(Platform::Linux)
        } else if cfg!(target_os = "macos") {
            Some(Platform::MacOs)
        } else {
            None
        }
    }
}
