// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Foreground privileged service entry point; clients never own networking.

use std::{
    ffi::OsString,
    fmt,
    io::{self, Write},
    process::ExitCode,
};

const HELP: &str = "warperd — selective tunnel service\n\nUsage:\n  warperd service\n  warperd --help\n  warperd --version\n\nservice runs in the foreground and requires initial-namespace root on Linux.\nDiagnostic run and offline recovery commands remain unavailable.\n";
const VERSION: &str = concat!("warperd ", env!("CARGO_PKG_VERSION"), "\n");
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Command {
    Help,
    Version,
    Service,
    Unsupported,
}
#[derive(Debug)]
enum Error {
    Usage,
    Unsupported,
    #[cfg(not(target_os = "linux"))]
    Platform,
    Io(io::ErrorKind),
    #[cfg(target_os = "linux")]
    SignalClosed,
    #[cfg(target_os = "linux")]
    Setup(warper_service::linux::daemon::Error),
    #[cfg(target_os = "linux")]
    Service(Box<warper_service::linux::daemon::Failure>),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => f.write_str("InvalidArguments: use warperd --help"),
            Self::Unsupported => {
                f.write_str("UnsupportedCapability: requested daemon command is unavailable")
            }
            #[cfg(not(target_os = "linux"))]
            Self::Platform => f.write_str("UnsupportedIntegration: native daemon supports Linux"),
            Self::Io(kind) => write!(
                f,
                "NativeIo: daemon runtime, signal or output operation failed ({kind:?})"
            ),
            #[cfg(target_os = "linux")]
            Self::SignalClosed => f.write_str("WorkerFailed: daemon signal observation stopped"),
            #[cfg(target_os = "linux")]
            Self::Setup(error) => error.fmt(f),
            #[cfg(target_os = "linux")]
            Self::Service(error) => error.fmt(f),
        }
    }
}
fn parse(args: &[OsString]) -> Result<Command, Error> {
    match args {
        [] => Ok(Command::Help),
        [arg] if arg == "--help" || arg == "-h" => Ok(Command::Help),
        [arg] if arg == "--version" || arg == "-V" => Ok(Command::Version),
        [arg] if arg == "service" => Ok(Command::Service),
        [arg] if arg == "recover" || arg == "run" => Ok(Command::Unsupported),
        [arg, inspect] if arg == "recover" && inspect == "--inspect" => Ok(Command::Unsupported),
        _ => Err(Error::Usage),
    }
}
fn execute(command: Command) -> Result<(), Error> {
    match command {
        Command::Help => io::stdout()
            .lock()
            .write_all(HELP.as_bytes())
            .map_err(|error| Error::Io(error.kind())),
        Command::Version => io::stdout()
            .lock()
            .write_all(VERSION.as_bytes())
            .map_err(|error| Error::Io(error.kind())),
        Command::Unsupported => Err(Error::Unsupported),
        Command::Service => service(),
    }
}
#[cfg(target_os = "linux")]
fn service() -> Result<(), Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| Error::Io(error.kind()))?;
    let result = runtime.block_on(async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|error| Error::Io(error.kind()))?;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .map_err(|error| Error::Io(error.kind()))?;
        let (stop, cancellation) = tokio::sync::watch::channel(false);
        let mut daemon = warper_service::linux::daemon::Daemon::new().map_err(Error::Setup)?;
        let running = daemon.run(cancellation);
        tokio::pin!(running);
        let (signal_lost, result) = tokio::select! { biased;
            result = &mut running => (false, result),
            signal = term.recv() => { stop.send_replace(true); (signal.is_none(), running.await) },
            signal = interrupt.recv() => { stop.send_replace(true); (signal.is_none(), running.await) },
        };
        result.map_err(|error| Error::Service(Box::new(error)))?;
        if signal_lost { Err(Error::SignalClosed) } else { Ok(()) }
    });
    // Native filesystem waits are not asynchronously abortable. A bounded
    // runtime stop never claims their journal/endpoint cleanup succeeded.
    runtime.shutdown_timeout(std::time::Duration::from_secs(5));
    result
}
#[cfg(not(target_os = "linux"))]
fn service() -> Result<(), Error> {
    Err(Error::Platform)
}
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match parse(&args).and_then(execute) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let code = if matches!(error, Error::Usage) { 2 } else { 1 };
            // The primary exit classification survives unavailable diagnostics.
            let _diagnostic = writeln!(io::stderr().lock(), "{error}");
            ExitCode::from(code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn command_forms_are_explicit_and_reject_unrelated_arguments() {
        for (args, expected) in [
            (vec![], Command::Help),
            (vec!["service"], Command::Service),
            (vec!["--version"], Command::Version),
            (vec!["recover", "--inspect"], Command::Unsupported),
        ] {
            assert_eq!(
                parse(&args.into_iter().map(OsString::from).collect::<Vec<_>>()).unwrap(),
                expected
            );
        }
        assert!(matches!(
            parse(&["service".into(), "sample-secret".into()]),
            Err(Error::Usage)
        ));
    }
}
