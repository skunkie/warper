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

const HELP: &str = "warperd — selective tunnel service\n\nUsage:\n  warperd service\n  warperd run [--config PATH] [--headless] [--verbose] [--debug]\n  warperd recover [--inspect]\n  warperd --help\n  warperd --version\n\nservice runs in the foreground and requires initial-namespace root on Linux.\nrecover requires the stopped service's exclusive instance lock.\nrun owns a foreground diagnostic engine; its signals stop that engine.\n";
const VERSION: &str = concat!("warperd ", env!("CARGO_PKG_VERSION"), "\n");
#[path = "warperd/diagnostic.rs"]
mod diagnostic;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Command {
    Help,
    Version,
    Service,
    Recover,
    InspectRecovery,
    Run(diagnostic::Arguments),
}
#[derive(Debug)]
enum Error {
    Usage,
    #[cfg(not(target_os = "linux"))]
    Platform,
    Io(io::ErrorKind),
    #[cfg(target_os = "linux")]
    SignalClosed,
    #[cfg(target_os = "linux")]
    SignalCleanup(Box<Error>),
    #[cfg(target_os = "linux")]
    Import(warper_cli::Error),
    #[cfg(target_os = "linux")]
    Diagnostic(warper_service::linux::diagnostic::Error),
    #[cfg(target_os = "linux")]
    Network(Box<warper_service::linux::network::Failure>),
    #[cfg(target_os = "linux")]
    Unverified,
    #[cfg(target_os = "linux")]
    Setup(warper_service::linux::daemon::Error),
    #[cfg(target_os = "linux")]
    Recovery(warper_service::linux::recovery::Error),
    #[cfg(target_os = "linux")]
    Service(Box<warper_service::linux::daemon::Failure>),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => f.write_str("InvalidArguments: use warperd --help"),
            #[cfg(not(target_os = "linux"))]
            Self::Platform => f.write_str("UnsupportedIntegration: native daemon supports Linux"),
            Self::Io(kind) => write!(
                f,
                "NativeIo: daemon runtime, signal or output operation failed ({kind:?})"
            ),
            #[cfg(target_os = "linux")]
            Self::SignalClosed => f.write_str("WorkerFailed: runtime signal observation stopped"),
            #[cfg(target_os = "linux")]
            Self::SignalCleanup(cleanup) => write!(
                f,
                "WorkerFailed: runtime signal observation stopped; shutdown also failed: {cleanup}"
            ),
            #[cfg(target_os = "linux")]
            Self::Import(error) => error.fmt(f),
            #[cfg(target_os = "linux")]
            Self::Diagnostic(error) => error.fmt(f),
            #[cfg(target_os = "linux")]
            Self::Network(error) => error.fmt(f),
            #[cfg(target_os = "linux")]
            Self::Unverified => {
                f.write_str("RecoveryRequired: diagnostic retirement is unverified")
            }
            #[cfg(target_os = "linux")]
            Self::Setup(error) => error.fmt(f),
            #[cfg(target_os = "linux")]
            Self::Recovery(error) => error.fmt(f),
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
        [arg] if arg == "recover" => Ok(Command::Recover),
        [arg, rest @ ..] if arg == "run" => diagnostic::parse(rest).map(Command::Run),
        [arg, inspect] if arg == "recover" && inspect == "--inspect" => {
            Ok(Command::InspectRecovery)
        }
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
        Command::Run(arguments) => diagnostic::run(arguments),
        Command::Service => service(),
        Command::InspectRecovery => inspect_recovery(),
        Command::Recover => recover(),
    }
}
#[cfg(target_os = "linux")]
fn inspect_recovery() -> Result<(), Error> {
    let report = warper_service::linux::recovery::inspect().map_err(Error::Recovery)?;
    write!(io::stdout().lock(), "{report}").map_err(|error| Error::Io(error.kind()))
}
#[cfg(target_os = "linux")]
fn recover() -> Result<(), Error> {
    warper_service::linux::recovery::recover().map_err(Error::Recovery)?;
    io::stdout()
        .lock()
        .write_all(b"Recovery completed.\n")
        .map_err(|error| Error::Io(error.kind()))
}
#[cfg(not(target_os = "linux"))]
fn recover() -> Result<(), Error> {
    Err(Error::Platform)
}
#[cfg(not(target_os = "linux"))]
fn inspect_recovery() -> Result<(), Error> {
    Err(Error::Platform)
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
        signal_result(signal_lost, result.map(|_| ()).map_err(|error| Error::Service(Box::new(error))))
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
#[cfg(target_os = "linux")]
fn signal_result<T>(lost: bool, result: Result<T, Error>) -> Result<T, Error> {
    match (lost, result) {
        (false, result) => result,
        (true, Ok(_)) => Err(Error::SignalClosed),
        (true, Err(error)) => Err(Error::SignalCleanup(Box::new(error))),
    }
}
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    #[cfg(target_os = "linux")]
    if args
        .first()
        .is_some_and(|arg| arg == "--native-materialize")
    {
        return match warper_cli::materialize::child(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => ExitCode::from(
                warper_cli::report_error(error, &mut io::stderr().lock()).exit_code(),
            ),
        };
    }
    match parse(&args).and_then(execute) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let code = match &error {
                Error::Usage => 2,
                #[cfg(target_os = "linux")]
                Error::Import(error) => error.exit_code(),
                _ => 1,
            };
            // The primary exit classification survives unavailable diagnostics.
            let _diagnostic = writeln!(io::stderr().lock(), "{error}");
            ExitCode::from(code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    #[test]
    fn signal_loss_preserves_initial_failure_and_typed_cleanup_cause() {
        assert!(matches!(
            signal_result(true, Ok(())),
            Err(Error::SignalClosed)
        ));
        let failure = signal_result::<()>(true, Err(Error::Io(io::ErrorKind::Other))).unwrap_err();
        assert!(
            matches!(failure, Error::SignalCleanup(ref error) if matches!(error.as_ref(), Error::Io(io::ErrorKind::Other)))
        );
        assert!(matches!(
            signal_result::<()>(false, Err(Error::Io(io::ErrorKind::PermissionDenied))),
            Err(Error::Io(io::ErrorKind::PermissionDenied))
        ));
    }
    #[test]
    fn command_forms_are_explicit_and_reject_unrelated_arguments() {
        for (args, expected) in [
            (vec![], Command::Help),
            (vec!["service"], Command::Service),
            (vec!["--version"], Command::Version),
            (vec!["recover", "--inspect"], Command::InspectRecovery),
            (vec!["recover"], Command::Recover),
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
