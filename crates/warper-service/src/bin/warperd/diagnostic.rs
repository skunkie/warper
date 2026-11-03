// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::Error;
use std::{ffi::OsString, path::PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Arguments {
    path: Option<PathBuf>,
    verbose: bool,
    debug: bool,
}

pub(super) fn parse(arguments: &[OsString]) -> Result<Arguments, Error> {
    let mut source = vec![OsString::from("check-config")];
    let (mut headless, mut verbose, mut debug) = (false, false, false);
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        match argument.to_str() {
            Some("--headless") if !headless => headless = true,
            Some("--verbose") if !verbose => verbose = true,
            Some("--debug") if !debug => debug = true,
            Some("--config") => {
                source.push(argument.clone());
                index += 1;
                source.push(arguments.get(index).ok_or(Error::Usage)?.clone());
            }
            _ => return Err(Error::Usage),
        }
        index += 1;
    }
    let warper_cli::args::Command::CheckConfig { path } =
        warper_cli::args::parse(&source).map_err(|_| Error::Usage)?
    else {
        return Err(Error::Usage);
    };
    Ok(Arguments {
        path,
        verbose,
        debug,
    })
}

#[cfg(target_os = "linux")]
pub(super) fn run(arguments: Arguments) -> Result<(), Error> {
    use std::{
        io::{self, Write},
        time::Duration,
    };
    use warper_service::linux::{diagnostic::Diagnostic, network};
    let encoded =
        warper_cli::materialize::prepare(arguments.path.as_deref()).map_err(Error::Import)?;
    // Blocking import/native bootstrap complete before the async executor exists.
    let mut diagnostic = Diagnostic::new(encoded.expose()).map_err(Error::Diagnostic)?;
    let verbose = arguments.verbose || arguments.debug;
    if verbose {
        writeln!(
            io::stderr().lock(),
            "Starting foreground diagnostic networking."
        )
        .map_err(|error| Error::Io(error.kind()))?;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| Error::Io(error.kind()))?;
    let result = runtime.block_on(async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|error| Error::Io(error.kind()))?;
        let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .map_err(|error| Error::Io(error.kind()))?;
        let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            .map_err(|error| Error::Io(error.kind()))?;
        let (stop, cancellation) = tokio::sync::watch::channel(false);
        let (state, _observed) = tokio::sync::watch::channel(network::State::Starting);
        let running = diagnostic.run(cancellation, &state);
        tokio::pin!(running);
        let (lost, outcome) = tokio::select! { biased;
            outcome = &mut running => (false, outcome),
            signal = term.recv() => { stop.send_replace(true); (signal.is_none(), running.await) },
            signal = interrupt.recv() => { stop.send_replace(true); (signal.is_none(), running.await) },
            signal = hangup.recv() => { stop.send_replace(true); (signal.is_none(), running.await) },
        };
        super::signal_result(lost, outcome.map_err(|error| Error::Network(Box::new(error))))
    });
    runtime.shutdown_timeout(Duration::from_secs(5));
    drop(diagnostic);
    let report = result?;
    if !report.retired {
        return Err(Error::Unverified);
    }
    // No presentation write can stall forwarding: all networking is retired.
    if verbose {
        writeln!(
            io::stderr().lock(),
            "diagnostic_summary retired={} admitted_flows={} captured_packets={}",
            report.retired,
            report.relays.as_ref().map_or(0, |report| report.admitted),
            report
                .packets
                .as_ref()
                .map_or(0, |report| report.captured_packets)
        )
        .map_err(|error| Error::Io(error.kind()))?;
    }
    writeln!(io::stdout().lock(), "Diagnostic stopped.").map_err(|error| Error::Io(error.kind()))
}
#[cfg(not(target_os = "linux"))]
pub(super) fn run(_arguments: Arguments) -> Result<(), Error> {
    Err(Error::Platform)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostic_arguments_preserve_paths_aliases_and_reject_ambiguous_forms() {
        let arguments = [
            "--headless",
            "--verbose",
            "--debug",
            "--config",
            "sample.yaml",
        ]
        .map(OsString::from);
        assert_eq!(
            parse(&arguments).unwrap(),
            Arguments {
                path: Some("sample.yaml".into()),
                verbose: true,
                debug: true
            }
        );
        assert_eq!(
            parse(&[]).unwrap(),
            Arguments {
                path: None,
                verbose: false,
                debug: false
            }
        );
        for arguments in [
            vec!["--config"],
            vec!["--unknown"],
            vec!["--headless", "--headless"],
            vec!["--config", "--debug"],
            vec!["--config", "a", "--config", "b"],
        ] {
            assert!(matches!(
                parse(
                    &arguments
                        .into_iter()
                        .map(OsString::from)
                        .collect::<Vec<_>>()
                ),
                Err(Error::Usage)
            ));
        }
    }
}
