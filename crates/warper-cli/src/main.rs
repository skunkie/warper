// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Native client entry point. Network ownership remains in the service.

use std::{io, process::ExitCode};

fn main() -> ExitCode {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    #[cfg(target_os = "linux")]
    if arguments
        .first()
        .is_some_and(|arg| arg == "--native-materialize")
    {
        return match warper_cli::materialize::child(&arguments[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => ExitCode::from(
                warper_cli::report_error(error, &mut io::stderr().lock()).exit_code(),
            ),
        };
    }
    let result = warper_cli::args::parse(&arguments)
        .map_err(warper_cli::Error::Arguments)
        .and_then(warper_cli::run_native)
        .and_then(|output| warper_cli::write_output(output, &mut io::stdout().lock()));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            ExitCode::from(warper_cli::report_error(error, &mut io::stderr().lock()).exit_code())
        }
    }
}
