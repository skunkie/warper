// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Offline command entry point. No networking engine is constructed here.

use std::{io, process::ExitCode};

fn main() -> ExitCode {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
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
