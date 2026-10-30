// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Read-only native lookup probe; not part of the installed CLI contract.

#[cfg(unix)]
fn main() -> Result<(), warper_core::configuration::paths::Error> {
    use std::path::Path;

    use warper_config::identity::UnixIdentity;
    use warper_core::configuration::paths::{Paths, invoking_account};

    // Explicitly probe the current account, independent of the shell's sudo
    // environment. Real import/diagnostic commands must supply both sudo fields.
    let account = invoking_account(&UnixIdentity, None, None)?;
    let paths = Paths::new(&account, Path::new("/"), None)?;
    if paths.config_file() != account.home.join(".warp.yaml") {
        return Err(warper_core::configuration::paths::Error::InvalidAccount);
    }
    println!("PASS native current-account lookup and default configuration path");
    Ok(())
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("native account lookup probe requires Unix");
    std::process::ExitCode::FAILURE
}
