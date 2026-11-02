// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Portable process boundaries; privileged service execution belongs to CI.

use std::process::Command;

#[test]
fn daemon_entry_points_keep_usage_errors_and_offline_output_separate() {
    for (arguments, code, stdout_prefix, stderr_prefix) in [
        (vec!["--help"], 0, "warperd — selective tunnel service", ""),
        (
            vec!["--version"],
            0,
            concat!("warperd ", env!("CARGO_PKG_VERSION")),
            "",
        ),
        (
            vec!["recover", "--inspect"],
            1,
            "",
            "UnsupportedCapability:",
        ),
        (vec!["service", "sample-secret"], 2, "", "InvalidArguments:"),
    ] {
        let mut process = Command::new(env!("CARGO_BIN_EXE_warperd"));
        process.env_clear().args(&arguments);
        if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
            process.env("LLVM_PROFILE_FILE", profile);
        }
        let output = process.output().unwrap();
        assert_eq!(output.status.code(), Some(code), "{arguments:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stdout.starts_with(stdout_prefix), "{arguments:?}");
        assert!(stderr.starts_with(stderr_prefix), "{arguments:?}");
        if code != 0 {
            assert!(stdout.is_empty());
        } else {
            assert!(stderr.is_empty());
        }
        assert!(!stderr.contains("sample-secret"));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn unprivileged_service_reports_the_native_cause_when_its_worker_exits() {
    use std::os::unix::{fs::PermissionsExt, process::CommandExt};
    let binary = env!("CARGO_BIN_EXE_warperd");
    let directory = std::env::temp_dir().join(format!("warper-daemon-cli-{}", std::process::id()));
    let mut process;
    let mut owned_directory = false;
    if nix::unistd::geteuid().is_root() {
        std::fs::create_dir(&directory).unwrap();
        owned_directory = true;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        let copied = directory.join("daemon");
        std::fs::copy(binary, &copied).unwrap();
        std::fs::set_permissions(&copied, std::fs::Permissions::from_mode(0o755)).unwrap();
        process = Command::new(copied);
        process.uid(65534).gid(65534);
    } else {
        process = Command::new(binary);
    }
    process.arg("service").env_clear();
    if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
        process.env("LLVM_PROFILE_FILE", profile);
    }
    let result = process.output();
    if owned_directory {
        std::fs::remove_dir_all(directory).unwrap();
    }
    let output = result.unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.starts_with("PermissionDenied:") || stderr.starts_with("Authentication:"),
        "{stderr}"
    );
    assert!(!stderr.contains("owned daemon task or channel stopped"));
}
