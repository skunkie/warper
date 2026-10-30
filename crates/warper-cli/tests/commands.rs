// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! End-to-end CLI flow with explicit identity, source, and output boundaries.

use std::{
    ffi::OsString,
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command as Process,
};

use warper_cli::{
    Environment, EnvironmentError, Error, Output, SourceReader, SudoIdentity,
    args::{self, Command, ServiceCommand},
    execute, report_error, write_output,
};
use warper_config::{schema::Platform, source};
use warper_core::configuration::paths::{Account, Error as PathError, IdentityProvider};

const VALID: &[u8] = b"tunnel: {ip: 192.0.2.1}\nprotocols: [{socks5: {host: proxy.example.test:1080, ips: [10.0.0.0/8]}}]";

struct StubEnvironment {
    effective_uid: u32,
    account: Result<Account, PathError>,
    cwd: Result<PathBuf, EnvironmentError>,
    sudo_uid: Option<OsString>,
    sudo_user: Option<OsString>,
    platform: Option<Platform>,
}

impl StubEnvironment {
    fn new() -> Self {
        Self {
            effective_uid: 1234,
            account: Ok(Account {
                uid: 1234,
                name: "sample".into(),
                home: "/fixture/home".into(),
            }),
            cwd: Ok("/fixture/work".into()),
            sudo_uid: None,
            sudo_user: None,
            platform: Some(Platform::Linux),
        }
    }
}

impl IdentityProvider for StubEnvironment {
    fn effective_uid(&self) -> u32 {
        self.effective_uid
    }
    fn account_by_uid(&self, _: u32) -> Result<Account, PathError> {
        self.account.clone()
    }
}

impl Environment for StubEnvironment {
    fn original_cwd(&self) -> Result<PathBuf, EnvironmentError> {
        self.cwd.clone()
    }
    fn sudo_identity(&self) -> SudoIdentity {
        SudoIdentity {
            uid: self.sudo_uid.clone(),
            user: self.sudo_user.clone(),
        }
    }
    fn platform(&self) -> Option<Platform> {
        self.platform
    }
}

struct MockSource {
    expected: PathBuf,
    result: Result<Vec<u8>, source::Error>,
    calls: usize,
}

impl MockSource {
    fn new(expected: impl Into<PathBuf>, result: Result<Vec<u8>, source::Error>) -> Self {
        Self {
            expected: expected.into(),
            result,
            calls: 0,
        }
    }
}

impl SourceReader for MockSource {
    fn read(&mut self, path: &Path) -> Result<Vec<u8>, source::Error> {
        assert_eq!(path, self.expected, "only the selected source may be read");
        self.calls += 1;
        self.result.clone()
    }
}

struct ForbiddenEnvironment;

impl IdentityProvider for ForbiddenEnvironment {
    fn effective_uid(&self) -> u32 {
        panic!("command must not inspect identity")
    }
    fn account_by_uid(&self, _: u32) -> Result<Account, PathError> {
        panic!("command must not look up accounts")
    }
}

impl Environment for ForbiddenEnvironment {
    fn original_cwd(&self) -> Result<PathBuf, EnvironmentError> {
        panic!("command must not inspect cwd")
    }
    fn sudo_identity(&self) -> SudoIdentity {
        panic!("command must not inspect sudo")
    }
    fn platform(&self) -> Option<Platform> {
        panic!("command must not inspect platform")
    }
}

struct ForbiddenSource;
impl SourceReader for ForbiddenSource {
    fn read(&mut self, _: &Path) -> Result<Vec<u8>, source::Error> {
        panic!("command must not read files")
    }
}

fn arguments(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

fn invoke(
    args: &[OsString],
    environment: &impl Environment,
    source: &mut impl SourceReader,
) -> (u8, String, String) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let result = args::parse(args)
        .map_err(Error::Arguments)
        .and_then(|command| execute(command, environment, source))
        .and_then(|output| write_output(output, &mut stdout));
    let code = match result {
        Ok(()) => 0,
        Err(error) => report_error(error, &mut stderr).exit_code(),
    };
    (
        code,
        String::from_utf8(stdout).unwrap(),
        String::from_utf8(stderr).unwrap(),
    )
}

#[test]
fn check_config_catalog_has_documented_exit_codes_and_redacted_streams() {
    let catalog: toml::Table = include_str!("../../../tests/fixtures/configuration/cases.toml")
        .parse()
        .unwrap();
    let fixture_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/configuration");
    for case in catalog["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let bytes = std::fs::read(fixture_dir.join(case["path"].as_str().unwrap())).unwrap();
        let mut source = MockSource::new("/fixture/work/sample.yaml", Ok(bytes));
        let (code, stdout, stderr) = invoke(
            &arguments(&["check-config", "--config", "sample.yaml"]),
            &StubEnvironment::new(),
            &mut source,
        );
        assert_eq!(source.calls, 1, "{id}");
        match case["expected"].as_str().unwrap() {
            "valid" => {
                assert_eq!(code, 0, "{id}");
                assert_eq!(stdout, "Configuration is valid (offline).\n", "{id}");
                assert!(stderr.is_empty(), "{id}");
            }
            "InvalidConfig" => {
                assert_eq!(code, 2, "{id}");
                assert!(stdout.is_empty(), "{id}");
                let field = case["expected_field"].as_str().unwrap();
                assert!(
                    stderr.starts_with(&format!("InvalidConfig at {field}:")),
                    "{id}"
                );
                assert!(!stderr.contains("synthetic-invalid-key"), "{id}");
            }
            _ => panic!("unexpected catalog outcome {id}"),
        }
    }
}

#[test]
fn help_version_and_unavailable_commands_do_not_touch_environment_or_sources() {
    for args in [
        &["--help"][..],
        &["-h"],
        &["--version"],
        &["-V"],
        &["check-config", "--help"],
        &["check-config", "-h"],
    ] {
        let (code, stdout, stderr) = invoke(
            &arguments(args),
            &ForbiddenEnvironment,
            &mut ForbiddenSource,
        );
        assert_eq!(code, 0);
        assert!(!stdout.is_empty());
        assert!(stderr.is_empty());
    }
    for args in [
        &[][..],
        &["status"],
        &["status", "--json"],
        &["routes", "--json"],
        &["connections"],
        &["logs", "--follow"],
        &["explain", "apps.example.test", "--json"],
        &["up"],
        &["down", "--no-wait"],
        &["up", "--wait-ms", "123"],
        &["recover", "--inspect"],
        &["config", "install", "--config", "source.yaml"],
    ] {
        let (code, stdout, stderr) = invoke(
            &arguments(args),
            &ForbiddenEnvironment,
            &mut ForbiddenSource,
        );
        assert_eq!(code, 1, "{args:?}");
        assert!(stdout.is_empty(), "{args:?}");
        assert!(stderr.starts_with("UnsupportedCapability:"), "{args:?}");
    }
}

#[test]
fn malformed_arguments_fail_before_any_environment_or_file_access() {
    for args in [
        &["sample-secret"][..],
        &["check-config", "sample-secret"],
        &["check-config", "--config"],
        &["check-config", "--config", "--help"],
        &["check-config", "--config", ""],
        &["check-config", "--config", "a", "--config", "b"],
        &["--version", "sample-secret"],
        &["status", "--follow"],
        &["config"],
        &["config", "unknown"],
        &["explain"],
        &["up", "--wait-ms", "0"],
        &["up", "--wait-ms", "18446744073709551616"],
        &["up", "--wait-ms", "not-a-number"],
        &["down", "--no-wait", "--wait-ms", "1"],
        &["up", "--wait-ms"],
        &["logs", "--json"],
        &["recover", "--unknown"],
    ] {
        let (code, stdout, stderr) = invoke(
            &arguments(args),
            &ForbiddenEnvironment,
            &mut ForbiddenSource,
        );
        assert_eq!(code, 2, "{args:?}");
        assert!(stdout.is_empty(), "{args:?}");
        assert!(stderr.starts_with("InvalidArguments:"), "{args:?}");
        assert!(!stderr.contains("sample-secret"));
    }
    assert_eq!(
        args::parse(&arguments(&["connections", "--json"])),
        Ok(Command::Service(ServiceCommand::Connections))
    );
    assert_eq!(
        args::parse(&arguments(&["check-config", "--config", "./-source"])),
        Ok(Command::CheckConfig {
            path: Some("./-source".into())
        })
    );
}

#[test]
fn source_paths_use_invoking_home_original_cwd_and_elevated_identity() {
    let environment = StubEnvironment::new();
    for (args, expected) in [
        (vec!["check-config"], "/fixture/home/.warp.yaml"),
        (
            vec!["check-config", "--config", "~/source.yaml"],
            "/fixture/home/source.yaml",
        ),
        (
            vec!["check-config", "--config", "configs/source.yaml"],
            "/fixture/work/configs/source.yaml",
        ),
        (
            vec!["check-config", "--config", "/absolute/source.yaml"],
            "/absolute/source.yaml",
        ),
    ] {
        let mut source = MockSource::new(expected, Ok(VALID.to_vec()));
        let (code, _, stderr) = invoke(&arguments(&args), &environment, &mut source);
        assert_eq!(code, 0, "{stderr}");
        assert_eq!(source.calls, 1);
    }
    let environment = StubEnvironment {
        effective_uid: 0,
        sudo_uid: Some("1234".into()),
        sudo_user: Some("sample".into()),
        ..StubEnvironment::new()
    };
    let mut source = MockSource::new("/fixture/home/.warp.yaml", Ok(VALID.to_vec()));
    assert_eq!(
        invoke(&arguments(&["check-config"]), &environment, &mut source).0,
        0
    );
    let environment = StubEnvironment {
        sudo_uid: Some("0".into()),
        sudo_user: Some("sample-secret".into()),
        ..StubEnvironment::new()
    };
    let mut source = MockSource::new("/fixture/home/.warp.yaml", Ok(VALID.to_vec()));
    assert_eq!(
        invoke(&arguments(&["check-config"]), &environment, &mut source).0,
        0,
        "non-root sudo variables cannot select an identity"
    );
    let (code, _, stderr) = invoke(
        &arguments(&["check-config", "--config", "~sample-secret/file"]),
        &StubEnvironment::new(),
        &mut ForbiddenSource,
    );
    assert_eq!(code, 2);
    assert!(!stderr.contains("sample-secret"));
}

#[test]
fn identity_environment_and_source_failures_keep_their_exit_classification() {
    for (environment, expected) in [
        (
            StubEnvironment {
                account: Err(PathError::IdentityLookup),
                ..StubEnvironment::new()
            },
            1,
        ),
        (
            StubEnvironment {
                account: Ok(Account {
                    uid: 9999,
                    name: "sample".into(),
                    home: "/fixture/home".into(),
                }),
                ..StubEnvironment::new()
            },
            1,
        ),
        (
            StubEnvironment {
                effective_uid: 0,
                sudo_uid: Some("1234".into()),
                ..StubEnvironment::new()
            },
            2,
        ),
        (
            StubEnvironment {
                effective_uid: 0,
                sudo_uid: Some("1234".into()),
                sudo_user: Some("sample-secret".into()),
                ..StubEnvironment::new()
            },
            2,
        ),
        (
            StubEnvironment {
                cwd: Err(EnvironmentError::WorkingDirectory),
                ..StubEnvironment::new()
            },
            1,
        ),
        (
            StubEnvironment {
                cwd: Ok("relative".into()),
                ..StubEnvironment::new()
            },
            1,
        ),
        (
            StubEnvironment {
                platform: None,
                ..StubEnvironment::new()
            },
            1,
        ),
    ] {
        let (code, stdout, stderr) = invoke(
            &arguments(&["check-config"]),
            &environment,
            &mut ForbiddenSource,
        );
        assert_eq!(code, expected);
        assert!(stdout.is_empty());
        assert!(!stderr.contains("sample-secret"));
    }
    for error in [
        source::Error::NotFound,
        source::Error::PermissionDenied,
        source::Error::NotRegular,
        source::Error::Read,
        source::Error::TooLarge,
    ] {
        let mut source = MockSource::new("/fixture/home/.warp.yaml", Err(error));
        let (code, stdout, stderr) = invoke(
            &arguments(&["check-config"]),
            &StubEnvironment::new(),
            &mut source,
        );
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(!stderr.is_empty());
    }
}

#[test]
fn broken_output_and_diagnostic_writers_preserve_typed_failures() {
    struct BrokenWriter;
    impl Write for BrokenWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let error = write_output(Output::ConfigValid, &mut BrokenWriter).unwrap_err();
    assert!(matches!(error, Error::Output(io::ErrorKind::BrokenPipe)));
    let failure = report_error(error, &mut BrokenWriter);
    assert_eq!(failure.exit_code(), 1);
    assert_eq!(failure.diagnostic, Some(io::ErrorKind::BrokenPipe));
    assert!(matches!(
        failure.primary,
        Error::Output(io::ErrorKind::BrokenPipe)
    ));
    let failure = report_error(Error::Arguments(args::Error::Usage), &mut BrokenWriter);
    assert_eq!(failure.exit_code(), 2);
    assert_eq!(failure.diagnostic, Some(io::ErrorKind::BrokenPipe));
}

#[test]
fn executable_entry_points_keep_stdout_stderr_and_exit_codes_separate() {
    for (args, expected_code, expected_stdout, expected_stderr) in [
        (vec!["--help"], 0, warper_cli::HELP, ""),
        (vec!["check-config", "--help"], 0, warper_cli::HELP, ""),
        (vec!["--version"], 0, warper_cli::VERSION, ""),
        (vec!["status"], 1, "", "UnsupportedCapability:"),
        (vec!["sample-secret"], 2, "", "InvalidArguments:"),
    ] {
        let mut command = Process::new(env!("CARGO_BIN_EXE_warper"));
        command.env_clear().args(args);
        // Keep coverage artifacts in the harness-owned location even though the
        // command deliberately runs without the developer's environment.
        if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
            command.env("LLVM_PROFILE_FILE", profile);
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(expected_code));
        assert_eq!(String::from_utf8(output.stdout).unwrap(), expected_stdout);
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.starts_with(expected_stderr));
        assert!(!stderr.contains("sample-secret"));
    }
}

#[cfg(unix)]
#[test]
fn native_path_bytes_are_preserved_but_invalid_sudo_encoding_is_redacted() {
    use std::os::unix::ffi::OsStringExt;
    let path = OsString::from_vec(b"configs/\xff.yaml".to_vec());
    let expected = Path::new("/fixture/work").join(&path);
    let mut source = MockSource::new(expected, Ok(VALID.to_vec()));
    let args = [
        OsString::from("check-config"),
        OsString::from("--config"),
        path,
    ];
    assert_eq!(invoke(&args, &StubEnvironment::new(), &mut source).0, 0);
    let environment = StubEnvironment {
        effective_uid: 0,
        sudo_uid: Some(OsString::from_vec(vec![0xff])),
        sudo_user: Some("sample".into()),
        ..StubEnvironment::new()
    };
    assert_eq!(
        invoke(
            &arguments(&["check-config"]),
            &environment,
            &mut ForbiddenSource
        )
        .0,
        2
    );
    let args = [OsString::from_vec(b"sample-secret\xff".to_vec())];
    let (code, _, stderr) = invoke(&args, &ForbiddenEnvironment, &mut ForbiddenSource);
    assert_eq!(code, 2);
    assert!(!stderr.contains("sample-secret"));
}
