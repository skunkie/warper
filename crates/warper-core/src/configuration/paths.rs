// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Invoking-user lookup and lexical paths for import and offline diagnostics.
//! Installed services must use their protected managed store instead.

use std::{
    fmt,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Account {
    pub uid: u32,
    pub name: String,
    pub home: PathBuf,
}

/// Implemented by the native client using trusted OS account records.
/// Environment variables, including HOME, are not account records.
pub trait IdentityProvider {
    fn effective_uid(&self) -> u32;
    fn account_by_uid(&self, uid: u32) -> Result<Account, Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    IdentityLookup,
    InconsistentSudoIdentity,
    InvalidAccount,
    RelativeWorkingDirectory,
    EmptyPath,
    InvalidPath,
    UnsupportedHomeExpansion,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::IdentityLookup => "cannot resolve invoking account from OS records",
            Self::InconsistentSudoIdentity => {
                "SUDO_UID and SUDO_USER must identify the same OS account"
            }
            Self::InvalidAccount => {
                "OS account must have a matching UID, name, and absolute home directory"
            }
            Self::RelativeWorkingDirectory => "original working directory must be absolute",
            Self::EmptyPath => "path must not be empty",
            Self::InvalidPath => "path must not contain a NUL byte",
            Self::UnsupportedHomeExpansion => "use ~ or ~/ for invoking-user home expansion",
        })
    }
}

impl std::error::Error for Error {}

/// Cross-check both sudo fields when elevated; neither means the current account.
/// Non-root callers cannot select a different identity through sudo variables.
pub fn invoking_account(
    provider: &impl IdentityProvider,
    sudo_uid: Option<&str>,
    sudo_user: Option<&str>,
) -> Result<Account, Error> {
    let effective_uid = provider.effective_uid();
    let (uid, expected_name) = if effective_uid == 0 {
        match (sudo_uid, sudo_user) {
            (None, None) => (effective_uid, None),
            (Some(uid), Some(name))
                if !uid.is_empty()
                    && uid.bytes().all(|byte| byte.is_ascii_digit())
                    && !name.is_empty() =>
            {
                (
                    uid.parse().map_err(|_| Error::InconsistentSudoIdentity)?,
                    Some(name),
                )
            }
            _ => return Err(Error::InconsistentSudoIdentity),
        }
    } else {
        (effective_uid, None)
    };
    let account = provider.account_by_uid(uid)?;
    if account.uid != uid
        || account.name.is_empty()
        || !account.home.is_absolute()
        || account.home.as_os_str().as_encoded_bytes().contains(&0)
    {
        return Err(Error::InvalidAccount);
    }
    if expected_name.is_some_and(|name| name != account.name) {
        return Err(Error::InconsistentSudoIdentity);
    }
    Ok(account)
}

/// Owns the resolved source path and invoking home for one validation/import.
/// Resolution does not canonicalize symlinks, open files, or expand substitutions.
#[derive(Debug)]
pub struct Paths {
    home: PathBuf,
    config_file: PathBuf,
}

impl Paths {
    pub fn new(
        account: &Account,
        original_cwd: &Path,
        config: Option<&str>,
    ) -> Result<Self, Error> {
        Self::with_config_path(account, original_cwd, config.map(Path::new))
    }

    /// Preserve native filename bytes in the CLI source path and its directory.
    pub fn with_config_path(
        account: &Account,
        original_cwd: &Path,
        config: Option<&Path>,
    ) -> Result<Self, Error> {
        if !account.home.is_absolute() || account.home.as_os_str().as_encoded_bytes().contains(&0) {
            return Err(Error::InvalidAccount);
        }
        if !original_cwd.is_absolute() {
            return Err(Error::RelativeWorkingDirectory);
        }
        if original_cwd.as_os_str().as_encoded_bytes().contains(&0) {
            return Err(Error::InvalidPath);
        }
        let config_file = resolve(
            config.unwrap_or(Path::new("~/.warp.yaml")),
            &account.home,
            original_cwd,
        )?;
        Ok(Self {
            home: account.home.clone(),
            config_file,
        })
    }

    pub fn config_file(&self) -> &Path {
        &self.config_file
    }

    /// The caller attaches the schema field path to this redacted typed error.
    pub fn resolve_value(&self, value: &str) -> Result<PathBuf, Error> {
        // An absolute path always has a parent except for the filesystem root.
        let directory = self.config_file.parent().unwrap_or(&self.config_file);
        resolve(Path::new(value), &self.home, directory)
    }
}

fn resolve(value: &Path, home: &Path, directory: &Path) -> Result<PathBuf, Error> {
    if value.as_os_str().is_empty() {
        return Err(Error::EmptyPath);
    }
    if value.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(Error::InvalidPath);
    }
    if let Ok(relative) = value.strip_prefix("~") {
        return Ok(home.join(relative));
    }
    if value.as_os_str().as_encoded_bytes().starts_with(b"~") {
        return Err(Error::UnsupportedHomeExpansion);
    }
    Ok(directory.join(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubIdentity {
        effective_uid: u32,
        account: Result<Account, Error>,
    }

    impl IdentityProvider for StubIdentity {
        fn effective_uid(&self) -> u32 {
            self.effective_uid
        }
        fn account_by_uid(&self, _: u32) -> Result<Account, Error> {
            self.account.clone()
        }
    }

    fn account() -> Account {
        Account {
            uid: 1000,
            name: "sample".into(),
            home: "/home/sample".into(),
        }
    }

    #[test]
    fn invoking_account_checks_elevated_identity() {
        struct Case {
            id: &'static str,
            sudo_uid: Option<&'static str>,
            sudo_user: Option<&'static str>,
            expected: Result<Account, Error>,
        }
        let provider = StubIdentity {
            effective_uid: 0,
            account: Ok(account()),
        };
        let cases = [
            Case {
                id: "matching",
                sudo_uid: Some("1000"),
                sudo_user: Some("sample"),
                expected: Ok(account()),
            },
            Case {
                id: "different name",
                sudo_uid: Some("1000"),
                sudo_user: Some("other"),
                expected: Err(Error::InconsistentSudoIdentity),
            },
            Case {
                id: "missing name",
                sudo_uid: Some("1000"),
                sudo_user: None,
                expected: Err(Error::InconsistentSudoIdentity),
            },
            Case {
                id: "missing uid",
                sudo_uid: None,
                sudo_user: Some("sample"),
                expected: Err(Error::InconsistentSudoIdentity),
            },
            Case {
                id: "overflow",
                sudo_uid: Some("4294967296"),
                sudo_user: Some("sample"),
                expected: Err(Error::InconsistentSudoIdentity),
            },
            Case {
                id: "signed uid",
                sudo_uid: Some("+1000"),
                sudo_user: Some("sample"),
                expected: Err(Error::InconsistentSudoIdentity),
            },
            Case {
                id: "empty uid",
                sudo_uid: Some(""),
                sudo_user: Some("sample"),
                expected: Err(Error::InconsistentSudoIdentity),
            },
            Case {
                id: "empty user",
                sudo_uid: Some("1000"),
                sudo_user: Some(""),
                expected: Err(Error::InconsistentSudoIdentity),
            },
        ];
        for case in cases {
            assert_eq!(
                invoking_account(&provider, case.sudo_uid, case.sudo_user),
                case.expected,
                "{}",
                case.id
            );
        }
    }

    #[test]
    fn current_account_ignores_non_root_sudo_environment() {
        let provider = StubIdentity {
            effective_uid: 1000,
            account: Ok(account()),
        };
        assert_eq!(
            invoking_account(&provider, Some("0"), Some("root")),
            Ok(account())
        );
        assert_eq!(invoking_account(&provider, None, None), Ok(account()));
        let root = Account {
            uid: 0,
            name: "root".into(),
            home: "/root".into(),
        };
        let provider = StubIdentity {
            effective_uid: 0,
            account: Ok(root.clone()),
        };
        assert_eq!(invoking_account(&provider, None, None), Ok(root));
    }

    #[test]
    fn invalid_os_records_and_lookup_failures_are_rejected() {
        for invalid in [
            Account {
                uid: 1,
                ..account()
            },
            Account {
                name: String::new(),
                ..account()
            },
            Account {
                home: "relative".into(),
                ..account()
            },
            Account {
                home: "/home/\0sample".into(),
                ..account()
            },
        ] {
            let provider = StubIdentity {
                effective_uid: 1000,
                account: Ok(invalid),
            };
            assert_eq!(
                invoking_account(&provider, None, None),
                Err(Error::InvalidAccount)
            );
        }
        let provider = StubIdentity {
            effective_uid: 1000,
            account: Err(Error::IdentityLookup),
        };
        assert_eq!(
            invoking_account(&provider, None, None),
            Err(Error::IdentityLookup)
        );
    }

    #[test]
    fn paths_use_original_cwd_config_directory_and_invoking_home() {
        let paths =
            Paths::new(&account(), Path::new("/work"), Some("configs/sample.yaml")).unwrap();
        assert_eq!(paths.config_file(), Path::new("/work/configs/sample.yaml"));
        for (sample, expected) in [
            ("keys/key", "/work/configs/keys/key"),
            ("../key", "/work/configs/../key"),
            ("/keys/key", "/keys/key"),
            ("~", "/home/sample"),
            ("~/.ssh/key", "/home/sample/.ssh/key"),
            ("~//key", "/home/sample/key"),
            ("$HOME/`sample`", "/work/configs/$HOME/`sample`"),
            ("ключ", "/work/configs/ключ"),
        ] {
            assert_eq!(
                paths.resolve_value(sample).unwrap(),
                Path::new(expected),
                "{sample}"
            );
        }
        assert_eq!(
            Paths::new(&account(), Path::new("/work"), None)
                .unwrap()
                .config_file(),
            Path::new("/home/sample/.warp.yaml")
        );
        assert_eq!(
            Paths::new(&account(), Path::new("/work"), Some("~/config.yaml"))
                .unwrap()
                .config_file(),
            Path::new("/home/sample/config.yaml")
        );
        let root = Paths::new(&account(), Path::new("/work"), Some("/")).unwrap();
        assert_eq!(root.resolve_value("key").unwrap(), Path::new("/key"));
    }

    #[test]
    fn invalid_paths_fail_without_echoing_input() {
        let paths = Paths::new(&account(), Path::new("/work"), None).unwrap();
        for (sample, expected) in [
            ("", Error::EmptyPath),
            ("~other/secret", Error::UnsupportedHomeExpansion),
            ("secret\0key", Error::InvalidPath),
        ] {
            assert_eq!(paths.resolve_value(sample), Err(expected));
            assert!(
                matches!(Paths::new(&account(), Path::new("/work"), Some(sample)), Err(error) if error == expected)
            );
            assert!(!expected.to_string().contains("secret"));
        }
        assert!(matches!(
            Paths::new(&account(), Path::new("relative"), None),
            Err(Error::RelativeWorkingDirectory)
        ));
        assert!(matches!(
            Paths::new(&account(), Path::new("/work\0"), None),
            Err(Error::InvalidPath)
        ));
        let invalid = Account {
            home: "relative".into(),
            ..account()
        };
        assert!(matches!(
            Paths::new(&invalid, Path::new("/work"), None),
            Err(Error::InvalidAccount)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn native_source_and_home_paths_preserve_non_utf8_filename_bytes() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        let path = PathBuf::from(OsString::from_vec(b"directory-\xff/source.yaml".to_vec()));
        let paths = Paths::with_config_path(&account(), Path::new("/work"), Some(&path)).unwrap();
        assert_eq!(paths.config_file(), Path::new("/work").join(&path));
        assert_eq!(
            paths.resolve_value("key").unwrap(),
            Path::new("/work").join(path.parent().unwrap()).join("key")
        );
        let path = PathBuf::from(OsString::from_vec(b"~/\xff.yaml".to_vec()));
        assert_eq!(
            Paths::with_config_path(&account(), Path::new("/work"), Some(&path))
                .unwrap()
                .config_file(),
            Path::new("/home/sample").join(OsString::from_vec(b"\xff.yaml".to_vec()))
        );
        let account = Account {
            home: PathBuf::from(OsString::from_vec(b"/home/\xff".to_vec())),
            ..account()
        };
        assert_eq!(
            Paths::new(&account, Path::new("/work"), None)
                .unwrap()
                .config_file(),
            account.home.join(".warp.yaml")
        );
    }
}
