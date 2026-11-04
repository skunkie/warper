// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Shared disposable-only root admission, namespace guards and retained jobs.

use std::{
    fs,
    os::unix::{
        fs::{FileTypeExt, MetadataExt},
        net::UnixStream as NativeStream,
    },
    process::Command,
    time::Duration,
};
use warper_control::{namespace, unix};
use warper_core::transport::Request;

pub(crate) type Failure = Box<dyn std::error::Error + Send + Sync>;

pub(crate) fn root() -> Result<(), Failure> {
    namespace::require_initial_user_namespace()?;
    let (a, _b) = NativeStream::pair()?;
    unix::authenticate_service(&a)?;
    Ok(())
}
pub(crate) fn isolated(mount: &str, net: &str) -> Result<(), Failure> {
    root()?;
    for (kind, anchor) in [("mnt", mount), ("net", net)] {
        let fd: u32 = anchor.parse()?;
        let path = format!("/proc/self/fd/{fd}");
        let label = fs::read_link(&path)?;
        let label = label.to_str().ok_or("invalid fixture namespace label")?;
        let file = fs::File::open(&path)?;
        if rustix::fs::fstatfs(&file)?.f_type as u64 != 0x6e736673
            || !label.starts_with(&format!("{kind}:["))
            || !label.ends_with(']')
        {
            return Err("fixture requires inherited namespace handles".into());
        }
        let old = file.metadata()?;
        let current = fs::metadata(format!("/proc/thread-self/ns/{kind}"))?;
        if old.dev() == current.dev() && old.ino() == current.ino() {
            return Err("fixture requires private mount/network namespaces".into());
        }
    }
    let device = fs::symlink_metadata("/dev/net/tun")?;
    if !device.file_type().is_char_device()
        || device.uid() != 0
        || rustix::fs::major(device.rdev()) != 10
        || rustix::fs::minor(device.rdev()) != 200
    {
        return Err("fixture requires a real protected TUN character device".into());
    }
    Ok(())
}
pub(crate) fn ip(args: &[&str]) -> Result<Vec<u8>, Failure> {
    let output = Command::new("timeout")
        .args(["--kill-after=1s", "2s", "ip"])
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err("controlled ip operation failed".into());
    }
    Ok(output.stdout)
}

pub(crate) async fn join_native<T: Send + 'static>(
    task: &mut warper_service::native::Task<T>,
    cancellation_owner: &tokio::sync::watch::Sender<bool>,
) -> Result<T, Failure> {
    // The independently bounded harness can terminate hung kernel work.
    // A caller deadline here never discards the retained native job.
    loop {
        match task
            .wait(Request {
                deadline: tokio::time::Instant::now() + Duration::from_secs(10),
                cancellation: cancellation_owner.subscribe(),
            })
            .await
        {
            Err(warper_service::native::Error::Deadline) => continue,
            result => return Ok(result?),
        }
    }
}

#[derive(Debug)]
pub(crate) struct CombinedFailure {
    pub(crate) primary: Failure,
    pub(crate) cleanup: Vec<Failure>,
}
impl std::fmt::Display for CombinedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; {} cleanup failure(s)",
            self.primary,
            self.cleanup.len()
        )
    }
}
impl std::error::Error for CombinedFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.primary)
    }
}
pub(crate) fn preserve<T>(
    primary: Result<T, Failure>,
    mut cleanup: Vec<Failure>,
) -> Result<T, Failure> {
    let primary = match primary {
        Err(error) => error,
        Ok(value) if cleanup.is_empty() => return Ok(value),
        Ok(value) => {
            drop(value);
            cleanup.remove(0)
        }
    };
    if cleanup.is_empty() {
        Err(primary)
    } else {
        Err(Box::new(CombinedFailure { primary, cleanup }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Debug)]
    struct Guard(Arc<AtomicUsize>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn owned_results_drop_when_cleanup_fails_and_survive_success() {
        let drops = Arc::new(AtomicUsize::new(0));
        let retained = preserve(Ok(Guard(drops.clone())), vec![]).unwrap();
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        drop(retained);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        let failure = preserve(
            Ok(Guard(drops.clone())),
            vec![Box::new(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            ))],
        )
        .unwrap_err();
        assert_eq!(drops.load(Ordering::Relaxed), 2);
        assert_eq!(
            failure.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }
}
