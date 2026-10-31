// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Controlled admission probe with an isolated overmount attack scope, separate
//! from the installed CLI. Mount attack scope requires a disposable namespace.

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::net::UnixStream;
    use warper_control::{
        Access, Error, OwnerPolicy, Role, namespace::require_initial_user_namespace, unix,
    };

    let args: Vec<_> = std::env::args().skip(1).collect();
    let (client, service) = UnixStream::pair()?;
    let policy = OwnerPolicy::new(Some(nix::unistd::geteuid().as_raw()))?;
    match args.as_slice() {
        [mode] if mode == "--expect-initial" => {
            require_initial_user_namespace()?;
            let role = unix::authenticate_client(&service, &policy, Access::Operate)?;
            if !matches!(role, Role::Owner | Role::Administrator) {
                return Err("unexpected authorization role".into());
            }
            println!("PASS initial user-namespace admission and kernel peer authorization");
        }
        [mode] if mode == "--expect-nested-root" => {
            if nix::unistd::geteuid().as_raw() != 0 {
                return Err("probe requires namespace-local UID 0".into());
            }
            let credentials =
                nix::sys::socket::getsockopt(&service, nix::sys::socket::sockopt::PeerCredentials)?;
            if credentials.uid() != 0 {
                return Err("kernel did not report namespace-local root".into());
            }
            if require_initial_user_namespace() != Err(Error::UntrustedNamespace)
                || !matches!(
                    unix::peer_credentials(&service),
                    Err(Error::UntrustedNamespace)
                )
                || unix::authenticate_client(&service, &policy, Access::Administer)
                    != Err(Error::UntrustedNamespace)
                || unix::authenticate_service(&client) != Err(Error::UntrustedNamespace)
                || !matches!(
                    warper_control::runtime::RuntimeLease::acquire(),
                    Err(warper_control::runtime::Error::Admission(
                        Error::UntrustedNamespace
                    ))
                )
            {
                return Err("namespace-local root bypassed admission".into());
            }
            println!("PASS namespace-local root rejected before peer authorization");
        }
        [mode] if mode == "--expect-invalid-procfs" => {
            if require_initial_user_namespace() != Err(Error::InvalidNamespaceEvidence)
                || !matches!(
                    unix::peer_credentials(&service),
                    Err(Error::InvalidNamespaceEvidence)
                )
                || unix::authenticate_client(&service, &policy, Access::Administer)
                    != Err(Error::InvalidNamespaceEvidence)
                || unix::authenticate_service(&client) != Err(Error::InvalidNamespaceEvidence)
            {
                return Err("counterfeit procfs bypassed admission".into());
            }
            println!("PASS counterfeit procfs rejected at both peer boundaries");
        }
        [mode] if mode == "--expect-self-overmount-rejected" => {
            // Development-only attack fixture: use a disposable user/mount
            // namespace. Nested user-namespace root cannot mutate the host's
            // initial-owned mount namespace.
            if nix::unistd::geteuid().as_raw() != 0
                || require_initial_user_namespace() != Err(Error::UntrustedNamespace)
            {
                return Err("overmount probe requires namespace-local root outside the initial user namespace".into());
            }
            // Target only this single-threaded probe's ns directory. The PID
            // identifies fixture state, never a principal. The external harness
            // owns mount-namespace destruction, including failure cleanup.
            let target = format!("/proc/{0}/task/{0}/ns", std::process::id());
            let status = std::process::Command::new("mount")
                .args(["--bind", &target, &target])
                .status()?;
            if !status.success() {
                return Err("private self-ns overmount failed".into());
            }
            let expected = Error::NamespaceInspection(
                std::io::Error::from_raw_os_error(nix::errno::Errno::EXDEV as i32).kind(),
            );
            if require_initial_user_namespace() != Err(expected)
                || !matches!(unix::peer_credentials(&service), Err(error) if error == expected)
                || unix::authenticate_client(&service, &policy, Access::Administer) != Err(expected)
                || unix::authenticate_service(&client) != Err(expected)
            {
                return Err("procfs submount crossed the admission boundary".into());
            }
            println!("PASS same-procfs overmount rejected by mount-crossing guard");
        }
        _ => return Err("select a documented namespace probe scope".into()),
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("UnsupportedIntegration: namespace probe requires Linux");
    std::process::ExitCode::FAILURE
}
