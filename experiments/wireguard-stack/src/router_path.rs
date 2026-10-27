// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Controlled interruption of a private routed outer transport path.

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    net::{IpAddr, SocketAddr, UdpSocket},
    os::unix::fs::MetadataExt,
    path::Path,
    sync::{Arc, atomic::AtomicBool},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use smoltcp::socket::{tcp, udp};

use crate::{Endpoint, REQUEST, RESPONSE, kernel_peer, router_mtu};

pub fn run(directory: &Path, ipv6: bool) -> Result<()> {
    kernel_peer::require_mapped_namespace()?;
    validate_directory(directory)?;
    let mut client = router_mtu::client(ipv6, ipv6)?;
    let local = client.transport.socket.local_addr()?;
    let result = exchange(directory, ipv6, &mut client);
    drop(client);
    let cleanup = UdpSocket::bind(local).map(drop);
    finish_client(result, cleanup)
}

pub fn serve(directory: &Path, ipv6: bool) -> Result<()> {
    kernel_peer::require_mapped_namespace()?;
    validate_directory(directory)?;
    let (mut netlink, port) = kernel_peer::configure_with_port(9010)?;
    ensure!(port == 9010, "physical-path peer port changed");
    let address = inner_address(ipv6)?;
    let mut workers = kernel_peer::Workers::start(
        address,
        Duration::from_secs(40),
        Arc::new(AtomicBool::new(false)),
    )?;
    let result = (|| -> Result<()> {
        write_marker(directory, "peer.ready")?;
        let start = Instant::now();
        while !directory.join("peer.stop").try_exists()? {
            ensure!(
                start.elapsed() < Duration::from_secs(45),
                "physical-path peer deadline exceeded"
            );
            thread::sleep(Duration::from_millis(2));
        }
        Ok(())
    })();
    let cleanup = workers.finish();
    let report = finish_peer(result, cleanup)?;
    ensure!(
        report.tcp == 1
            && report.udp == 2
            && report.bytes == REQUEST.len() + RESPONSE.len() + 2 * (1 + b"heartbeat".len()),
        "physical-path peer observed unexpected traffic"
    );
    drop(UdpSocket::bind((address, 9000))?);
    drop(std::net::TcpListener::bind((address, 9000))?);
    kernel_peer::verify_handshake(&mut netlink, false)?;
    let (peer_rx, peer_tx) = kernel_peer::peer_traffic(&mut netlink)?;
    println!(
        "PASS physical-path peer: tcp=1, udp=2, application_bytes={}, peer_rx_bytes={peer_rx}, peer_tx_bytes={peer_tx}, workers_joined=true",
        report.bytes
    );
    Ok(())
}

fn finish_client(result: Result<()>, cleanup: io::Result<()>) -> Result<()> {
    match (result, cleanup) {
        (Err(primary), cleanup) => Err(primary.context(match cleanup {
            Ok(()) => "physical-path outer socket rebound".into(),
            Err(error) => format!("physical-path socket cleanup also failed: {error}"),
        })),
        (Ok(()), cleanup) => Ok(cleanup?),
    }
}

fn finish_peer(
    result: Result<()>,
    cleanup: Result<kernel_peer::Report>,
) -> Result<kernel_peer::Report> {
    match (result, cleanup) {
        (Err(primary), cleanup) => Err(primary.context(match cleanup {
            Ok(_) => "physical-path peer workers joined".into(),
            Err(error) => format!("physical-path worker cleanup also failed: {error:#}"),
        })),
        (Ok(()), cleanup) => cleanup,
    }
}

fn validate_directory(directory: &Path) -> Result<()> {
    ensure!(
        directory.is_absolute() && directory.parent() == Some(Path::new("/tmp")),
        "invalid physical-path control directory"
    );
    let name = directory
        .file_name()
        .and_then(|name| name.to_str())
        .context("invalid physical-path control directory")?;
    ensure!(
        name.starts_with("warper-path.")
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.'),
        "invalid physical-path control directory"
    );
    let metadata = fs::symlink_metadata(directory)?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == 0
            && metadata.mode() & 0o7777 == 0o700
            && fs::canonicalize(directory)? == directory,
        "physical-path control directory ownership or mode invalid"
    );
    let path = directory
        .to_str()
        .context("invalid physical-path control directory")?;
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    ensure!(
        mounts.lines().any(|line| {
            line.split_once(" - ").is_some_and(|(left, right)| {
                left.split_whitespace().nth(4) == Some(path)
                    && right.split_whitespace().next() == Some("tmpfs")
            })
        }),
        "physical-path control directory requires a tmpfs mount"
    );
    Ok(())
}

fn write_marker(directory: &Path, name: &str) -> Result<()> {
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join(name))?;
    marker.write_all(b"ready\n")?;
    Ok(())
}

fn inner_address(ipv6: bool) -> Result<IpAddr> {
    Ok(if ipv6 { "fd66:66::10" } else { "10.66.66.10" }.parse()?)
}

fn exchange(directory: &Path, ipv6: bool, client: &mut Endpoint) -> Result<()> {
    let destination = inner_address(ipv6)?;
    let source: IpAddr = if ipv6 { "fd66:66::2" } else { "10.66.66.2" }.parse()?;
    client
        .peer
        .sockets
        .get_mut::<tcp::Socket>(client.peer.tcp)
        .connect(
            client.peer.interface.context(),
            (destination, 9000),
            (source, 40001),
        )?;
    client
        .peer
        .sockets
        .get_mut::<udp::Socket>(client.peer.udp)
        .send_slice(&[0x31], (destination, 9000))?;
    let start = Instant::now();
    let mut warm = false;
    let mut requested_down = false;
    let mut down_since = None;
    let mut up_requested = false;
    let mut restored = false;
    let mut lost_udp = false;
    let mut sent_tcp = false;
    let mut transient_errors = 0usize;
    let mut response = Vec::new();
    let mut heartbeat_sent = false;
    let mut heartbeat = false;
    let mut done_since = None;
    loop {
        let now = start.elapsed();
        ensure!(
            now < Duration::from_secs(35),
            "physical-path recovery deadline exceeded"
        );
        client.peer.poll(i64::try_from(now.as_millis())?);
        if down_since.is_some() && !restored {
            for packet in &client.peer.device.outgoing {
                lost_udp |= crate::is_lost_datagram(packet)?;
                if let Some(frame) = crate::pmtu_probe::plain_tcp(packet)? {
                    let tcp = smoltcp::wire::TcpPacket::new_checked(frame.payload)?;
                    sent_tcp |= !tcp.payload().is_empty();
                }
            }
        }
        if let Err(error) = client.transport.pump(&mut client.peer, now) {
            handle_path_error(
                error,
                down_since.is_some() && !heartbeat_sent,
                &mut transient_errors,
            )?;
        }
        let tcp = client.peer.sockets.get_mut::<tcp::Socket>(client.peer.tcp);
        if tcp.can_recv() {
            tcp.recv(|bytes| {
                response.extend_from_slice(bytes);
                (bytes.len(), ())
            })?;
            ensure!(
                response.len() <= RESPONSE.len(),
                "physical-path response exceeded budget"
            );
        }
        let established = tcp.can_send();
        let ended = down_since.is_some() && !tcp.may_recv();
        let udp = client.peer.sockets.get_mut::<udp::Socket>(client.peer.udp);
        if udp.can_recv() {
            let (payload, metadata) = udp.recv()?;
            ensure!(
                metadata.endpoint == SocketAddr::new(destination, 9000).into(),
                "physical-path UDP tuple changed"
            );
            if !warm {
                ensure!(payload == [0x31], "physical-path warmup changed");
                warm = true;
            } else {
                ensure!(
                    heartbeat_sent && payload == b"heartbeat" && !heartbeat,
                    "unexpected physical-path UDP response"
                );
                heartbeat = true;
            }
        }
        if warm && established && !requested_down {
            write_marker(directory, "down.request")?;
            requested_down = true;
        }
        if requested_down && down_since.is_none() && directory.join("down.ready").try_exists()? {
            ensure!(
                client
                    .peer
                    .sockets
                    .get_mut::<tcp::Socket>(client.peer.tcp)
                    .send_slice(REQUEST)?
                    == REQUEST.len(),
                "partial physical-path TCP request"
            );
            client
                .peer
                .sockets
                .get_mut::<tcp::Socket>(client.peer.tcp)
                .close();
            client
                .peer
                .sockets
                .get_mut::<udp::Socket>(client.peer.udp)
                .send_slice(b"lost-datagram", (destination, 9000))?;
            down_since = Some(start.elapsed());
        }
        if let Some(down) = down_since
            && !up_requested
            && now.saturating_sub(down) >= Duration::from_millis(1200)
            && lost_udp
            && sent_tcp
        {
            write_marker(directory, "up.request")?;
            up_requested = true;
        }
        if up_requested && !restored && directory.join("up.ready").try_exists()? {
            restored = true;
        }
        if restored && ended && !heartbeat_sent {
            ensure!(
                response == RESPONSE,
                "physical-path TCP response or EOF changed"
            );
            client
                .peer
                .sockets
                .get_mut::<udp::Socket>(client.peer.udp)
                .send_slice(b"heartbeat", (destination, 9000))?;
            heartbeat_sent = true;
        }
        if restored && ended && heartbeat {
            ensure!(response == RESPONSE, "physical-path TCP response changed");
            let done = *done_since.get_or_insert_with(Instant::now);
            if done.elapsed() >= Duration::from_millis(100) {
                println!(
                    "PASS private outer path restored: IPv6={ipv6}, down_at_least_ms=1200, elapsed_ms={}, lost_udp_not_replayed=true, tcp_write_once=true, observed_os_errors={transient_errors}",
                    start.elapsed().as_millis()
                );
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn handle_path_error(error: anyhow::Error, recovering: bool, count: &mut usize) -> Result<()> {
    if !recovering || !retryable_path_error(&error) {
        return Err(error);
    }
    if *count >= 64 {
        return Err(error.context("physical-path error limit exceeded"));
    }
    *count += 1;
    Ok(())
}

fn retryable_path_error(error: &anyhow::Error) -> bool {
    let errno = error
        .downcast_ref::<io::Error>()
        .and_then(io::Error::raw_os_error);
    matches!(errno, Some(code) if code == nix::libc::ENETUNREACH || code == nix::libc::EHOSTUNREACH || code == nix::libc::ECONNREFUSED || code == nix::libc::ENETDOWN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::fs::symlink, path::PathBuf, time::SystemTime};

    struct TemporaryDirectory(PathBuf);

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn marker_creation_never_overwrites_existing_content_or_symlinks() {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = TemporaryDirectory(PathBuf::from(format!(
            "/tmp/warper-marker-{}-{unique}",
            std::process::id()
        )));
        fs::create_dir(&directory.0).unwrap();
        write_marker(&directory.0, "marker").unwrap();
        let error = write_marker(&directory.0, "marker").unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(directory.0.join("marker")).unwrap(), b"ready\n");
        symlink(directory.0.join("marker"), directory.0.join("link")).unwrap();
        let error = write_marker(&directory.0, "link").unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::AlreadyExists
        );
        fs::remove_file(directory.0.join("link")).unwrap();
        fs::remove_file(directory.0.join("marker")).unwrap();
        fs::remove_dir(&directory.0).unwrap();
    }

    #[test]
    fn control_directory_rejects_relative_and_unowned_paths_before_mutation() {
        for path in ["relative", "/", "/tmp", "/tmp/not-a-warper-path"] {
            assert!(validate_directory(Path::new(path)).is_err(), "{path}");
        }
    }

    #[test]
    fn path_error_handling_is_bounded_and_preserves_the_underlying_failure() {
        let network_error =
            || anyhow::Error::new(io::Error::from_raw_os_error(nix::libc::ENETUNREACH));
        let mut count = 0;
        assert!(handle_path_error(network_error(), true, &mut count).is_ok());
        assert_eq!(count, 1);
        let error = handle_path_error(network_error(), false, &mut count).unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
            Some(nix::libc::ENETUNREACH)
        );
        assert_eq!(count, 1);
        let error = handle_path_error(
            io::Error::from(io::ErrorKind::PermissionDenied).into(),
            true,
            &mut count,
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        count = 64;
        let error = handle_path_error(network_error(), true, &mut count).unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
            Some(nix::libc::ENETUNREACH)
        );
        assert_eq!(count, 64);
    }

    #[test]
    fn cleanup_failures_preserve_primary_errors_and_report_secondary_failures() {
        let error = finish_client(
            Err(io::Error::from(io::ErrorKind::PermissionDenied).into()),
            Err(io::Error::from(io::ErrorKind::BrokenPipe)),
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(format!("{error:#}").contains("socket cleanup also failed"));
        let error = finish_peer(
            Err(io::Error::from(io::ErrorKind::PermissionDenied).into()),
            Err(io::Error::from(io::ErrorKind::BrokenPipe).into()),
        )
        .err()
        .unwrap();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(format!("{error:#}").contains("worker cleanup also failed"));
        let error = finish_client(
            Err(io::Error::from(io::ErrorKind::PermissionDenied).into()),
            Ok(()),
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        let error = finish_peer(
            Err(io::Error::from(io::ErrorKind::PermissionDenied).into()),
            Ok(kernel_peer::Report::default()),
        )
        .err()
        .unwrap();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        let error =
            finish_client(Ok(()), Err(io::Error::from(io::ErrorKind::BrokenPipe))).unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::BrokenPipe
        );
        let error = finish_peer(
            Ok(()),
            Err(io::Error::from(io::ErrorKind::BrokenPipe).into()),
        )
        .err()
        .unwrap();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert!(finish_client(Ok(()), Ok(())).is_ok());
        assert!(finish_peer(Ok(()), Ok(kernel_peer::Report::default())).is_ok());
    }

    #[test]
    fn retryable_errors_use_os_categories_and_reject_unrelated_failures() {
        for code in [
            nix::libc::ENETUNREACH,
            nix::libc::EHOSTUNREACH,
            nix::libc::ECONNREFUSED,
            nix::libc::ENETDOWN,
        ] {
            assert!(retryable_path_error(
                &io::Error::from_raw_os_error(code).into()
            ));
        }
        assert!(!retryable_path_error(
            &io::Error::from(io::ErrorKind::PermissionDenied).into()
        ));
        assert!(!retryable_path_error(&anyhow::anyhow!("synthetic failure")));
    }
}
