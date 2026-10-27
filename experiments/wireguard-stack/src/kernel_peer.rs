// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Linux kernel WireGuard interoperability, restricted to mapped namespaces.

use std::{
    fs,
    io::{self, Read, Write},
    net::{IpAddr, Shutdown, SocketAddr, TcpListener, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use boringtun::x25519::{PublicKey, StaticSecret};
use wireguard_uapi::{DeviceInterface, WgSocket, set};

use super::{
    REKEY_DURATION, REQUEST, RESPONSE, create_client, loopback_address, run_client_with_outage,
};

const INTERFACE: &str = "wg-feasibility";
const WORKER_POLL: Duration = Duration::from_millis(2);
const READ_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Default)]
pub(super) struct Report {
    pub tcp: usize,
    pub udp: usize,
    pub bytes: usize,
}

pub(super) struct Workers {
    stop: Arc<AtomicBool>,
    handles: Vec<JoinHandle<Result<Report>>>,
}

impl Workers {
    fn start(address: IpAddr, duration: Duration, response_sent: Arc<AtomicBool>) -> Result<Self> {
        let listener = TcpListener::bind((address, 9000))?;
        let udp = UdpSocket::bind((address, 9000))?;
        Self::start_sockets(listener, udp, duration, Some(response_sent))
    }

    fn start_sockets(
        listener: TcpListener,
        udp: UdpSocket,
        duration: Duration,
        response_sent: Option<Arc<AtomicBool>>,
    ) -> Result<Self> {
        listener.set_nonblocking(true)?;
        udp.set_nonblocking(true)?;
        let mut workers = Self {
            stop: Arc::new(AtomicBool::new(false)),
            handles: Vec::with_capacity(2),
        };
        let deadline = Instant::now() + duration + Duration::from_secs(10);
        let stop = workers.stop.clone();
        workers.handles.push(
            thread::Builder::new()
                .name("kernel-peer-tcp".into())
                .spawn(move || {
                    tcp_server(
                        &listener,
                        &stop,
                        deadline,
                        REQUEST,
                        RESPONSE,
                        response_sent.as_deref(),
                    )
                })?,
        );
        let stop = workers.stop.clone();
        match thread::Builder::new()
            .name("kernel-peer-udp".into())
            .spawn(move || udp_server(udp, &stop, deadline))
        {
            Ok(handle) => workers.handles.push(handle),
            Err(primary) => {
                let cleanup = workers.finish();
                return Err(anyhow::Error::new(primary).context(match cleanup {
                    Ok(_) => "UDP worker startup failed; prior worker joined".into(),
                    Err(error) => {
                        format!("UDP worker startup failed; cleanup also failed: {error}")
                    }
                }));
            }
        }
        Ok(workers)
    }

    pub(super) fn start_tcp(
        listener: TcpListener,
        request: Vec<u8>,
        response: &'static [u8],
    ) -> Result<Self> {
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let deadline = Instant::now() + Duration::from_secs(6);
        let handle = thread::Builder::new()
            .name("kernel-mtu-tcp".into())
            .spawn(move || {
                tcp_server(&listener, &worker_stop, deadline, &request, response, None)
            })?;
        Ok(Self {
            stop,
            handles: vec![handle],
        })
    }

    pub(super) fn start_udp(sockets: [UdpSocket; 2]) -> Result<Self> {
        for socket in &sockets {
            socket.set_nonblocking(true)?;
        }
        let mut workers = Self {
            stop: Arc::new(AtomicBool::new(false)),
            handles: Vec::with_capacity(2),
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        for socket in sockets {
            let stop = workers.stop.clone();
            match thread::Builder::new()
                .name("router-peer-udp".into())
                .spawn(move || udp_server(socket, &stop, deadline))
            {
                Ok(handle) => workers.handles.push(handle),
                Err(primary) => {
                    let cleanup = workers.finish();
                    return Err(anyhow::Error::new(primary).context(match cleanup {
                        Ok(_) => "prior UDP workers joined".into(),
                        Err(error) => format!("UDP worker startup cleanup also failed: {error}"),
                    }));
                }
            }
        }
        Ok(workers)
    }

    pub(super) fn start_router(
        sockets: [UdpSocket; 2],
        listeners: [TcpListener; 2],
        request: Vec<u8>,
        response: &'static [u8],
    ) -> Result<Self> {
        for listener in &listeners {
            listener.set_nonblocking(true)?;
        }
        let mut workers = Self::start_udp(sockets)?;
        let deadline = Instant::now() + Duration::from_secs(15);
        for listener in listeners {
            let stop = workers.stop.clone();
            let request = request.clone();
            match thread::Builder::new()
                .name("router-peer-tcp".into())
                .spawn(move || {
                    let mut report = Report::default();
                    for _ in 0..2 {
                        let completed =
                            tcp_server(&listener, &stop, deadline, &request, response, None)?;
                        report.tcp += completed.tcp;
                        report.bytes += completed.bytes;
                    }
                    Ok(report)
                }) {
                Ok(handle) => workers.handles.push(handle),
                Err(primary) => {
                    let cleanup = workers.finish();
                    return Err(anyhow::Error::new(primary).context(match cleanup {
                        Ok(_) => "prior router workers joined".into(),
                        Err(error) => format!("router worker startup cleanup also failed: {error}"),
                    }));
                }
            }
        }
        Ok(workers)
    }

    pub(super) fn finish(&mut self) -> Result<Report> {
        self.stop.store(true, Ordering::Release);
        let mut report = Report::default();
        let mut errors = Vec::new();
        for handle in self.handles.drain(..) {
            match handle.join() {
                Ok(Ok(result)) => {
                    report.tcp += result.tcp;
                    report.udp += result.udp;
                    report.bytes += result.bytes;
                }
                Ok(Err(error)) => errors.push(error.to_string()),
                Err(_) => errors.push("kernel peer worker panicked".into()),
            }
        }
        ensure!(errors.is_empty(), "kernel peer worker failures: {errors:?}");
        Ok(report)
    }
}

impl Drop for Workers {
    fn drop(&mut self) {
        if !self.handles.is_empty() && self.finish().is_err() {
            eprintln!("kernel peer cleanup failed during unwinding");
        }
    }
}

pub(super) fn configure() -> Result<(WgSocket, u16)> {
    configure_with_port(0)
}

pub(super) fn configure_with_port(port: u16) -> Result<(WgSocket, u16)> {
    require_mapped_namespace()?;
    let mut netlink =
        WgSocket::connect().map_err(|_| anyhow::anyhow!("kernel WireGuard netlink unavailable"))?;
    let original = read_device(&mut netlink)?;
    ensure!(
        original.peers.is_empty() && original.public_key.is_none_or(|key| key == [0; 32]),
        "refusing to overwrite a configured WireGuard interface"
    );
    // Public synthetic fixture keys. No key-bearing netlink message is logged.
    let private_key = [0x22; 32];
    let client_key = PublicKey::from(&StaticSecret::from([0x11; 32])).to_bytes();
    let client_v4: IpAddr = "10.66.66.2".parse()?;
    let client_v6: IpAddr = "fd66:66::2".parse()?;
    let peer = set::Peer::from_public_key(&client_key)
        .flags(vec![set::WgPeerF::ReplaceAllowedIps])
        .allowed_ips(vec![
            set::AllowedIp::from_ipaddr(&client_v4),
            set::AllowedIp::from_ipaddr(&client_v6),
        ]);
    netlink
        .set_device(
            set::Device::from_ifname(INTERFACE)
                .flags(vec![set::WgDeviceF::ReplacePeers])
                .private_key(&private_key)
                .listen_port(port)
                .peers(vec![peer]),
        )
        .map_err(|_| anyhow::anyhow!("kernel WireGuard configuration failed"))?;
    // The library does not expose a full ACK contract. Require readback and real traffic.
    let configured = read_device(&mut netlink)?;
    let server_public = PublicKey::from(&StaticSecret::from(private_key)).to_bytes();
    ensure!(
        configured.public_key == Some(server_public)
            && configured.listen_port != 0
            && (port == 0 || configured.listen_port == port)
            && configured.peers.len() == 1
            && configured.peers[0].public_key == client_key,
        "kernel WireGuard configuration readback mismatch"
    );
    let mut allowed: Vec<_> = configured.peers[0]
        .allowed_ips
        .iter()
        .map(|ip| (ip.ipaddr, ip.cidr_mask))
        .collect();
    allowed.sort();
    let mut expected = vec![(client_v4, 32), (client_v6, 128)];
    expected.sort();
    ensure!(
        allowed == expected,
        "kernel WireGuard allowed-address readback mismatch"
    );
    Ok((netlink, configured.listen_port))
}

pub fn run(rekey: bool) -> Result<()> {
    let (mut netlink, port) = configure()?;
    for ipv6 in [false, true] {
        let mut endpoint = loopback_address(ipv6);
        endpoint.set_port(port);
        exchange(ipv6, Duration::ZERO, endpoint)?;
        verify_handshake(&mut netlink, false)?;
        super::udp_feedback_probe::run_kernel(ipv6, endpoint)?;
        println!("PASS independent kernel UDP port-unreachable propagation, IPv6={ipv6}");
        println!(
            "PASS independent Linux kernel peer: TCP/UDP, empty datagram, FIN, inner_ipv6={ipv6}, outer_ipv6={ipv6}"
        );
    }
    if rekey {
        let mut endpoint = loopback_address(true);
        endpoint.set_port(port);
        exchange(false, REKEY_DURATION, endpoint)?;
        verify_handshake(&mut netlink, true)?;
        println!(
            "PASS independent Linux kernel peer: sustained IPv4 inner traffic over IPv6 outer transport across completed rekey"
        );
    }
    Ok(())
}

pub(super) fn require_mapped_namespace() -> Result<()> {
    let mapping =
        fs::read_to_string("/proc/self/uid_map").context("cannot inspect namespace ownership")?;
    ensure!(
        single_uid_mapping(&mapping),
        "network fixture requires an isolated single-UID user/network namespace"
    );
    Ok(())
}

fn single_uid_mapping(mapping: &str) -> bool {
    let rows: Vec<_> = mapping
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    if rows.len() != 1 {
        return false;
    }
    let fields: Vec<_> = rows[0].split_whitespace().collect();
    fields.len() == 3 && fields[0] == "0" && fields[1].parse::<u32>().is_ok() && fields[2] == "1"
}

fn read_device(netlink: &mut WgSocket) -> Result<wireguard_uapi::get::Device> {
    netlink
        .get_device(DeviceInterface::Name(INTERFACE.into()))
        .map_err(|_| anyhow::anyhow!("kernel WireGuard state read failed"))
}

pub(super) fn verify_handshake(netlink: &mut WgSocket, rekey: bool) -> Result<()> {
    let device = read_device(netlink)?;
    ensure!(device.peers.len() == 1, "kernel peer count changed");
    let peer = &device.peers[0];
    ensure!(
        !peer.last_handshake_time.is_zero() && peer.rx_bytes > 0 && peer.tx_bytes > 0,
        "kernel peer did not observe a completed bidirectional exchange"
    );
    if rekey {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
        ensure!(
            now.checked_sub(peer.last_handshake_time)
                .is_some_and(|age| age < Duration::from_secs(30)),
            "kernel peer did not observe a recent completed rekey"
        );
    }
    Ok(())
}

fn exchange(ipv6: bool, duration: Duration, endpoint: SocketAddr) -> Result<()> {
    let address: IpAddr = if ipv6 { "fd66:66::10" } else { "10.66.66.10" }.parse()?;
    let (mut client, mut transport) = create_client(ipv6, endpoint)?;
    let require_retry = !ipv6 && duration.is_zero();
    transport.drop_first_handshake = require_retry;
    let inject_outage = duration.is_zero();
    let worker_duration = duration
        + if inject_outage {
            Duration::from_secs(15)
        } else {
            Duration::ZERO
        };
    let response_sent = Arc::new(AtomicBool::new(false));
    let mut workers = Workers::start(address, worker_duration, response_sent.clone())?;
    let result = run_client_with_outage(
        ipv6,
        duration,
        &mut client,
        &mut transport,
        None,
        inject_outage,
        inject_outage.then_some(response_sent.as_ref()),
    );
    let cleanup = workers.finish();
    let report = match (result, cleanup) {
        (Err(primary), cleanup) => {
            return Err(primary.context(match cleanup {
                Ok(_) => "kernel peer workers joined".into(),
                Err(error) => format!("kernel peer cleanup also failed: {error}"),
            }));
        }
        (Ok(()), report) => report?,
    };
    ensure!(
        report.tcp == 1 && report.udp >= 4,
        "kernel peer did not verify the complete workload"
    );
    if inject_outage {
        ensure!(
            transport.dropped_packets >= 3
                && !transport.blackhole
                && transport.dropped_inbound > 0
                && !transport.inbound_blackhole,
            "kernel workload did not complete the controlled outage"
        );
        ensure!(
            report.udp == 5,
            "kernel peer did not receive exactly the original datagrams and recovery heartbeat"
        );
        println!("PASS independent inbound blackout: response recovery, IPv6={ipv6}");
        println!(
            "PASS independent kernel outage: at least 1200ms blackout, TCP retry during outage and FIN, lost UDP not replayed, IPv6={ipv6}"
        );
    }
    if require_retry {
        ensure!(
            transport.dropped_handshakes == 1 && transport.initiations >= 2,
            "controlled handshake loss did not exercise protocol retry"
        );
        println!(
            "PASS independent peer recovered after one deliberately dropped handshake initiation"
        );
    }
    println!(
        "kernel peer verified: tcp={}, udp={}, application_bytes={}",
        report.tcp, report.udp, report.bytes
    );
    Ok(())
}

fn tcp_server(
    listener: &TcpListener,
    stop: &AtomicBool,
    deadline: Instant,
    expected_request: &[u8],
    response: &[u8],
    response_sent: Option<&AtomicBool>,
) -> Result<Report> {
    let (mut connection, source) = loop {
        ensure!(
            !stop.load(Ordering::Acquire) && Instant::now() < deadline,
            "kernel TCP peer stopped before accept"
        );
        match listener.accept() {
            Ok(accepted) => break accepted,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(WORKER_POLL),
            Err(error) => return Err(error.into()),
        }
    };
    let expected: IpAddr = if source.is_ipv6() {
        "fd66:66::2"
    } else {
        "10.66.66.2"
    }
    .parse()?;
    ensure!(
        source == SocketAddr::new(expected, 40001),
        "kernel TCP peer source changed"
    );
    connection.set_read_timeout(Some(READ_TIMEOUT))?;
    connection.set_write_timeout(Some(READ_TIMEOUT))?;
    let mut request = Vec::with_capacity(expected_request.len());
    let mut bytes = [0; 128];
    loop {
        ensure!(
            !stop.load(Ordering::Acquire) && Instant::now() < deadline,
            "kernel TCP peer stopped before EOF"
        );
        match connection.read(&mut bytes) {
            Ok(0) => break,
            Ok(count) => {
                ensure!(
                    request.len() + count <= expected_request.len(),
                    "kernel TCP request exceeded budget"
                );
                request.extend_from_slice(&bytes[..count]);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    ensure!(request == expected_request, "kernel TCP request changed");
    connection.write_all(response)?;
    if let Some(flag) = response_sent {
        flag.store(true, Ordering::Release);
    }
    connection.shutdown(Shutdown::Write)?;
    Ok(Report {
        tcp: 1,
        udp: 0,
        bytes: expected_request.len() + response.len(),
    })
}

fn udp_server(socket: UdpSocket, stop: &AtomicBool, deadline: Instant) -> Result<Report> {
    let mut report = Report::default();
    let mut bytes = [0; 1280];
    while !stop.load(Ordering::Acquire) {
        ensure!(
            Instant::now() < deadline,
            "kernel UDP peer exceeded deadline"
        );
        let (count, source) = match socket.recv_from(&mut bytes) {
            Ok(received) => received,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(WORKER_POLL);
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let expected: IpAddr = if source.is_ipv6() {
            "fd66:66::2"
        } else {
            "10.66.66.2"
        }
        .parse()?;
        ensure!(
            source == SocketAddr::new(expected, 40000),
            "kernel UDP peer source changed"
        );
        let payload = &bytes[..count];
        ensure!(
            payload.is_empty()
                || payload == [0x31]
                || payload == [0x72; 257]
                || (payload.len() == if source.is_ipv6() { 1232 } else { 1252 }
                    && payload.iter().all(|byte| *byte == 0x53))
                || payload == b"heartbeat"
                || payload == crate::router_mtu::OWNED_MESSAGE,
            "kernel UDP payload did not match synthetic workload"
        );
        ensure!(
            socket.send_to(payload, source)? == count,
            "kernel UDP response was partial"
        );
        report.udp += 1;
        report.bytes += count * 2;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_guard_rejects_initial_and_broad_uid_mappings() {
        assert!(single_uid_mapping("0 1000 1\n"));
        for mapping in [
            "0 0 4294967295\n",
            "1000 1000 1\n",
            "0 1000 1\n1 1001 1\n",
            "",
            "0 invalid 1",
        ] {
            assert!(!single_uid_mapping(mapping), "{mapping:?}");
        }
    }

    #[test]
    fn worker_shutdown_joins_idle_readers_and_releases_sockets() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp_address = listener.local_addr().unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_address = udp.local_addr().unwrap();
        let mut workers = Workers::start_sockets(listener, udp, Duration::ZERO, None).unwrap();
        assert!(
            workers.finish().is_err(),
            "incomplete TCP work must not report peer success"
        );
        assert!(std::net::TcpStream::connect_timeout(&tcp_address, READ_TIMEOUT).is_err());
        UdpSocket::bind(udp_address).unwrap();
    }

    #[test]
    fn udp_only_workers_join_and_release_both_listeners() {
        let sockets = [
            UdpSocket::bind("127.0.0.1:0").unwrap(),
            UdpSocket::bind("127.0.0.1:0").unwrap(),
        ];
        let addresses = sockets
            .each_ref()
            .map(|socket| socket.local_addr().unwrap());
        let mut workers = Workers::start_udp(sockets).unwrap();
        assert_eq!(workers.finish().unwrap().udp, 0);
        assert!(workers.handles.is_empty());
        for address in addresses {
            UdpSocket::bind(address).unwrap();
        }
    }

    #[test]
    fn router_workers_join_incomplete_tcp_and_release_all_listeners() {
        let sockets = [
            UdpSocket::bind("127.0.0.1:0").unwrap(),
            UdpSocket::bind("127.0.0.1:0").unwrap(),
        ];
        let listeners = [
            TcpListener::bind("127.0.0.1:0").unwrap(),
            TcpListener::bind("127.0.0.1:0").unwrap(),
        ];
        let udp_addresses = sockets
            .each_ref()
            .map(|socket| socket.local_addr().unwrap());
        let tcp_addresses = listeners
            .each_ref()
            .map(|listener| listener.local_addr().unwrap());
        let mut workers =
            Workers::start_router(sockets, listeners, b"sample".to_vec(), b"reply").unwrap();
        assert!(
            workers.finish().is_err(),
            "incomplete TCP cases cannot report router workload success"
        );
        assert!(workers.handles.is_empty());
        for address in udp_addresses {
            UdpSocket::bind(address).unwrap();
        }
        for address in tcp_addresses {
            TcpListener::bind(address).unwrap();
        }
    }

    #[test]
    fn single_tcp_worker_cancels_and_releases_its_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut workers = Workers::start_tcp(listener, b"sample".to_vec(), b"reply").unwrap();
        assert!(
            workers.finish().is_err(),
            "cancellation cannot claim completed TCP work"
        );
        assert!(workers.handles.is_empty());
        TcpListener::bind(address).unwrap();
    }

    #[test]
    fn single_tcp_worker_rejects_foreign_source_and_joins_its_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut workers = Workers::start_tcp(listener, b"sample".to_vec(), b"reply").unwrap();
        let mut client = std::net::TcpStream::connect_timeout(&address, READ_TIMEOUT).unwrap();
        client.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
        if let Err(error) = client.write_all(b"sample") {
            assert!(matches!(
                error.kind(),
                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
            ));
        }
        if let Err(error) = client.shutdown(Shutdown::Write) {
            assert!(matches!(
                error.kind(),
                io::ErrorKind::NotConnected | io::ErrorKind::ConnectionReset
            ));
        }
        let received = client.read(&mut [0; 32]);
        assert!(
            matches!(received, Ok(0))
                || matches!(received, Err(ref error) if error.kind() == io::ErrorKind::ConnectionReset)
        );
        assert!(
            workers.finish().is_err(),
            "worker validation failures must reach the owner"
        );
        assert!(workers.handles.is_empty());
        drop(client);
        TcpListener::bind(address).unwrap();
    }

    #[test]
    fn udp_peer_rejects_unapproved_source_without_reply() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let address = socket.local_addr().unwrap();
        let handle = thread::spawn(move || {
            udp_server(
                socket,
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(1),
            )
        });
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
        client.send_to(b"sample", address).unwrap();
        assert!(handle.join().unwrap().is_err());
        assert!(client.recv_from(&mut [0; 16]).is_err());
    }
}
