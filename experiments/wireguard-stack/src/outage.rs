// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Controlled active-tunnel outage, resource, and cancellation experiments.

use std::{
    fmt,
    net::{SocketAddr, UdpSocket},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use smoltcp::socket::{tcp, udp};

use super::{Endpoint, REQUEST, RESPONSE, TransportFailure, create_pair};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Reason {
    InvalidBudget,
    InvalidTime,
    NotReady,
    Busy,
    SetupTimeout,
    ResponseTimeout,
    LifetimeTimeout,
    StagingLimit,
    Transport,
    Cancelled,
}

#[derive(Debug)]
struct Failure {
    reason: Reason,
    source: Option<anyhow::Error>,
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "active tunnel experiment: {:?}", self.reason)
    }
}

impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|source| source.as_ref())
    }
}

impl From<Reason> for Failure {
    fn from(reason: Reason) -> Self {
        Self {
            reason,
            source: None,
        }
    }
}

#[derive(Clone, Copy)]
struct Budget {
    setup: Duration,
    lifetime: Duration,
}

struct Session {
    endpoint: Option<Endpoint>,
    budget: Budget,
    now: Duration,
    ready: bool,
    response_deadline: Option<Duration>,
    stopped: Option<Reason>,
}

impl Session {
    fn new(endpoint: Endpoint, budget: Budget) -> std::result::Result<Self, Failure> {
        if budget.setup.is_zero()
            || budget.lifetime < budget.setup
            || budget.lifetime.as_millis() > i64::MAX as u128
        {
            return Err(Reason::InvalidBudget.into());
        }
        Ok(Self {
            endpoint: Some(endpoint),
            budget,
            now: Duration::ZERO,
            ready: false,
            response_deadline: None,
            stopped: None,
        })
    }

    fn step(&mut self, now: Duration) -> std::result::Result<(), Failure> {
        if let Some(reason) = self.stopped {
            return Err(reason.into());
        }
        if now < self.now || now.as_millis() > i64::MAX as u128 {
            return Err(Reason::InvalidTime.into());
        }
        self.now = now;
        let timeout = if now >= self.budget.lifetime {
            Some(Reason::LifetimeTimeout)
        } else if !self.ready && now >= self.budget.setup {
            Some(Reason::SetupTimeout)
        } else if self
            .response_deadline
            .is_some_and(|deadline| now >= deadline)
        {
            Some(Reason::ResponseTimeout)
        } else {
            None
        };
        if let Some(reason) = timeout {
            return Err(self.stop(reason, None));
        }
        let endpoint = self.endpoint.as_mut().ok_or(Reason::Cancelled)?;
        endpoint.peer.poll(now.as_millis() as i64);
        if let Err(source) = endpoint.transport.pump(&mut endpoint.peer, now) {
            let reason = if matches!(
                source.downcast_ref::<TransportFailure>(),
                Some(TransportFailure::StagingLimit)
            ) {
                Reason::StagingLimit
            } else {
                Reason::Transport
            };
            return Err(self.stop(reason, Some(source)));
        }
        self.ready |= endpoint.transport.tunnel.stats().0.is_some();
        Ok(())
    }

    fn arm_response(&mut self, timeout: Duration) -> std::result::Result<(), Failure> {
        if let Some(reason) = self.stopped {
            return Err(reason.into());
        }
        if timeout.is_zero() || timeout > self.budget.lifetime {
            return Err(Reason::InvalidBudget.into());
        }
        if !self.ready {
            return Err(Reason::NotReady.into());
        }
        if self.response_deadline.is_some() {
            return Err(Reason::Busy.into());
        }
        self.response_deadline = Some(self.now + timeout);
        Ok(())
    }

    fn complete_response(&mut self) {
        self.response_deadline = None;
    }

    fn cancel(&mut self) {
        if self.stopped.is_none() {
            self.stop(Reason::Cancelled, None);
        }
    }

    fn endpoint(&mut self) -> std::result::Result<&mut Endpoint, Failure> {
        self.endpoint
            .as_mut()
            .ok_or_else(|| self.stopped.unwrap_or(Reason::Cancelled).into())
    }

    fn stop(&mut self, reason: Reason, source: Option<anyhow::Error>) -> Failure {
        self.stopped = Some(reason);
        self.endpoint = None;
        Failure { reason, source }
    }
}

fn fixture(ipv6: bool) -> Result<(Session, Endpoint)> {
    let (client, server) = create_pair(ipv6)?;
    Ok((
        Session::new(
            client,
            Budget {
                setup: Duration::from_secs(1),
                lifetime: Duration::from_secs(10),
            },
        )?,
        server,
    ))
}

fn destination(ipv6: bool) -> Result<SocketAddr> {
    Ok(if ipv6 {
        "[fd66:66::10]:9000"
    } else {
        "10.66.66.10:9000"
    }
    .parse()?)
}

fn server_step(server: &mut Endpoint, now: Duration) -> Result<()> {
    server.peer.poll(i64::try_from(now.as_millis())?);
    server.transport.pump(&mut server.peer, now)
}

fn connect(session: &mut Session, server: &mut Endpoint, ipv6: bool) -> Result<()> {
    let endpoint = session.endpoint()?;
    let local = SocketAddr::new(
        if ipv6 { "fd66:66::2" } else { "10.66.66.2" }.parse()?,
        40001,
    );
    endpoint
        .peer
        .sockets
        .get_mut::<tcp::Socket>(endpoint.peer.tcp)
        .connect(endpoint.peer.interface.context(), destination(ipv6)?, local)?;
    let wall = Instant::now();
    for step in 0..500 {
        ensure!(
            wall.elapsed() < Duration::from_secs(2),
            "controlled connect exceeded wall deadline"
        );
        let now = Duration::from_millis(step);
        session.step(now)?;
        server_step(server, now)?;
        if session.ready {
            let endpoint = session.endpoint()?;
            if endpoint
                .peer
                .sockets
                .get::<tcp::Socket>(endpoint.peer.tcp)
                .state()
                == tcp::State::Established
            {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(1));
    }
    anyhow::bail!("controlled connection did not establish")
}

pub fn run_probe(ipv6: bool) -> Result<()> {
    transient_outage(ipv6)?;
    setup_and_response_expiry(ipv6)?;
    staging_limit(ipv6)?;
    cancellation(ipv6)?;
    Ok(())
}

fn transient_outage(ipv6: bool) -> Result<()> {
    let (mut client, mut server) = fixture(ipv6)?;
    connect(&mut client, &mut server, ipv6)?;
    client.arm_response(Duration::from_secs(3))?;
    let start = client.now;
    let endpoint = client.endpoint()?;
    endpoint.transport.blackhole = true;
    let socket = endpoint
        .peer
        .sockets
        .get_mut::<tcp::Socket>(endpoint.peer.tcp);
    ensure!(
        socket.send_slice(REQUEST)? == REQUEST.len(),
        "partial outage request admission"
    );
    socket.close();
    endpoint
        .peer
        .sockets
        .get_mut::<udp::Socket>(endpoint.peer.udp)
        .send_slice(b"lost-datagram", destination(ipv6)?)?;
    client.step(start + Duration::from_millis(1))?;
    ensure!(
        client.endpoint()?.transport.dropped_packets >= 2,
        "blackhole did not suppress TCP and UDP"
    );
    server_step(&mut server, start + Duration::from_millis(1))?;
    ensure!(
        !server
            .peer
            .sockets
            .get::<tcp::Socket>(server.peer.tcp)
            .can_recv()
            && !server
                .peer
                .sockets
                .get::<udp::Socket>(server.peer.udp)
                .can_recv(),
        "outage delivered application data"
    );
    client.endpoint()?.transport.blackhole = false;
    let endpoint = client.endpoint()?;
    endpoint
        .peer
        .sockets
        .get_mut::<udp::Socket>(endpoint.peer.udp)
        .send_slice(b"post-outage", destination(ipv6)?)?;
    let (mut request, mut response) = (Vec::new(), Vec::new());
    let (mut replied, mut udp_received) = (false, false);
    let wall = Instant::now();
    for step in 2..2000 {
        ensure!(
            wall.elapsed() < Duration::from_secs(3),
            "outage recovery exceeded wall deadline"
        );
        let now = start + Duration::from_millis(step);
        client.step(now)?;
        server_step(&mut server, now)?;
        let socket = server.peer.sockets.get_mut::<tcp::Socket>(server.peer.tcp);
        for _ in 0..2 {
            if !socket.can_recv() {
                break;
            }
            socket.recv(|bytes| {
                request.extend_from_slice(bytes);
                (bytes.len(), ())
            })?;
            ensure!(
                request.len() <= REQUEST.len(),
                "outage replayed TCP application bytes"
            );
        }
        if !replied && !socket.may_recv() && socket.can_send() {
            ensure!(request == REQUEST, "outage changed request bytes or FIN");
            ensure!(
                socket.send_slice(RESPONSE)? == RESPONSE.len(),
                "partial outage response admission"
            );
            socket.close();
            replied = true;
        }
        let socket = server.peer.sockets.get_mut::<udp::Socket>(server.peer.udp);
        if socket.can_recv() {
            let (payload, _) = socket.recv()?;
            ensure!(
                !udp_received && payload == b"post-outage",
                "lost UDP was replayed or datagram duplicated"
            );
            udp_received = true;
        }
        let endpoint = client.endpoint()?;
        let socket = endpoint
            .peer
            .sockets
            .get_mut::<tcp::Socket>(endpoint.peer.tcp);
        for _ in 0..2 {
            if !socket.can_recv() {
                break;
            }
            socket.recv(|bytes| {
                response.extend_from_slice(bytes);
                (bytes.len(), ())
            })?;
            ensure!(
                response.len() <= RESPONSE.len(),
                "outage duplicated response bytes"
            );
        }
        if replied && udp_received && !socket.may_recv() {
            ensure!(response == RESPONSE, "response after outage/FIN changed");
            client.complete_response();
            let address = endpoint_address(&mut client)?;
            client.cancel();
            UdpSocket::bind(address).context("cancel did not release outage transport")?;
            return Ok(());
        }
        thread::sleep(Duration::from_millis(1));
    }
    anyhow::bail!("TCP did not retransmit across controlled outage")
}

fn endpoint_address(session: &mut Session) -> Result<SocketAddr> {
    Ok(session.endpoint()?.transport.socket.local_addr()?)
}

fn setup_and_response_expiry(ipv6: bool) -> Result<()> {
    let (mut client, _server) = fixture(ipv6)?;
    let address = endpoint_address(&mut client)?;
    let endpoint = client.endpoint()?;
    endpoint.transport.blackhole = true;
    endpoint
        .peer
        .sockets
        .get_mut::<udp::Socket>(endpoint.peer.udp)
        .send_slice(b"setup", destination(ipv6)?)?;
    client.step(Duration::ZERO)?;
    ensure!(
        client
            .step(Duration::from_secs(1))
            .is_err_and(|failure| failure.reason == Reason::SetupTimeout),
        "setup loss did not expire"
    );
    UdpSocket::bind(address).context("setup expiry retained outer socket")?;

    let (mut client, mut server) = fixture(ipv6)?;
    connect(&mut client, &mut server, ipv6)?;
    let address = endpoint_address(&mut client)?;
    client.arm_response(Duration::from_millis(100))?;
    let now = client.now;
    let endpoint = client.endpoint()?;
    endpoint.transport.blackhole = true;
    endpoint
        .peer
        .sockets
        .get_mut::<udp::Socket>(endpoint.peer.udp)
        .send_slice(b"request", destination(ipv6)?)?;
    client.step(now + Duration::from_millis(1))?;
    ensure!(
        client
            .step(now + Duration::from_millis(100))
            .is_err_and(|failure| failure.reason == Reason::ResponseTimeout),
        "established session masked request loss"
    );
    UdpSocket::bind(address).context("response expiry retained outer socket")?;
    Ok(())
}

fn staging_limit(ipv6: bool) -> Result<()> {
    let (mut client, _server) = fixture(ipv6)?;
    let address = endpoint_address(&mut client)?;
    for step in 0..=super::PACKET_CAPACITY {
        let endpoint = client.endpoint()?;
        endpoint
            .peer
            .sockets
            .get_mut::<udp::Socket>(endpoint.peer.udp)
            .send_slice(b"queued", destination(ipv6)?)?;
        let result = client.step(Duration::from_millis(step as u64));
        if step == super::PACKET_CAPACITY {
            ensure!(
                result.is_err_and(|failure| failure.reason == Reason::StagingLimit),
                "staging silently exceeded budget"
            );
        } else {
            result?;
        }
    }
    UdpSocket::bind(address).context("staging failure retained outer socket")?;
    Ok(())
}

fn cancellation(ipv6: bool) -> Result<()> {
    for connected in [false, true] {
        let (mut client, mut server) = fixture(ipv6)?;
        if connected {
            connect(&mut client, &mut server, ipv6)?;
        } else {
            let endpoint = client.endpoint()?;
            endpoint.transport.blackhole = true;
            endpoint
                .peer
                .sockets
                .get_mut::<udp::Socket>(endpoint.peer.udp)
                .send_slice(b"pending-setup", destination(ipv6)?)?;
            client.step(Duration::ZERO)?;
            ensure!(
                client.endpoint()?.transport.staged_packets == 1,
                "setup cancellation did not own queued plaintext"
            );
        }
        let address = endpoint_address(&mut client)?;
        client.cancel();
        client.cancel();
        ensure!(
            client
                .step(Duration::ZERO)
                .is_err_and(|failure| failure.reason == Reason::Cancelled),
            "cancelled session resumed"
        );
        UdpSocket::bind(address).context("cancel retained outer socket")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_tunnel_outage_and_cancellation_preserve_owned_boundaries() {
        for ipv6 in [false, true] {
            run_probe(ipv6).unwrap();
        }
    }

    #[test]
    fn full_staging_queue_drains_all_packets_and_the_done_sentinel() {
        for ipv6 in [false, true] {
            let (mut client, mut server) = fixture(ipv6).unwrap();
            for step in 0..super::super::PACKET_CAPACITY {
                let endpoint = client.endpoint().unwrap();
                endpoint
                    .peer
                    .sockets
                    .get_mut::<udp::Socket>(endpoint.peer.udp)
                    .send_slice(&[step as u8], destination(ipv6).unwrap())
                    .unwrap();
                client.step(Duration::from_millis(step as u64)).unwrap();
            }
            assert_eq!(client.endpoint().unwrap().transport.staged_packets, 64);
            server_step(&mut server, Duration::from_millis(65)).unwrap();
            client.step(Duration::from_millis(66)).unwrap();
            assert_eq!(client.endpoint().unwrap().transport.staged_packets, 0);
            let mut observed = 0;
            let mut bytes = [0; super::super::MTU + 256];
            for _ in 0..66 {
                match server.transport.socket.recv_from(&mut bytes) {
                    Ok((length, _)) => {
                        if bytes[0] == 4 && length > 32 {
                            observed += 1;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("controlled UDP receiver failed: {error}"),
                }
            }
            assert_eq!(
                observed, 64,
                "all staged IP packets must reach the outer socket without silent loss"
            );
        }
    }

    #[test]
    fn clock_and_budget_validation_preserves_live_resources_until_cancel() {
        let (mut client, _server) = fixture(false).unwrap();
        let address = endpoint_address(&mut client).unwrap();
        assert_eq!(
            client
                .arm_response(Duration::from_secs(1))
                .unwrap_err()
                .reason,
            Reason::NotReady
        );
        assert_eq!(
            client.arm_response(Duration::ZERO).unwrap_err().reason,
            Reason::InvalidBudget
        );
        client.step(Duration::from_millis(100)).unwrap();
        for now in [Duration::ZERO, Duration::MAX] {
            assert_eq!(client.step(now).unwrap_err().reason, Reason::InvalidTime);
            assert!(
                UdpSocket::bind(address).is_err(),
                "invalid input must not mutate ownership"
            );
        }
        client.cancel();
        UdpSocket::bind(address).unwrap();
        for budget in [
            Budget {
                setup: Duration::ZERO,
                lifetime: Duration::from_secs(1),
            },
            Budget {
                setup: Duration::from_secs(2),
                lifetime: Duration::from_secs(1),
            },
            Budget {
                setup: Duration::from_secs(1),
                lifetime: Duration::MAX,
            },
        ] {
            let (endpoint, _server) = create_pair(false).unwrap();
            assert!(matches!(
                Session::new(endpoint, budget),
                Err(Failure {
                    reason: Reason::InvalidBudget,
                    ..
                })
            ));
        }
    }

    #[test]
    fn response_reservation_is_explicit_and_lifetime_expiry_preserves_terminal_reason() {
        let (mut client, mut server) = fixture(false).unwrap();
        connect(&mut client, &mut server, false).unwrap();
        let address = endpoint_address(&mut client).unwrap();
        client.arm_response(Duration::from_secs(1)).unwrap();
        assert_eq!(
            client
                .arm_response(Duration::from_secs(1))
                .unwrap_err()
                .reason,
            Reason::Busy
        );
        client.complete_response();
        client.arm_response(Duration::from_secs(1)).unwrap();
        client.complete_response();
        assert_eq!(
            client.step(Duration::from_secs(10)).unwrap_err().reason,
            Reason::LifetimeTimeout
        );
        client.cancel();
        assert_eq!(
            client.step(Duration::from_secs(11)).unwrap_err().reason,
            Reason::LifetimeTimeout
        );
        assert!(matches!(
            client.endpoint(),
            Err(Failure {
                reason: Reason::LifetimeTimeout,
                ..
            })
        ));
        UdpSocket::bind(address).unwrap();
    }

    #[test]
    fn unexpected_outer_peer_is_fatal_with_preserved_source_and_socket_cleanup() {
        let (mut client, _server) = fixture(false).unwrap();
        let address = endpoint_address(&mut client).unwrap();
        let stranger = UdpSocket::bind("127.0.0.1:0").unwrap();
        stranger.send_to(&[0], address).unwrap();
        let failure = client.step(Duration::ZERO).unwrap_err();
        assert_eq!(failure.reason, Reason::Transport);
        assert!(std::error::Error::source(&failure).is_some());
        client.cancel();
        assert_eq!(
            client.step(Duration::ZERO).unwrap_err().reason,
            Reason::Transport
        );
        UdpSocket::bind(address).unwrap();
    }

    #[test]
    fn dropping_an_unstarted_session_releases_its_outer_socket() {
        let (mut client, _server) = fixture(false).unwrap();
        let address = endpoint_address(&mut client).unwrap();
        drop(client);
        UdpSocket::bind(address).unwrap();
    }

    #[test]
    fn partial_fragment_cancellation_and_fatal_overlap_release_the_session() {
        use crate::fragment_probe::{address, fragments, warm_up};
        for ipv6 in [false, true] {
            for cancel in [false, true] {
                let (mut endpoint, mut server) = crate::create_pair(ipv6).unwrap();
                let now = warm_up(&mut endpoint, &mut server).unwrap();
                let outer = endpoint.transport.socket.local_addr().unwrap();
                let packets =
                    fragments(&mut server, address(&endpoint), &[0x53; 200], now, 46).unwrap();
                let mut client = Session::new(
                    endpoint,
                    Budget {
                        setup: Duration::from_secs(5),
                        lifetime: Duration::from_secs(10),
                    },
                )
                .unwrap();
                server.peer.device.outgoing.push_back(packets[0].clone());
                server.transport.pump(&mut server.peer, now).unwrap();
                client.step(now).unwrap();
                assert!(
                    client
                        .endpoint
                        .as_ref()
                        .unwrap()
                        .transport
                        .reassembly
                        .next_deadline()
                        .is_some()
                );
                let expected = if cancel {
                    client.cancel();
                    Reason::Cancelled
                } else {
                    server.peer.device.outgoing.push_back(packets[0].clone());
                    server.transport.pump(&mut server.peer, now).unwrap();
                    let failure = client.step(now).unwrap_err();
                    assert_eq!(failure.reason, Reason::Transport);
                    assert_eq!(
                        failure
                            .source
                            .as_ref()
                            .unwrap()
                            .downcast_ref::<crate::reassembly::Error>(),
                        Some(&crate::reassembly::Error::Overlap)
                    );
                    Reason::Transport
                };
                assert!(client.endpoint.is_none());
                assert_eq!(client.step(now).unwrap_err().reason, expected);
                UdpSocket::bind(outer).unwrap();
            }
        }
    }

    #[test]
    fn reserved_udp_errors_and_cancellation_release_the_owner() {
        for ipv6 in [false, true] {
            for action in ["feedback", "cancel", "expire"] {
                let (mut client, mut server) = fixture(ipv6).unwrap();
                let address = endpoint_address(&mut client).unwrap();
                let mut target = destination(ipv6).unwrap();
                target.set_port(9001);
                let endpoint = client.endpoint().unwrap();
                endpoint
                    .peer
                    .sockets
                    .get_mut::<udp::Socket>(endpoint.peer.udp)
                    .send_slice(&[0x53; 257], target)
                    .unwrap();
                endpoint.peer.poll(0);
                let packet = endpoint.peer.device.outgoing.front().unwrap().clone();
                endpoint.transport.watch_udp(&packet).unwrap();
                assert_eq!(
                    endpoint
                        .transport
                        .watch_udp(&packet)
                        .unwrap_err()
                        .downcast_ref::<crate::udp_feedback::Error>(),
                    Some(&crate::udp_feedback::Error::Busy)
                );
                if action == "cancel" {
                    client.cancel();
                    assert_eq!(
                        client.step(Duration::ZERO).unwrap_err().reason,
                        Reason::Cancelled
                    );
                } else if action == "expire" {
                    assert_eq!(
                        client.step(Duration::from_secs(10)).unwrap_err().reason,
                        Reason::LifetimeTimeout
                    );
                } else {
                    let wall = Instant::now();
                    let failure = loop {
                        assert!(wall.elapsed() < Duration::from_secs(2));
                        let now = wall.elapsed();
                        if let Err(failure) = client.step(now) {
                            break failure;
                        }
                        server_step(&mut server, now).unwrap();
                        thread::sleep(Duration::from_millis(1));
                    };
                    assert_eq!(failure.reason, Reason::Transport);
                    assert_eq!(
                        failure
                            .source
                            .as_ref()
                            .unwrap()
                            .downcast_ref::<crate::udp_feedback::Error>(),
                        Some(&crate::udp_feedback::Error::PortUnreachable)
                    );
                }
                assert!(client.endpoint.is_none());
                UdpSocket::bind(address).unwrap();
            }
        }
    }
}
