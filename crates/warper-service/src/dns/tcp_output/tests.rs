// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Real host stack, controlled TCP peer and explicitly modeled native commits.

use super::*;
use crate::dns::{Limits, routes::Controller};
use std::{
    future::Future,
    task::{Context, Poll, Waker},
};
use tokio::sync::watch;
use warper_config::schema::RoutingMode;
use warper_core::{BackendId, dns::Name, routing::Policy};
use warper_stack::{
    Seed,
    host::{HostAdapter, Limits as HostLimits},
};

struct Fixture {
    host: HostAdapter,
    connection: Option<Connection<AcceptedStream>>,
    controller: Arc<Controller>,
    query: Packet,
    reply: Option<Reply>,
    route: lease::Route,
    owner: watch::Sender<bool>,
}
impl Fixture {
    fn new() -> Self {
        let origin = Instant::now();
        let controller = Arc::new(
            Controller::new(
                Arc::new(Policy::new(&[], 2).unwrap()),
                lease::Limits {
                    lease_entries: 2,
                    route_entries: 2,
                    response_entries: 2,
                    flow_entries: 2,
                    addresses_per_response: 1,
                    bytes: 128 * 1024,
                },
                origin,
            )
            .unwrap(),
        );
        let (mut host, _backend, mut dns) = HostAdapter::with_dns(
            HostLimits::default(),
            controller.selector(),
            Seed::generate().unwrap(),
            "192.0.2.53:53".parse().unwrap(),
        )
        .unwrap();
        host.inject(&tcp(100, 0, 2)).unwrap();
        poll_host(&mut host, 0);
        let syn_ack = host.take_packet().unwrap();
        assert_eq!(syn_ack[33] & 0x12, 0x12);
        let sequence = u32::from_be_bytes(syn_ack[24..28].try_into().unwrap());
        host.inject(&tcp(101, sequence.wrapping_add(1), 0x10))
            .unwrap();
        poll_host(&mut host, 1);
        while host.take_packet().is_some() {}
        let flow = dns.try_recv().unwrap();
        let limits = Limits::new(512, 8).unwrap();
        let name = Name::from_ascii("routed.example.test").unwrap();
        let mut bytes = vec![0, 17, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        bytes.extend_from_slice(name.wire());
        bytes.extend_from_slice(&[0, 1, 0, 1]);
        let query = Packet::request(&bytes, limits).unwrap();
        bytes[2..4].copy_from_slice(&[0x81, 0x80]);
        bytes[7] = 1;
        bytes.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 203, 0, 113, 7]);
        let packet = Packet::response(&bytes, &query, limits).unwrap();
        let reservation = controller
            .reserve(
                RoutingMode::Dynamic,
                lease::QuestionKey {
                    backend: BackendId(7),
                    name,
                    record_type: 1,
                    class: 1,
                },
                &[lease::Contribution {
                    address: "203.0.113.7".parse().unwrap(),
                    expires_at: Duration::ZERO,
                }],
                origin + Duration::from_secs(10),
            )
            .unwrap();
        let route = controller.response_route(&reservation, 0).unwrap();
        Self {
            host,
            connection: Some(Connection::new(flow.stream, limits)),
            controller,
            query,
            reply: Some(Reply {
                packet,
                received_at: origin,
                reservation,
                grace: Duration::from_secs(1),
            }),
            route,
            owner: watch::channel(false).0,
        }
    }
    fn request(&self) -> Request {
        Request {
            deadline: Instant::now() + Duration::from_secs(10),
            cancellation: self.owner.subscribe(),
        }
    }
    fn begin(&mut self, mailbox: &Mailbox) -> Result<TcpOutput, Error> {
        TcpOutput::begin_queued(
            self.controller.clone(),
            self.connection.take().unwrap(),
            &self.query,
            self.reply.take().unwrap(),
            mailbox,
            self.request(),
        )
    }
    fn close(mut self, output: TcpOutput) {
        self.host.cancel();
        while self.host.take_packet().is_some() {}
        drop(output);
        drop(self.connection.take());
        self.controller.close().unwrap();
        self.controller.advance().unwrap();
        self.controller.finish_drain().unwrap();
        assert_eq!(self.host.retained_flows(), 0);
        assert_eq!(self.controller.stats().unwrap().responses, 0);
    }
}

fn poll_host(host: &mut HostAdapter, millis: u64) {
    host.poll_io(
        &mut Context::from_waker(Waker::noop()),
        Duration::from_millis(millis),
    )
    .unwrap();
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]));
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp(sequence: u32, acknowledgment: u32, flags: u8) -> Vec<u8> {
    let mut packet = vec![0u8; 40];
    packet[..4].copy_from_slice(&[0x45, 0, 0, 40]);
    packet[6..10].copy_from_slice(&[0x40, 0, 64, 6]);
    packet[12..20].copy_from_slice(&[192, 0, 2, 2, 192, 0, 2, 53]);
    packet[20..24].copy_from_slice(&[0xc3, 0x50, 0, 53]);
    packet[24..28].copy_from_slice(&sequence.to_be_bytes());
    packet[28..32].copy_from_slice(&acknowledgment.to_be_bytes());
    packet[32..36].copy_from_slice(&[0x50, flags, 0x20, 0]);
    let mut pseudo = packet[12..20].to_vec();
    pseudo.extend_from_slice(&[0, 6, 0, 20]);
    pseudo.extend_from_slice(&packet[20..]);
    packet[36..38].copy_from_slice(&checksum(&pseudo).to_be_bytes());
    let sum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet
}

async fn poll_output(output: &mut TcpOutput, request: Request) -> Poll<Result<(), Error>> {
    let mut waiting = Box::pin(output.wait(request));
    std::future::poll_fn(|context| Poll::Ready(waiting.as_mut().poll(context))).await
}

async fn publish(fixture: &Fixture, commits: &mut queue::FixtureCommits) {
    commits
        .finish_next(|response| {
            fixture
                .controller
                .confirm_publication(fixture.controller.response_route(response, 0).unwrap())
                .map_err(crate::linux::dns_routes::Error::Metadata)
        })
        .await;
}

#[tokio::test(start_paused = true)]
async fn interrupted_tcp_output_retains_routes_until_peer_ack_and_starts_grace_on_join() {
    let mut fixture = Fixture::new();
    let wire = fixture.reply.as_ref().unwrap().packet.encode().unwrap();
    let (mailbox, mut commits) = queue::fixture_mailbox();
    let mut output = fixture.begin(&mailbox).unwrap();
    assert!(output.take_connection().is_none());
    let expired = Request {
        deadline: Instant::now(),
        cancellation: fixture.owner.subscribe(),
    };
    assert_eq!(output.wait(expired).await, Err(Error::WaitDeadline));
    assert!(output.has_pending());
    assert!(output.failure().is_none());
    assert!(
        poll_output(&mut output, fixture.request())
            .await
            .is_pending()
    );
    poll_host(&mut fixture.host, 10);
    assert!(
        fixture.host.take_packet().is_none(),
        "no positive bytes may precede native commit"
    );
    let (cancelled, cancellation) = watch::channel(true);
    assert_eq!(
        output
            .wait(Request {
                deadline: fixture.request().deadline,
                cancellation
            })
            .await,
        Err(Error::WaitCancelled)
    );
    drop(cancelled);
    assert_eq!(mailbox.active(), 1);
    publish(&fixture, &mut commits).await;
    assert!(
        poll_output(&mut output, fixture.request())
            .await
            .is_pending()
    );
    assert_eq!(mailbox.active(), 0);
    assert_eq!(fixture.controller.stats().unwrap().responses, 1);
    let observer = Request {
        deadline: Instant::now() + Duration::from_millis(1),
        cancellation: fixture.owner.subscribe(),
    };
    assert_eq!(output.wait(observer).await, Err(Error::WaitDeadline));
    tokio::time::advance(Duration::from_secs(2)).await;
    fixture.controller.advance().unwrap();
    assert!(fixture.controller.retirement_candidate().unwrap().is_none());
    poll_host(&mut fixture.host, 100);
    let mut received = Vec::new();
    let mut acknowledgment = None;
    while let Some(packet) = fixture.host.take_packet() {
        let start = 20 + usize::from(packet[32] >> 4) * 4;
        if start < packet.len() {
            received.extend_from_slice(&packet[start..]);
            acknowledgment = Some(
                u32::from_be_bytes(packet[24..28].try_into().unwrap())
                    .wrapping_add((packet.len() - start) as u32),
            );
        }
    }
    let mut expected = (wire.len() as u16).to_be_bytes().to_vec();
    expected.extend_from_slice(&wire);
    assert_eq!(
        received, expected,
        "resuming an observation must not replay a prefix or payload"
    );
    assert!(
        poll_output(&mut output, fixture.request())
            .await
            .is_pending(),
        "native enqueue is not acknowledgment"
    );
    fixture
        .host
        .inject(&tcp(101, acknowledgment.unwrap(), 0x10))
        .unwrap();
    poll_host(&mut fixture.host, 101);
    assert_eq!(output.wait(fixture.request()).await, Ok(()));
    assert!(!output.has_pending());
    assert_eq!(
        output.wait(fixture.request()).await,
        Err(Error::AlreadyJoined)
    );
    assert_eq!(fixture.controller.stats().unwrap().responses, 0);
    assert!(fixture.controller.retirement_candidate().unwrap().is_none());
    tokio::time::advance(Duration::from_secs(1)).await;
    fixture.controller.advance().unwrap();
    assert_eq!(
        fixture.controller.retirement_candidate().unwrap(),
        Some(fixture.route)
    );
    fixture.connection = output.take_connection();
    assert!(output.take_connection().is_none());
    fixture.close(output);
}

#[tokio::test(start_paused = true)]
async fn terminal_tcp_failure_closes_admission_and_retains_uncertain_routing() {
    for cause in ["cancel", "expiry", "reset"] {
        let mut fixture = Fixture::new();
        let (mailbox, mut commits) = queue::fixture_mailbox();
        let mut output = fixture.begin(&mailbox).unwrap();
        publish(&fixture, &mut commits).await;
        assert!(
            poll_output(&mut output, fixture.request())
                .await
                .is_pending()
        );
        let expected = match cause {
            "cancel" => {
                fixture.owner.send_replace(true);
                DnsOutputError::Cancelled
            }
            "expiry" => {
                tokio::time::advance(Duration::from_secs(10)).await;
                DnsOutputError::Deadline
            }
            "reset" => {
                fixture.host.inject(&tcp(101, 0, 4)).unwrap();
                poll_host(&mut fixture.host, 100);
                DnsOutputError::Reset
            }
            _ => unreachable!(),
        };
        let (observer, cancellation) = watch::channel(false);
        let error = output
            .wait(Request {
                deadline: Instant::now() + Duration::from_secs(1),
                cancellation,
            })
            .await;
        assert_eq!(error, Err(Error::Output(expected)));
        assert!(fixture.controller.is_closed().unwrap());
        assert_eq!(
            fixture.controller.stats().unwrap().responses,
            1,
            "uncertain output must retain routing through native cleanup"
        );
        assert!(output.take_connection().is_none());
        assert_eq!(output.failure().unwrap().primary, Error::Output(expected));
        drop(observer);
        fixture.close(output);
    }
}

#[tokio::test]
async fn native_commit_failure_never_writes_and_preserves_its_typed_error() {
    let mut fixture = Fixture::new();
    let (mailbox, mut commits) = queue::fixture_mailbox();
    let mut output = fixture.begin(&mailbox).unwrap();
    commits
        .finish_next(|_| Err(crate::linux::dns_routes::Error::RequestCancelled))
        .await;
    assert_eq!(
        output.wait(fixture.request()).await,
        Err(Error::Commit(queue::Error::Operation(
            crate::linux::dns_routes::Error::RequestCancelled
        )))
    );
    assert!(fixture.controller.is_closed().unwrap());
    assert!(output.take_connection().is_none());
    fixture.controller.advance().unwrap();
    assert_eq!(fixture.controller.stats().unwrap().responses, 0);
    fixture.close(output);
}

#[tokio::test(start_paused = true)]
async fn cancelled_partial_frame_retains_its_guard_and_never_returns_a_reusable_connection() {
    let mut fixture = Fixture::new();
    let mut bytes = fixture.reply.as_ref().unwrap().packet.encode().unwrap();
    bytes[11] = 1;
    bytes.extend_from_slice(&[0xc0, 12, 0xff, 0, 0, 1, 0, 0, 0, 0]);
    bytes.extend_from_slice(&9000u16.to_be_bytes());
    bytes.resize(bytes.len() + 9000, 7);
    let limits = Limits::new(16 * 1024, 8).unwrap();
    fixture.reply.as_mut().unwrap().packet =
        Packet::response(&bytes, &fixture.query, limits).unwrap();
    fixture.connection = Some(Connection::new(
        fixture.connection.take().unwrap().into_inner(),
        limits,
    ));
    let (mailbox, mut commits) = queue::fixture_mailbox();
    let mut output = fixture.begin(&mailbox).unwrap();
    publish(&fixture, &mut commits).await;
    assert!(
        poll_output(&mut output, fixture.request())
            .await
            .is_pending()
    );
    let (observer, cancellation) = watch::channel(false);
    assert_eq!(
        output
            .wait(Request {
                deadline: Instant::now() + Duration::from_millis(1),
                cancellation: cancellation.clone()
            })
            .await,
        Err(Error::WaitDeadline)
    );
    fixture.owner.send_replace(true);
    assert_eq!(
        output
            .wait(Request {
                deadline: Instant::now() + Duration::from_secs(1),
                cancellation
            })
            .await,
        Err(Error::Framing(connection::Error::Operation(
            warper_core::transport::Error::Cancelled
        )))
    );
    assert!(output.take_connection().is_none());
    assert!(fixture.controller.is_closed().unwrap());
    assert_eq!(fixture.controller.stats().unwrap().responses, 1);
    drop(observer);
    fixture.close(output);
}

#[tokio::test]
async fn invalid_reply_and_delivery_admission_fail_before_native_submission() {
    for cause in [
        "correlation",
        "timestamp",
        "frame",
        "cancel",
        "busy",
        "closed",
    ] {
        let mut fixture = Fixture::new();
        let (mailbox, _commits) = queue::fixture_mailbox();
        let mailbox = if cause == "closed" {
            queue::closed_mailbox()
        } else {
            mailbox
        };
        let expected = match cause {
            "correlation" => {
                let mut bytes = fixture.query.encode().unwrap();
                bytes[1] += 1;
                fixture.query = Packet::request(&bytes, Limits::new(512, 8).unwrap()).unwrap();
                Error::Packet(crate::dns::Error::MismatchedResponse)
            }
            "timestamp" => {
                fixture.reply.as_mut().unwrap().received_at =
                    Instant::now() + Duration::from_secs(1);
                Error::InvalidTime
            }
            "frame" => {
                let stream = fixture.connection.take().unwrap().into_inner();
                fixture.connection = Some(Connection::new(stream, Limits::new(12, 8).unwrap()));
                Error::Framing(connection::Error::ResourceLimit)
            }
            "cancel" => {
                fixture.owner.send_replace(true);
                Error::Framing(connection::Error::Operation(
                    warper_core::transport::Error::Cancelled,
                ))
            }
            "busy" => {
                fixture
                    .connection
                    .as_ref()
                    .unwrap()
                    .stream()
                    .dns_output()
                    .unwrap()
                    .begin(fixture.request())
                    .unwrap();
                Error::Output(DnsOutputError::Busy)
            }
            "closed" => Error::Commit(queue::Error::Closed),
            _ => unreachable!(),
        };
        assert!(
            matches!(fixture.begin(&mailbox), Err(error) if error == expected),
            "{cause}"
        );
        assert_eq!(mailbox.active(), 0, "{cause}");
        fixture.host.cancel();
        while fixture.host.take_packet().is_some() {}
        fixture.controller.close().unwrap();
        fixture.controller.advance().unwrap();
        fixture.controller.finish_drain().unwrap();
        assert_eq!(fixture.host.retained_flows(), 0, "{cause}");
        assert_eq!(fixture.controller.stats().unwrap().responses, 0, "{cause}");
    }
}
