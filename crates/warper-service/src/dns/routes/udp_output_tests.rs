// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Composed routed output against a controlled in-memory native packet sink.

use super::*;
use crate::dns::{
    Limits, Packet,
    output::{Error as OutputError, RoutedReply, UdpOutput},
};
use std::{
    future::{Future, poll_fn},
    sync::mpsc as blocking,
    task::Poll,
};
use tokio::sync::{oneshot, watch};
use warper_core::{dns::Name, transport::Request};
use warper_stack::{
    Seed,
    host::Limits as HostLimits,
    runtime::{self, Runtime, delivery, udp_dns},
};

fn name() -> Name {
    Name::from_ascii("managed.example.test").unwrap()
}
fn address() -> IpAddr {
    "203.0.113.7".parse().unwrap()
}
fn query() -> Vec<u8> {
    let mut bytes = vec![0, 17, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    bytes.extend_from_slice(name().wire());
    bytes.extend_from_slice(&[0, 1, 0, 1]);
    bytes
}
fn packet(ttl: u32, id: u16, large: bool) -> Packet {
    let limits = Limits::new(4096, 8).unwrap();
    let mut bytes = query();
    bytes[..2].copy_from_slice(&id.to_be_bytes());
    let request = Packet::request(&bytes, limits).unwrap();
    bytes[2..4].copy_from_slice(&[0x81, 0x80]);
    bytes[7] = 1;
    bytes.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
    bytes.extend_from_slice(&ttl.to_be_bytes());
    bytes.extend_from_slice(&[0, 4, 203, 0, 113, 7]);
    if large {
        bytes[11] = 1;
        bytes.extend_from_slice(&[0xc0, 0x0c, 0xff, 0, 0, 1, 0, 0, 0, 0]);
        bytes.extend_from_slice(&1300_u16.to_be_bytes());
        bytes.resize(bytes.len() + 1300, 7);
    }
    Packet::response(&bytes, &request, limits).unwrap()
}
fn request(owner: &watch::Sender<bool>) -> Request {
    Request {
        deadline: Instant::now() + Duration::from_secs(10),
        cancellation: owner.subscribe(),
    }
}

struct Fixture {
    controller: Arc<Controller>,
    route: Route,
    reservation: Option<Response>,
    datagram: Option<udp_dns::Datagram>,
    endpoint: udp_dns::Endpoint,
    channels: runtime::Channels,
    host: tokio::task::JoinHandle<Result<runtime::Report, runtime::Failure>>,
    owner: watch::Sender<bool>,
    origin: Instant,
}
impl Fixture {
    async fn new(committed: bool) -> Self {
        Self::with_ttl(committed, 0).await
    }
    async fn with_ttl(committed: bool, ttl: u32) -> Self {
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
        let (runtime, mut channels) = Runtime::with_udp_dns(
            HostLimits::default(),
            controller.selector(),
            2,
            Seed::generate().unwrap(),
            udp_dns::Config {
                endpoint: "192.0.2.9:53".parse().unwrap(),
                requests: 1,
            },
        )
        .unwrap();
        let mut endpoint = channels.udp_dns.take().unwrap();
        let host = tokio::spawn(runtime.run());
        let bytes = query();
        assert_eq!(bytes.len(), 38);
        // Fixed checked IPv4/UDP envelope for the 38-byte synthetic query.
        let mut wire = vec![
            0x45, 0, 0, 66, 0, 0, 0x40, 0, 64, 17, 0xb6, 0x9f, 192, 0, 2, 2, 192, 0, 2, 9, 0xc3,
            0x50, 0, 53, 0, 46, 0, 0,
        ];
        wire.extend_from_slice(&bytes);
        channels.ingress.try_inject(&wire).unwrap();
        let datagram = endpoint.requests.recv().await.unwrap();
        let reservation = controller
            .reserve(
                RoutingMode::Dynamic,
                lease::QuestionKey {
                    backend: BackendId(7),
                    name: name(),
                    record_type: 1,
                    class: 1,
                },
                &[Contribution {
                    address: address(),
                    expires_at: Duration::from_secs(u64::from(ttl)),
                }],
                origin + Duration::from_secs(10),
            )
            .unwrap();
        let route = controller.response_route(&reservation, 0).unwrap();
        if committed {
            controller.confirm_publication(route).unwrap();
        }
        Self {
            controller,
            route,
            reservation: Some(reservation),
            datagram: Some(datagram),
            endpoint,
            channels,
            host,
            owner: watch::channel(false).0,
            origin,
        }
    }
    fn reply(&mut self, ttl: u32) -> RoutedReply {
        RoutedReply {
            packet: packet(ttl, 17, false),
            received_at: self.origin,
            reservation: self.reservation.take().unwrap(),
            grace: Duration::from_secs(1),
        }
    }
    fn begin(&mut self, reply: RoutedReply, operation: Request) -> Result<UdpOutput, OutputError> {
        UdpOutput::begin(
            self.controller.clone(),
            &mut self.datagram,
            reply,
            operation,
        )
    }
    async fn close(mut self) {
        drop(self.reservation.take());
        drop(self.datagram.take());
        self.controller.close().unwrap();
        self.controller.advance().unwrap();
        self.controller.finish_drain().unwrap();
        // Pure ledger fixture: no native route is installed in these unit tests.
        while let Some(route) = self.controller.retirement_candidate().unwrap() {
            self.controller.begin_retirement(route).unwrap();
            self.controller.finish_retirement(route).unwrap();
        }
        self.channels.shutdown.send(()).unwrap();
        self.host.await.unwrap().unwrap();
        assert_eq!(self.endpoint.retained_requests(), 0);
        assert_eq!(self.controller.stats().unwrap().routes, 0);
    }
}

#[tokio::test(start_paused = true)]
async fn routed_udp_delivery_retains_aged_ttl_after_late_observation_and_original_expiry() {
    let mut fixture = Fixture::with_ttl(true, 5).await;
    tokio::time::advance(Duration::from_secs(2)).await;
    let reply = fixture.reply(5);
    let mut output = fixture.begin(reply, request(&fixture.owner)).unwrap();
    let native = fixture.channels.packets.recv().await.unwrap();
    let wire = &native[28..];
    let ttl = u32::from_be_bytes(wire[wire.len() - 10..wire.len() - 6].try_into().unwrap());
    native.complete(Ok(())).unwrap();
    let (cancelled, _) = watch::channel(true);
    assert_eq!(
        output.wait(request(&cancelled)).await,
        Err(OutputError::WaitCancelled)
    );
    tokio::time::advance(Duration::from_secs(11)).await;
    fixture.controller.advance().unwrap();
    let pending = fixture.controller.stats().unwrap();
    let flow = fixture
        .controller
        .selector()
        .select_flow(address())
        .unwrap();
    let completed_at = Instant::now();
    output.wait(request(&fixture.owner)).await.unwrap();
    let expiry = fixture.controller.next_expiry().unwrap();
    let repeated = output.wait(request(&fixture.owner)).await;
    drop(flow);
    drop(output);
    tokio::time::advance(Duration::from_secs(2)).await;
    let connection = fixture
        .controller
        .selector()
        .select_flow(address())
        .unwrap();
    tokio::time::advance(Duration::from_secs(2)).await;
    fixture.controller.advance().unwrap();
    let retained = fixture.controller.route_info(fixture.route).unwrap().flows;
    drop(connection);
    fixture.close().await;
    assert_eq!(ttl, 3);
    assert_eq!(pending.responses, 1);
    assert_eq!(retained, 1);
    assert_eq!(expiry, Some(completed_at + Duration::from_secs(3)));
    assert_eq!(repeated, Err(OutputError::AlreadyJoined));
}

#[tokio::test]
async fn invalid_or_uncommitted_udp_replies_never_start_native_output() {
    for case in 0..7 {
        let mut fixture = Fixture::new(case != 3).await;
        let mut reply = fixture.reply(0);
        let mut operation = request(&fixture.owner);
        let expected = match case {
            0 => {
                reply.packet = packet(0, 18, false);
                OutputError::Packet(crate::dns::Error::MismatchedResponse)
            }
            1 => {
                reply.received_at += Duration::from_secs(1);
                OutputError::InvalidTime
            }
            2 => {
                reply.grace = Duration::MAX;
                OutputError::InvalidTime
            }
            3 => OutputError::Metadata(Error::Ledger(lease::Error::NotCommitted)),
            4 => {
                fixture.owner.send_replace(true);
                OutputError::Submission(udp_dns::Error::RequestCancelled)
            }
            5 => {
                operation.deadline = Instant::now();
                OutputError::Submission(udp_dns::Error::RequestExpired)
            }
            _ => {
                reply.packet = packet(0, 17, true);
                OutputError::Packet(crate::dns::Error::ResourceLimit)
            }
        };
        let result = fixture.begin(reply, operation);
        fixture.controller.advance().unwrap();
        let responses = fixture.controller.stats().unwrap().responses;
        let native =
            tokio::time::timeout(Duration::from_millis(10), fixture.channels.packets.recv()).await;
        let queued = native.is_err();
        drop(native);
        let retained = fixture.endpoint.retained_requests();
        let matched = matches!(result,Err(error) if error==expected);
        drop(result);
        let retained_for_failure = !matches!(expected, OutputError::Submission(_));
        if retained_for_failure {
            let mut wire = query();
            wire[2..4].copy_from_slice(&[0x81, 0x82]);
            let mut receipt = fixture
                .datagram
                .take()
                .unwrap()
                .respond(&wire, request(&fixture.owner))
                .unwrap();
            let native = fixture.channels.packets.recv().await.unwrap();
            let decoded = Packet::response(
                &native[28..],
                &Packet::request(&query(), Limits::new(512, 8).unwrap()).unwrap(),
                Limits::new(512, 8).unwrap(),
            )
            .unwrap();
            assert_eq!(decoded.response_code(), 2);
            native.complete(Ok(())).unwrap();
            receipt.wait(request(&fixture.owner)).await.unwrap();
        }
        fixture.close().await;
        assert!(matched, "case {case}");
        assert_eq!(responses, 0, "case {case}");
        assert!(queued, "case {case}");
        assert_eq!(retained, usize::from(retained_for_failure), "case {case}");
    }
}

#[tokio::test(start_paused = true)]
async fn known_native_cancellation_and_expiry_release_output_without_new_grace() {
    for failure in [delivery::Failure::Cancelled, delivery::Failure::Deadline] {
        let mut fixture = Fixture::new(true).await;
        let reply = fixture.reply(0);
        let mut output = fixture.begin(reply, request(&fixture.owner)).unwrap();
        let native = fixture.channels.packets.recv().await.unwrap();
        native.complete(Err(failure)).unwrap();
        let result = output.wait(request(&fixture.owner)).await;
        let fatal = output.failure();
        drop(output);
        fixture.controller.advance().unwrap();
        let stats = fixture.controller.stats().unwrap();
        let closed = fixture.controller.is_closed().unwrap();
        fixture.close().await;
        assert_eq!(result, Err(OutputError::Delivery(failure)));
        assert!(fatal.is_none());
        assert!(!closed);
        assert_eq!(stats.responses, 0);
        assert_eq!(stats.leases, 0);
    }
}

#[tokio::test]
async fn uncertain_native_delivery_closes_admission_and_retains_cleanup_ownership() {
    for lost in [false, true] {
        let mut fixture = Fixture::new(true).await;
        let reply = fixture.reply(0);
        let mut output = fixture.begin(reply, request(&fixture.owner)).unwrap();
        let native = fixture.channels.packets.recv().await.unwrap();
        if lost {
            drop(native);
        } else {
            native.complete(Err(delivery::Failure::Uncertain)).unwrap();
        }
        let result = output.wait(request(&fixture.owner)).await;
        let failure = output.failure();
        let closed = fixture.controller.is_closed().unwrap();
        let pending = fixture.controller.stats().unwrap().responses;
        let busy = output.has_pending();
        drop(output);
        fixture.close().await;
        assert_eq!(
            result,
            Err(OutputError::Delivery(delivery::Failure::Uncertain))
        );
        assert_eq!(
            failure,
            Some(crate::dns::output::Failure {
                primary: OutputError::Delivery(delivery::Failure::Uncertain),
                closure: None
            })
        );
        assert!(closed);
        assert_eq!(pending, 1);
        assert!(!busy);
    }
}

#[tokio::test]
async fn delivered_udp_output_survives_a_dropped_wait_while_metadata_is_busy() {
    let mut fixture = Fixture::new(true).await;
    let reply = fixture.reply(0);
    let mut output = fixture.begin(reply, request(&fixture.owner)).unwrap();
    fixture
        .channels
        .packets
        .recv()
        .await
        .unwrap()
        .complete(Ok(()))
        .unwrap();
    let controller = fixture.controller.clone();
    let (ready, started) = oneshot::channel();
    let (release, held) = blocking::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let _guard = controller.routes.owner.lock().unwrap();
        ready.send(()).unwrap();
        held.recv_timeout(Duration::from_secs(2)).unwrap();
    });
    started.await.unwrap();
    let polled = {
        let mut wait = std::pin::pin!(output.wait(request(&fixture.owner)));
        poll_fn(|cx| Poll::Ready(wait.as_mut().poll(cx))).await
    };
    let pending = output.has_pending();
    release.send(()).unwrap();
    worker.join().unwrap();
    output.wait(request(&fixture.owner)).await.unwrap();
    drop(output);
    let stats = fixture.controller.stats().unwrap();
    fixture.close().await;
    assert!(matches!(polled, Poll::Pending));
    assert!(pending);
    assert_eq!(stats.responses, 0);
    assert_eq!(stats.leases, 1);
}

#[tokio::test(start_paused = true)]
async fn udp_output_observer_expiry_keeps_both_route_and_native_delivery_ownership() {
    let mut fixture = Fixture::new(true).await;
    let reply = fixture.reply(0);
    let mut output = fixture.begin(reply, request(&fixture.owner)).unwrap();
    let native = fixture.channels.packets.recv().await.unwrap();
    let mut observer = request(&fixture.owner);
    observer.deadline = Instant::now() + Duration::from_millis(1);
    let expired = output.wait(observer).await;
    let pending = fixture.controller.stats().unwrap().responses;
    let admitted = fixture.endpoint.retained_requests();
    native.complete(Ok(())).unwrap();
    output.wait(request(&fixture.owner)).await.unwrap();
    drop(output);
    fixture.close().await;
    assert_eq!(expired, Err(OutputError::WaitDeadline));
    assert_eq!(pending, 1);
    assert_eq!(admitted, 1);
}

#[tokio::test]
async fn uncertain_udp_delivery_survives_cancelled_observation_until_admission_closes() {
    let mut fixture = Fixture::new(true).await;
    let reply = fixture.reply(0);
    let mut output = fixture.begin(reply, request(&fixture.owner)).unwrap();
    fixture
        .channels
        .packets
        .recv()
        .await
        .unwrap()
        .complete(Err(delivery::Failure::Uncertain))
        .unwrap();
    let controller = fixture.controller.clone();
    let (ready, started) = oneshot::channel();
    let (release, held) = blocking::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let _guard = controller.routes.owner.lock().unwrap();
        ready.send(()).unwrap();
        held.recv_timeout(Duration::from_secs(2)).unwrap();
    });
    started.await.unwrap();
    let polled = {
        let mut wait = std::pin::pin!(output.wait(request(&fixture.owner)));
        poll_fn(|cx| Poll::Ready(wait.as_mut().poll(cx))).await
    };
    let failure = output.failure();
    let (cancelled, _) = watch::channel(true);
    let cancelled = output.wait(request(&cancelled)).await;
    release.send(()).unwrap();
    worker.join().unwrap();
    let result = output.wait(request(&fixture.owner)).await;
    let closed = fixture.controller.is_closed().unwrap();
    drop(output);
    fixture.close().await;
    assert!(matches!(polled, Poll::Pending));
    assert!(failure.is_some());
    assert!(closed);
    assert_eq!(cancelled, Err(OutputError::WaitCancelled));
    assert_eq!(
        result,
        Err(OutputError::Delivery(delivery::Failure::Uncertain))
    );
}

#[tokio::test]
async fn post_delivery_metadata_failure_preserves_primary_and_closure_errors() {
    let mut fixture = Fixture::new(true).await;
    let reply = fixture.reply(0);
    let mut output = fixture.begin(reply, request(&fixture.owner)).unwrap();
    fixture
        .channels
        .packets
        .recv()
        .await
        .unwrap()
        .complete(Ok(()))
        .unwrap();
    let controller = fixture.controller.clone();
    let worker = std::thread::spawn(move || {
        let _guard = controller.routes.owner.lock().unwrap();
        panic!("synthetic metadata failure");
    });
    let injected = worker.join().is_err();
    let result = output.wait(request(&fixture.owner)).await;
    let failure = output.failure();
    fixture.controller.routes.owner.clear_poison();
    let pending = fixture.controller.stats().unwrap().responses;
    drop(output);
    fixture.close().await;
    assert!(injected);
    assert_eq!(pending, 1);
    assert_eq!(result, Err(OutputError::Metadata(Error::Unavailable)));
    assert_eq!(
        failure,
        Some(crate::dns::output::Failure {
            primary: OutputError::Metadata(Error::Unavailable),
            closure: Some(Error::Unavailable)
        })
    );
}

#[tokio::test]
async fn destroying_queued_native_output_retains_routes_until_uncertainty_is_observed() {
    let mut fixture = Fixture::new(true).await;
    let reply = fixture.reply(0);
    let mut output = fixture.begin(reply, request(&fixture.owner)).unwrap();
    let mut discarded = 0;
    for _ in 0..100 {
        discarded += fixture.channels.packets.discard_pending();
        if discarded != 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    fixture
        .channels
        .admission
        .cancel_flows()
        .unwrap()
        .wait(request(&fixture.owner))
        .await
        .unwrap();
    let result = output.wait(request(&fixture.owner)).await;
    let held = fixture.controller.stats().unwrap().responses;
    let closed = fixture.controller.is_closed().unwrap();
    drop(output);
    fixture.close().await;
    assert_eq!(discarded, 1);
    assert_eq!(held, 1);
    assert!(closed);
    assert_eq!(
        result,
        Err(OutputError::Delivery(delivery::Failure::Uncertain))
    );
}

#[tokio::test]
async fn cancellation_during_native_observation_keeps_the_same_output_for_resumption() {
    let mut fixture = Fixture::new(true).await;
    let reply = fixture.reply(0);
    let mut output = fixture.begin(reply, request(&fixture.owner)).unwrap();
    let native = fixture.channels.packets.recv().await.unwrap();
    let (observer, cancellation) = watch::channel(false);
    let cancel = observer.clone();
    let worker = tokio::spawn(async move {
        tokio::task::yield_now().await;
        cancel.send_replace(true);
    });
    let result = output
        .wait(Request {
            deadline: Instant::now() + Duration::from_secs(10),
            cancellation,
        })
        .await;
    worker.await.unwrap();
    let pending = fixture.controller.stats().unwrap().responses;
    native.complete(Ok(())).unwrap();
    output.wait(request(&fixture.owner)).await.unwrap();
    drop(output);
    fixture.close().await;
    assert_eq!(result, Err(OutputError::WaitCancelled));
    assert_eq!(pending, 1);
}
