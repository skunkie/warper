// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Public worker lifecycle flows reusing the dispatcher protocol peers.

use super::*;
use crate::dns::server::{Error as WorkerError, Limits as WorkerLimits, Workers};
use crate::linux::dns_routes::queue;
use warper_stack::{
    Seed,
    host::Limits as HostLimits,
    runtime::{self, Runtime, delivery, udp_dns},
};

struct RuntimeFixture {
    controller: Arc<Controller>,
    channels: Option<runtime::Channels>,
    endpoint: udp_dns::Endpoint,
    task: JoinHandle<Result<runtime::Report, runtime::Failure>>,
}
impl RuntimeFixture {
    fn new() -> Self {
        let controller = routes();
        let (runtime, mut channels) = Runtime::with_udp_dns(
            HostLimits::default(),
            controller.selector(),
            8,
            Seed::generate().unwrap(),
            udp_dns::Config {
                endpoint: "192.0.2.53:53".parse().unwrap(),
                requests: 2,
            },
        )
        .unwrap();
        let endpoint = channels.udp_dns.take().unwrap();
        Self {
            controller,
            channels: Some(channels),
            endpoint,
            task: tokio::spawn(runtime.run()),
        }
    }
    async fn input(&mut self, name: &str) -> udp_dns::Datagram {
        self.input_bytes(query(name, 1).encode().unwrap()).await
    }
    async fn input_bytes(&mut self, payload: Vec<u8>) -> udp_dns::Datagram {
        self.inject(payload);
        self.endpoint.requests.recv().await.unwrap()
    }
    fn inject(&self, payload: Vec<u8>) {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
        packet[6..10].copy_from_slice(&[0x40, 0, 64, 17]);
        packet[12..20].copy_from_slice(&[192, 0, 2, 2, 192, 0, 2, 53]);
        packet[20..24].copy_from_slice(&[0xc3, 0x50, 0, 53]);
        packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        let mut sum: u32 = packet[..20]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|chunk| u32::from(u16::from_be_bytes([chunk[0], chunk[1]])))
            .sum();
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        packet.extend_from_slice(&payload);
        self.channels
            .as_ref()
            .unwrap()
            .ingress
            .try_inject(&packet)
            .unwrap();
    }
    async fn close(mut self, workers: &mut Workers) {
        let mut channels = self.channels.take().unwrap();
        channels.shutdown.send(()).unwrap();
        self.task.await.unwrap().unwrap();
        channels.packets.discard_pending();
        workers.release_after_native_join().await.unwrap();
        self.controller.close().unwrap();
        self.controller.advance().unwrap();
        self.controller.finish_drain().unwrap();
        assert_eq!(workers.active(), 0);
        assert_eq!(self.endpoint.retained_requests(), 0);
        assert_eq!(self.controller.stats().unwrap().responses, 0);
    }
}
fn worker_limits() -> WorkerLimits {
    WorkerLimits {
        requests: 1,
        request_timeout: Duration::from_secs(2),
        cleanup_timeout: Duration::from_secs(1),
        attempts: 4,
        grace: Duration::from_secs(1),
        packet: limits(),
    }
}

#[tokio::test]
async fn worker_admission_precedes_io_and_native_join_releases_request_storage() {
    let mut fixture = RuntimeFixture::new();
    let events = Arc::new(Mutex::new(Vec::new()));
    let peer = Arc::new(MockPeer {
        marker: 54,
        backend: BackendId(7),
        tcp: Mutex::new(None),
        udp_error: None,
        events: events.clone(),
    });
    let dispatcher = Arc::new(
        Dispatcher::new(
            domains(),
            fixture.controller.clone(),
            Vec::new(),
            vec![peer.direct()],
            true,
            discovery(),
        )
        .unwrap(),
    );
    let (mailbox, _commits) = queue::fixture_mailbox();
    let mut workers = Workers::new(
        dispatcher,
        fixture.controller.clone(),
        mailbox,
        worker_limits(),
    )
    .unwrap();
    let datagram = fixture.input("unmatched.invalid").await;
    let deadline = datagram.received_at() + worker_limits().request_timeout;
    workers.admit_udp(datagram).unwrap();
    assert_eq!(
        workers.admit_udp(fixture.input("unmatched.invalid").await),
        Err(WorkerError::Full)
    );
    let packet = fixture
        .channels
        .as_mut()
        .unwrap()
        .packets
        .recv()
        .await
        .unwrap();
    assert_eq!(packet.request().unwrap().deadline, deadline);
    assert_eq!(
        Packet::response(&packet[28..], &query("unmatched.invalid", 1), limits())
            .unwrap()
            .response_code(),
        3
    );
    assert_eq!(workers.active(), 1);
    packet.complete(Ok(())).unwrap();
    assert_eq!(
        workers.join_next().await.unwrap().unwrap().outcome,
        Ok(None)
    );
    assert_eq!(events.lock().unwrap().len(), 1);
    assert_eq!(workers.active(), 0);
    workers
        .join(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    fixture.close(&mut workers).await;
}

#[tokio::test]
async fn aborted_routed_worker_retains_its_guard_until_native_output_is_destroyed() {
    let mut fixture = RuntimeFixture::new();
    let events = Arc::new(Mutex::new(Vec::new()));
    let (peer, server) = positive(53, &events);
    let dispatcher = Arc::new(
        Dispatcher::new(
            domains(),
            fixture.controller.clone(),
            vec![Selected {
                mode: RoutingMode::Dynamic,
                upstreams: vec![peer.selected()],
            }],
            Vec::new(),
            false,
            discovery(),
        )
        .unwrap(),
    );
    let (mailbox, mut commits) = queue::fixture_mailbox();
    let mut workers = Workers::new(
        dispatcher,
        fixture.controller.clone(),
        mailbox,
        worker_limits(),
    )
    .unwrap();
    workers
        .admit_udp(fixture.input("selected.example.test").await)
        .unwrap();
    commits
        .finish_next(|response| {
            fixture
                .controller
                .confirm_publication(fixture.controller.response_route(response, 0).unwrap())
                .map_err(crate::linux::dns_routes::Error::Metadata)
        })
        .await;
    let packet = fixture
        .channels
        .as_mut()
        .unwrap()
        .packets
        .recv()
        .await
        .unwrap();
    assert_eq!(fixture.controller.stats().unwrap().responses, 1);
    assert_eq!(
        workers.release_after_native_join().await,
        Err(WorkerError::InvalidState)
    );
    assert_eq!(
        workers.join(Instant::now()).await,
        Err(WorkerError::ShutdownDeadline)
    );
    assert_eq!(
        workers.shutdown_error(),
        Some(WorkerError::ShutdownDeadline)
    );
    assert!(workers.stopping());
    assert_eq!(workers.active(), 1);
    assert_eq!(fixture.controller.stats().unwrap().responses, 1);
    packet.complete(Err(delivery::Failure::Cancelled)).unwrap();
    server.await.unwrap();
    fixture.close(&mut workers).await;
}

#[tokio::test]
async fn parsed_dispatch_failure_sends_servfail_and_keeps_its_typed_diagnostic() {
    use crate::dns::server::RequestFailure;
    let mut fixture = RuntimeFixture::new();
    let events = Arc::new(Mutex::new(Vec::new()));
    let peer = failed(53, TransportError::Authentication, &events);
    let dispatcher = Arc::new(
        Dispatcher::new(
            domains(),
            fixture.controller.clone(),
            vec![Selected {
                mode: RoutingMode::Dynamic,
                upstreams: vec![peer.selected()],
            }],
            Vec::new(),
            false,
            discovery(),
        )
        .unwrap(),
    );
    let (mailbox, _commits) = queue::fixture_mailbox();
    let mut workers = Workers::new(
        dispatcher,
        fixture.controller.clone(),
        mailbox,
        worker_limits(),
    )
    .unwrap();
    workers
        .admit_udp(fixture.input("selected.example.test").await)
        .unwrap();
    let packet = fixture
        .channels
        .as_mut()
        .unwrap()
        .packets
        .recv()
        .await
        .unwrap();
    assert_eq!(
        Packet::response(&packet[28..], &query("selected.example.test", 1), limits())
            .unwrap()
            .response_code(),
        2
    );
    packet.complete(Ok(())).unwrap();
    let completion = workers.join_next().await.unwrap().unwrap();
    assert!(matches!(
        completion.outcome,
        Ok(Some(RequestFailure::Dispatch(_)))
    ));
    assert_eq!(workers.first_request_failure(), completion.outcome.unwrap());
    assert_eq!(fixture.controller.stats().unwrap().routes, 0);
    workers
        .join(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    fixture.close(&mut workers).await;
}

#[tokio::test(start_paused = true)]
async fn malformed_and_expired_requests_release_admission_without_upstream_or_output() {
    let mut fixture = RuntimeFixture::new();
    let events = Arc::new(Mutex::new(Vec::new()));
    let peer = failed(53, TransportError::Protocol, &events);
    let dispatcher = Arc::new(
        Dispatcher::new(
            domains(),
            fixture.controller.clone(),
            vec![Selected {
                mode: RoutingMode::Dynamic,
                upstreams: vec![peer.selected()],
            }],
            Vec::new(),
            false,
            discovery(),
        )
        .unwrap(),
    );
    let (mailbox, _commits) = queue::fixture_mailbox();
    let mut workers = Workers::new(
        dispatcher,
        fixture.controller.clone(),
        mailbox,
        worker_limits(),
    )
    .unwrap();
    workers
        .admit_udp(fixture.input_bytes(b"bad".to_vec()).await)
        .unwrap();
    assert!(matches!(
        workers.join_next().await.unwrap().unwrap().outcome,
        Err(WorkerError::Packet(_))
    ));
    assert!(matches!(
        workers.first_request_error(),
        Some(WorkerError::Packet(_))
    ));
    let datagram = fixture.input("selected.example.test").await;
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(workers.admit_udp(datagram), Err(WorkerError::Expired));
    assert!(events.lock().unwrap().is_empty());
    assert_eq!(workers.active(), 0);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(1),
            fixture.channels.as_mut().unwrap().packets.recv()
        )
        .await
        .is_err()
    );
    workers
        .join(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    fixture.close(&mut workers).await;
}

#[tokio::test]
async fn worker_panic_is_joined_and_stops_admission_without_losing_parent_owned_slots() {
    let mut fixture = RuntimeFixture::new();
    let events = Arc::new(Mutex::new(Vec::new()));
    let peer = Arc::new(MockPeer {
        marker: 53,
        backend: BackendId(7),
        tcp: Mutex::new(None),
        udp_error: None,
        events,
    });
    let dispatcher = Arc::new(
        Dispatcher::new(
            domains(),
            fixture.controller.clone(),
            vec![Selected {
                mode: RoutingMode::Dynamic,
                upstreams: vec![peer.selected()],
            }],
            Vec::new(),
            false,
            discovery(),
        )
        .unwrap(),
    );
    let (mailbox, _commits) = queue::fixture_mailbox();
    let mut workers = Workers::new(
        dispatcher,
        fixture.controller.clone(),
        mailbox,
        worker_limits(),
    )
    .unwrap();
    workers
        .admit_udp(fixture.input("selected.example.test").await)
        .unwrap();
    let (_tcp_owner, mut tcp) = tokio::sync::mpsc::channel(1);
    let (observer, _) = watch::channel(false);
    assert_eq!(
        workers
            .serve(
                &mut fixture.endpoint,
                &mut tcp,
                Request {
                    deadline: Instant::now() + Duration::from_secs(1),
                    cancellation: observer.subscribe(),
                }
            )
            .await,
        Err(WorkerError::WorkerStopped)
    );
    assert!(workers.stopping());
    assert_eq!(workers.active(), 1);
    assert_eq!(
        workers.admit_udp(fixture.input("selected.example.test").await),
        Err(WorkerError::Stopping)
    );
    workers
        .join(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    fixture.close(&mut workers).await;
}

fn direct_workers(controller: Arc<Controller>) -> (Workers, Events) {
    direct_workers_with_budget(
        controller,
        crate::dns::memory::Budget::new(1_048_576).unwrap(),
    )
}
fn direct_workers_with_budget(
    controller: Arc<Controller>,
    buffers: crate::dns::memory::Budget,
) -> (Workers, Events) {
    try_direct_workers_with_budget(controller, buffers).unwrap()
}
fn try_direct_workers_with_budget(
    controller: Arc<Controller>,
    buffers: crate::dns::memory::Budget,
) -> Result<(Workers, Events), WorkerError> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let peer = Arc::new(MockPeer {
        marker: 54,
        backend: BackendId(7),
        tcp: Mutex::new(None),
        udp_error: None,
        events: events.clone(),
    });
    let dispatcher = Arc::new(
        Dispatcher::new(
            domains(),
            controller.clone(),
            Vec::new(),
            vec![peer.direct()],
            true,
            discovery(),
        )
        .unwrap(),
    );
    let (mailbox, _commits) = queue::fixture_mailbox();
    Ok((
        Workers::with_budget(dispatcher, controller, mailbox, worker_limits(), buffers)?,
        events,
    ))
}

#[tokio::test(start_paused = true)]
async fn receive_loop_rejects_pressure_and_resumes_without_cancelling_native_output() {
    let mut fixture = RuntimeFixture::new();
    let (mut workers, events) = direct_workers(fixture.controller.clone());
    let (_tcp_owner, mut tcp) = tokio::sync::mpsc::channel(1);
    let (observer, _) = watch::channel(false);
    fixture.inject(query("unmatched.invalid", 1).encode().unwrap());
    fixture.inject(query("other.invalid", 1).encode().unwrap());
    let original_deadline = Instant::now() + worker_limits().request_timeout;
    let observe = || Request {
        deadline: Instant::now() + Duration::from_millis(100),
        cancellation: observer.subscribe(),
    };
    assert_eq!(
        workers
            .serve(&mut fixture.endpoint, &mut tcp, observe())
            .await,
        Err(WorkerError::Observer(TransportError::Timeout))
    );
    assert!(!workers.stopping());
    assert_eq!(workers.active(), 1);
    assert_eq!(workers.rejected_inputs().udp, 1);
    assert_eq!(events.lock().unwrap().len(), 1);
    let packet = fixture
        .channels
        .as_mut()
        .unwrap()
        .packets
        .recv()
        .await
        .unwrap();
    assert_eq!(packet.request().unwrap().deadline, original_deadline);
    packet.complete(Ok(())).unwrap();
    assert_eq!(
        workers
            .serve(&mut fixture.endpoint, &mut tcp, observe())
            .await,
        Err(WorkerError::Observer(TransportError::Timeout))
    );
    assert_eq!(workers.active(), 0);
    assert_eq!(fixture.endpoint.retained_requests(), 0);
    assert_eq!(workers.first_request_error(), None);
    workers
        .join(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    fixture.close(&mut workers).await;
}

#[tokio::test]
async fn receive_loop_surfaces_closed_consumers_and_stops_admission() {
    let fixture = RuntimeFixture::new();
    let (mut workers, events) = direct_workers(fixture.controller.clone());
    let (tcp_owner, mut tcp) = tokio::sync::mpsc::channel(1);
    drop(tcp_owner);
    let (observer, _) = watch::channel(false);
    let mut fixture = fixture;
    assert_eq!(
        workers
            .serve(
                &mut fixture.endpoint,
                &mut tcp,
                Request {
                    deadline: Instant::now() + Duration::from_secs(1),
                    cancellation: observer.subscribe(),
                }
            )
            .await,
        Err(WorkerError::ConsumerClosed)
    );
    assert!(workers.stopping());
    assert!(events.lock().unwrap().is_empty());
    workers
        .join(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    fixture.close(&mut workers).await;
}

#[tokio::test(start_paused = true)]
async fn receive_loop_continues_after_bad_input_but_preserves_uncertain_output_for_cleanup() {
    let mut fixture = RuntimeFixture::new();
    let buffers = crate::dns::memory::Budget::new(1_048_576).unwrap();
    let (mut workers, events) =
        direct_workers_with_budget(fixture.controller.clone(), buffers.clone());
    let storage = buffers.used();
    let (_tcp_owner, mut tcp) = tokio::sync::mpsc::channel(1);
    let (observer, _) = watch::channel(false);
    let observe = || Request {
        deadline: Instant::now() + Duration::from_millis(100),
        cancellation: observer.subscribe(),
    };
    fixture.inject(vec![0; 12]);
    assert_eq!(
        workers
            .serve(&mut fixture.endpoint, &mut tcp, observe())
            .await,
        Err(WorkerError::Observer(TransportError::Timeout))
    );
    assert_eq!(
        workers.first_request_error(),
        Some(WorkerError::Packet(crate::dns::Error::Malformed))
    );
    assert!(!workers.stopping());
    assert!(events.lock().unwrap().is_empty());
    fixture.inject(query("unmatched.invalid", 1).encode().unwrap());
    assert_eq!(
        workers
            .serve(&mut fixture.endpoint, &mut tcp, observe())
            .await,
        Err(WorkerError::Observer(TransportError::Timeout))
    );
    let packet = fixture
        .channels
        .as_mut()
        .unwrap()
        .packets
        .recv()
        .await
        .unwrap();
    let retained = buffers.used();
    assert!(retained > storage);
    packet.complete(Err(delivery::Failure::Uncertain)).unwrap();
    assert_eq!(
        workers
            .serve(&mut fixture.endpoint, &mut tcp, observe())
            .await,
        Err(WorkerError::Delivery(delivery::Error::Delivery(
            delivery::Failure::Uncertain
        )))
    );
    assert!(workers.stopping());
    assert_eq!(buffers.used(), retained);
    assert_eq!(workers.active(), 1);
    assert_eq!(events.lock().unwrap().len(), 1);
    workers
        .join(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    fixture.close(&mut workers).await;
    assert_eq!(buffers.used(), storage);
    drop(workers);
    assert_eq!(buffers.used(), 0);
}

#[tokio::test]
async fn shared_scratch_budget_rejects_before_io_and_releases_after_native_join() {
    let mut fixture = RuntimeFixture::new();
    let budget = crate::dns::memory::Budget::new(1_048_576).unwrap();
    let (mut first, first_events) =
        direct_workers_with_budget(fixture.controller.clone(), budget.clone());
    let (mut second, second_events) =
        direct_workers_with_budget(fixture.controller.clone(), budget.clone());
    let storage = budget.used();
    first
        .admit_udp(fixture.input("first.invalid").await)
        .unwrap();
    let packet = fixture
        .channels
        .as_mut()
        .unwrap()
        .packets
        .recv()
        .await
        .unwrap();
    let scratch = budget.used() - storage;
    assert!(scratch > 0);
    let competing = budget.reserve(budget.limit() - budget.used()).unwrap();
    assert_eq!(
        second.admit_udp(fixture.input("second.invalid").await),
        Err(WorkerError::Full)
    );
    assert_eq!(second.active(), 0);
    assert!(second_events.lock().unwrap().is_empty());
    assert_eq!(first_events.lock().unwrap().len(), 1);
    assert_eq!(budget.used(), budget.limit());
    packet.complete(Ok(())).unwrap();
    first.join_next().await.unwrap().unwrap().outcome.unwrap();
    assert_eq!(budget.used(), budget.limit() - scratch);
    second
        .admit_udp(fixture.input("second.invalid").await)
        .unwrap();
    let packet = fixture
        .channels
        .as_mut()
        .unwrap()
        .packets
        .recv()
        .await
        .unwrap();
    packet.complete(Ok(())).unwrap();
    second.join_next().await.unwrap().unwrap().outcome.unwrap();
    assert_eq!(second_events.lock().unwrap().len(), 1);
    assert_eq!(budget.used(), budget.limit() - scratch);
    drop(competing);
    assert_eq!(budget.used(), storage);
    second
        .join(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    drop(second);
    first
        .join(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    fixture.close(&mut first).await;
    drop(first);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn scratch_reservation_uses_upstream_limit_before_upstream_io() {
    let mut fixture = RuntimeFixture::new();
    let events = Arc::new(Mutex::new(Vec::new()));
    let peer = Arc::new(MockPeer {
        marker: 54,
        backend: BackendId(7),
        tcp: Mutex::new(None),
        udp_error: None,
        events: events.clone(),
    });
    let direct = Arc::new(
        DirectUdpTransport::new(
            peer.clone(),
            peer,
            "192.0.2.54:53".parse().unwrap(),
            Limits::new(65_535, 8).unwrap(),
            Admission::new(1).unwrap(),
        )
        .unwrap(),
    );
    let dispatcher = Arc::new(
        Dispatcher::new(
            domains(),
            fixture.controller.clone(),
            Vec::new(),
            vec![direct],
            true,
            discovery(),
        )
        .unwrap(),
    );
    let buffers = crate::dns::memory::Budget::new(1_048_576).unwrap();
    let (mailbox, _commits) = queue::fixture_mailbox();
    let mut workers = Workers::with_budget(
        dispatcher,
        fixture.controller.clone(),
        mailbox,
        worker_limits(),
        buffers.clone(),
    )
    .unwrap();
    let storage = buffers.used();
    workers
        .admit_udp(fixture.input("unmatched.invalid").await)
        .unwrap();
    assert!(buffers.used() - storage >= 8 * 65_537);
    assert!(events.lock().unwrap().is_empty());
    let packet = fixture
        .channels
        .as_mut()
        .unwrap()
        .packets
        .recv()
        .await
        .unwrap();
    packet.complete(Ok(())).unwrap();
    workers.join_next().await.unwrap().unwrap().outcome.unwrap();
    assert_eq!(buffers.used(), storage);
    workers
        .join(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    fixture.close(&mut workers).await;
    drop(workers);
    assert_eq!(buffers.used(), 0);
}

#[test]
fn worker_storage_shortage_preserves_the_shared_budget() {
    let buffers = crate::dns::memory::Budget::new(1).unwrap();
    assert!(matches!(
        try_direct_workers_with_budget(routes(), buffers.clone()),
        Err(WorkerError::BufferBudget)
    ));
    assert_eq!(buffers.used(), 0);
}
