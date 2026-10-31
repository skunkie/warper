// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use std::{
    future::pending,
    net::SocketAddr,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use warper_core::transport::{Metadata, OpenTcp};

struct BackendMock {
    stream: Mutex<Option<DuplexStream>>,
    calls: AtomicUsize,
    destination: SocketAddr,
    error: Option<SetupError>,
    panics: bool,
    capabilities: Capabilities,
}
impl Backend for BackendMock {
    fn id(&self) -> BackendId {
        BackendId(17)
    }
    fn capabilities(&self) -> Capabilities {
        self.capabilities
    }
    fn open_tcp(&self, destination: SocketAddr, _request: Request) -> OpenTcp<'_> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            assert_eq!(destination, self.destination);
            assert!(!self.panics, "injected worker panic");
            if let Some(error) = self.error {
                return Err(error);
            }
            let stream = self.stream.lock().unwrap().take();
            match stream {
                Some(stream) => Ok(Box::new(stream) as _),
                None => pending().await,
            }
        })
    }
}
fn create(
    limits: Limits,
    error: Option<SetupError>,
    panics: bool,
) -> (
    Relays,
    Arc<BackendMock>,
    DuplexStream,
    CapturedTcp,
    DuplexStream,
) {
    let (application, captured) = tokio::io::duplex(128);
    let (upstream, target) = tokio::io::duplex(128);
    let destination = "192.0.2.9:443".parse().unwrap();
    let backend = Arc::new(BackendMock {
        stream: Mutex::new(Some(upstream)),
        calls: AtomicUsize::new(0),
        destination,
        error,
        panics,
        capabilities: Capabilities {
            ipv4: true,
            ipv6: true,
            tcp: true,
            udp: false,
        },
    });
    let relays = Relays::new(vec![backend.clone()], limits).unwrap();
    (
        relays,
        backend,
        application,
        CapturedTcp {
            metadata: Metadata {
                id: 1,
                source: "192.0.2.2:50000".parse().unwrap(),
                destination,
                backend: BackendId(17),
            },
            stream: Box::new(captured),
        },
        target,
    )
}
#[tokio::test]
async fn bidirectional_bytes_and_response_after_fin_are_joined_with_exact_counts() {
    let (mut relays, backend, mut application, flow, mut target) =
        create(Limits::default(), None, false);
    relays.admit(flow).unwrap();
    let expected: Vec<u8> = (0..65536).map(|n| (n % 251) as u8).collect();
    let request = expected.clone();
    let response = expected.clone();
    let app = tokio::spawn(async move {
        application.write_all(&request).await.unwrap();
        application.shutdown().await.unwrap();
        let mut received = Vec::new();
        application.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, request);
    });
    let peer = tokio::spawn(async move {
        let mut received = Vec::new();
        target.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, response);
        target.write_all(&received).await.unwrap();
        target.shutdown().await.unwrap();
    });
    let completion = tokio::time::timeout(Duration::from_secs(2), relays.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    app.await.unwrap();
    peer.await.unwrap();
    assert_eq!(completion.outcome, Ok(()));
    assert_eq!(
        completion.transferred,
        Transferred {
            sent: 65536,
            received: 65536
        }
    );
    assert_eq!(backend.calls.load(Ordering::Relaxed), 1);
    let report = relays.shutdown().await;
    assert_eq!(report.finished, 1);
    assert_eq!(report.failed, 0);
}
#[tokio::test(start_paused = true)]
async fn setup_failure_idle_and_absolute_expiry_never_retry_the_selected_backend() {
    for expected in [
        FlowError::Setup(SetupError::Authentication),
        FlowError::IdleTimeout,
        FlowError::MaxAge,
    ] {
        let limits = Limits {
            idle_timeout: Duration::from_millis(if expected == FlowError::MaxAge {
                100
            } else {
                10
            }),
            max_age: Duration::from_millis(if expected == FlowError::MaxAge {
                10
            } else {
                100
            }),
            ..Limits::default()
        };
        let error = if let FlowError::Setup(error) = expected {
            Some(error)
        } else {
            None
        };
        let (mut relays, backend, _app, flow, _target) = create(limits, error, false);
        relays.admit(flow).unwrap();
        let completion = relays.next().await.unwrap().unwrap();
        assert_eq!(completion.outcome, Err(expected));
        assert_eq!(backend.calls.load(Ordering::Relaxed), 1);
        assert_eq!(relays.shutdown().await.failed, 1);
    }
}
#[tokio::test]
async fn explicit_shutdown_cancels_and_joins_workers_and_closes_both_owned_streams() {
    let (mut relays, _backend, mut app, flow, mut target) = create(Limits::default(), None, false);
    relays.admit(flow).unwrap();
    tokio::task::yield_now().await;
    let report = relays.shutdown().await;
    assert_eq!(report.cancelled, 1);
    assert_eq!(report.aborted, 0);
    assert_eq!(app.read(&mut [0]).await.unwrap(), 0);
    assert_eq!(target.read(&mut [0]).await.unwrap(), 0);
}
#[tokio::test]
async fn worker_panic_is_surfaced_and_permanently_closes_admission() {
    let (mut relays, _backend, _app, flow, _target) = create(Limits::default(), None, true);
    relays.admit(flow).unwrap();
    assert_eq!(relays.next().await, Err(WorkerError::Panicked));
    let (_app, stream) = tokio::io::duplex(1);
    let flow = CapturedTcp {
        metadata: Metadata {
            id: 2,
            source: "192.0.2.2:50001".parse().unwrap(),
            destination: "192.0.2.9:443".parse().unwrap(),
            backend: BackendId(17),
        },
        stream: Box::new(stream),
    };
    assert_eq!(relays.admit(flow), Err(AdmissionError::Stopping));
    assert_eq!(relays.shutdown().await.worker_failures, 1);
}

#[tokio::test(start_paused = true)]
async fn service_enforces_setup_deadline_when_backend_ignores_its_request() {
    let limits = Limits {
        setup_timeout: Duration::from_millis(10),
        ..Limits::default()
    };
    let (mut relays, backend, _app, flow, _target) = create(limits, None, false);
    drop(backend.stream.lock().unwrap().take());
    relays.admit(flow).unwrap();
    let completion = relays.next().await.unwrap().unwrap();
    assert_eq!(
        completion.outcome,
        Err(FlowError::Setup(SetupError::Timeout))
    );
    assert_eq!(backend.calls.load(Ordering::Relaxed), 1);
    assert_eq!(relays.shutdown().await.failed, 1);
}

#[tokio::test(start_paused = true)]
async fn payload_progress_renews_idle_expiry_but_never_absolute_age() {
    for absolute in [false, true] {
        let limits = Limits {
            idle_timeout: Duration::from_millis(10),
            max_age: Duration::from_millis(if absolute { 25 } else { 100 }),
            ..Limits::default()
        };
        let (mut relays, _backend, mut app, flow, mut target) = create(limits, None, false);
        relays.admit(flow).unwrap();
        for _ in 0..3 {
            app.write_all(&[7]).await.unwrap();
            target.read_exact(&mut [0]).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(8), relays.next())
                    .await
                    .is_err()
            );
        }
        let completion = relays.next().await.unwrap().unwrap();
        assert_eq!(
            completion.outcome,
            Err(if absolute {
                FlowError::MaxAge
            } else {
                FlowError::IdleTimeout
            })
        );
        assert_eq!(completion.transferred.sent, 3);
        relays.shutdown().await;
    }
}

#[tokio::test]
async fn cancellation_before_first_poll_performs_no_backend_attempt() {
    let (mut relays, backend, _app, flow, _target) = create(Limits::default(), None, false);
    relays.admit(flow).unwrap();
    assert_eq!(relays.shutdown().await.cancelled, 1);
    assert_eq!(backend.calls.load(Ordering::Relaxed), 0);
}

fn flow(id: u64, backend: BackendId, destination: SocketAddr) -> CapturedTcp {
    let (_app, stream) = tokio::io::duplex(1);
    CapturedTcp {
        metadata: Metadata {
            id,
            source: "192.0.2.2:50000".parse().unwrap(),
            destination,
            backend,
        },
        stream: Box::new(stream),
    }
}
#[tokio::test]
async fn admission_bounds_ids_and_completed_records_until_the_owner_joins() {
    let limits = Limits {
        flows: 1,
        ..Limits::default()
    };
    let (mut relays, backend, mut app, captured, mut target) = create(limits, None, false);
    let destination = captured.metadata.destination;
    assert_eq!(
        relays.admit(flow(0, BackendId(17), destination)),
        Err(AdmissionError::InvalidFlow)
    );
    assert_eq!(
        relays.admit(flow(1, BackendId(99), destination)),
        Err(AdmissionError::UnknownBackend)
    );
    relays.admit(captured).unwrap();
    assert_eq!(
        relays.admit(flow(1, BackendId(17), destination)),
        Err(AdmissionError::DuplicateFlow)
    );
    assert_eq!(
        relays.admit(flow(2, BackendId(17), destination)),
        Err(AdmissionError::Full)
    );
    app.shutdown().await.unwrap();
    target.shutdown().await.unwrap();
    assert_eq!(app.read(&mut [0]).await.unwrap(), 0);
    assert_eq!(target.read(&mut [0]).await.unwrap(), 0);
    assert_eq!(
        relays.admit(flow(2, BackendId(17), destination)),
        Err(AdmissionError::Full)
    );
    assert_eq!(relays.next().await.unwrap().unwrap().outcome, Ok(()));
    assert_eq!(relays.retained(), 0);
    assert_eq!(backend.calls.load(Ordering::Relaxed), 1);
    assert_eq!(relays.next().await, Ok(None));
    relays.shutdown().await;
}

#[test]
fn invalid_limits_and_backend_registration_are_rejected_before_task_creation() {
    for limits in [
        Limits {
            flows: 0,
            ..Limits::default()
        },
        Limits {
            flows: 1025,
            ..Limits::default()
        },
        Limits {
            setup_timeout: Duration::ZERO,
            ..Limits::default()
        },
        Limits {
            idle_timeout: Duration::ZERO,
            ..Limits::default()
        },
        Limits {
            max_age: Duration::MAX,
            ..Limits::default()
        },
        Limits {
            shutdown_timeout: Duration::ZERO,
            ..Limits::default()
        },
    ] {
        assert_eq!(
            Relays::required_buffer_capacity(limits),
            Err(AdmissionError::InvalidLimits)
        );
        assert!(matches!(
            Relays::new(vec![], limits),
            Err(AdmissionError::InvalidLimits)
        ));
    }
    assert!(matches!(
        Relays::new(vec![], Limits::default()),
        Err(AdmissionError::InvalidBackends)
    ));
    let backend = Arc::new(BackendMock {
        stream: Mutex::new(None),
        calls: AtomicUsize::new(0),
        destination: "192.0.2.9:443".parse().unwrap(),
        error: None,
        panics: false,
        capabilities: Capabilities {
            ipv4: true,
            ipv6: true,
            tcp: true,
            udp: false,
        },
    });
    assert!(matches!(
        Relays::new(vec![backend.clone(), backend.clone()], Limits::default()),
        Err(AdmissionError::InvalidBackends)
    ));
    assert_eq!(backend.calls.load(Ordering::Relaxed), 0);
    assert_eq!(
        Relays::required_buffer_capacity(Limits::default()),
        Ok(1024 * 16384)
    );
}

#[tokio::test]
async fn later_io_failure_retains_positive_write_counts_without_payload_replay() {
    let (mut relays, backend, mut app, captured, mut target) =
        create(Limits::default(), None, false);
    relays.admit(captured).unwrap();
    app.write_all(&[7]).await.unwrap();
    target.read_exact(&mut [0]).await.unwrap();
    drop(target);
    app.write_all(&[8; 64]).await.unwrap();
    let completion = tokio::time::timeout(Duration::from_secs(1), relays.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        completion.outcome,
        Err(FlowError::Io(io::ErrorKind::BrokenPipe))
    );
    assert_eq!(completion.transferred.sent, 1);
    assert_eq!(backend.calls.load(Ordering::Relaxed), 1);
    let report = relays.shutdown().await;
    assert_eq!(report.failed, 1);
    assert_eq!(report.first_flow_failure, Some(completion));
    assert_eq!(report.shutdown_error, None);
}

#[tokio::test]
async fn unsupported_destination_family_is_rejected_without_backend_io() {
    let backend = Arc::new(BackendMock {
        stream: Mutex::new(None),
        calls: AtomicUsize::new(0),
        destination: "192.0.2.9:443".parse().unwrap(),
        error: None,
        panics: false,
        capabilities: Capabilities {
            ipv4: false,
            ipv6: true,
            tcp: true,
            udp: false,
        },
    });
    let mut relays = Relays::new(vec![backend.clone()], Limits::default()).unwrap();
    assert_eq!(
        relays.admit(flow(1, BackendId(17), backend.destination)),
        Err(AdmissionError::UnsupportedCapability)
    );
    assert_eq!(backend.calls.load(Ordering::Relaxed), 0);
    assert_eq!(relays.shutdown().await.admitted, 0);
}

struct PendingBackend;
impl Backend for PendingBackend {
    fn id(&self) -> BackendId {
        BackendId(18)
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            ipv4: true,
            ipv6: true,
            tcp: true,
            udp: false,
        }
    }
    fn open_tcp(&self, _destination: SocketAddr, _request: Request) -> OpenTcp<'_> {
        Box::pin(pending())
    }
}
#[tokio::test]
async fn surfaced_worker_panic_cancels_and_joins_the_other_selected_backend() {
    let (original, backend, _app, captured, _target) = create(Limits::default(), None, true);
    original.shutdown().await;
    let mut relays =
        Relays::new(vec![backend, Arc::new(PendingBackend)], Limits::default()).unwrap();
    let destination = captured.metadata.destination;
    relays.admit(captured).unwrap();
    relays.admit(flow(2, BackendId(18), destination)).unwrap();
    assert_eq!(relays.next().await, Err(WorkerError::Panicked));
    let report = relays.shutdown().await;
    assert_eq!(report.worker_failures, 1);
    assert_eq!(report.first_worker_failure, Some(WorkerError::Panicked));
    assert_eq!(report.cancelled, 1);
    assert_eq!(report.aborted, 0);
}
