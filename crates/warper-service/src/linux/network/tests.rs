// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Startup task acknowledgment and service-owned cancellation boundaries.

use super::*;

fn request(owner: &watch::Sender<bool>) -> Request {
    Request {
        deadline: Instant::now() + Duration::from_secs(1),
        cancellation: owner.subscribe(),
    }
}

#[test]
fn native_supervisor_deadlines_reject_unbounded_and_submillisecond_values() {
    for wait in [
        Duration::ZERO,
        Duration::from_nanos(1),
        Duration::from_secs(31),
    ] {
        assert_eq!(
            crate::preflight::validate_native_deadlines(wait, Duration::from_secs(1)),
            Err(crate::preflight::Error::InvalidLimits)
        );
        assert_eq!(
            crate::preflight::validate_native_deadlines(Duration::from_secs(1), wait),
            Err(crate::preflight::Error::InvalidLimits)
        );
    }
    crate::preflight::validate_native_deadlines(Duration::from_millis(1), Duration::from_secs(30))
        .unwrap();
}

#[tokio::test]
async fn task_that_completes_before_polling_pending_cannot_acknowledge_startup() {
    let (owner, _) = watch::channel(false);
    let (task, ready) = spawn_started(async { 7u8 });
    assert_eq!(
        wait_started(ready, request(&owner)).await,
        Err(Error::TaskStopped)
    );
    assert_eq!(task.await.unwrap(), 7);
}

#[tokio::test]
async fn startup_acknowledgment_preserves_the_same_task_until_join() {
    let (owner, _) = watch::channel(false);
    let (release, gate) = oneshot::channel::<u8>();
    let (task, ready) = spawn_started(async move { gate.await.unwrap() });
    wait_started(ready, request(&owner)).await.unwrap();
    assert!(!task.is_finished());
    release.send(19).unwrap();
    assert_eq!(task.await.unwrap(), 19);
}

#[tokio::test(start_paused = true)]
async fn expired_start_observer_does_not_discard_owned_work() {
    let (owner, _) = watch::channel(false);
    let (release, gate) = oneshot::channel::<u8>();
    let (task, ready) = spawn_started(async move { gate.await.unwrap() });
    assert_eq!(
        wait_started(
            ready,
            Request {
                deadline: Instant::now(),
                cancellation: owner.subscribe()
            }
        )
        .await,
        Err(Error::Deadline)
    );
    release.send(23).unwrap();
    assert_eq!(task.await.unwrap(), 23);
}

#[tokio::test]
async fn dropped_readiness_observer_does_not_cancel_the_service_task() {
    let (release, gate) = oneshot::channel::<u8>();
    let (task, ready) = spawn_started(async move { gate.await.unwrap() });
    drop(ready);
    tokio::task::yield_now().await;
    assert!(!task.is_finished());
    release.send(29).unwrap();
    assert_eq!(task.await.unwrap(), 29);
}

#[tokio::test]
async fn canceled_or_lost_service_owner_is_distinct_before_mutation() {
    let (owner, receiver) = watch::channel(false);
    owner.send_replace(true);
    assert_eq!(check(&request(&owner)), Err(Error::Cancelled));
    owner.send_replace(false);
    let expired = Request {
        deadline: Instant::now(),
        cancellation: receiver.clone(),
    };
    assert_eq!(check(&expired), Err(Error::Deadline));
    drop(owner);
    assert_eq!(
        check(&Request {
            deadline: Instant::now() + Duration::from_secs(1),
            cancellation: receiver
        }),
        Err(Error::OwnerLost)
    );
}

struct PendingBackend;
impl warper_core::transport::Backend for PendingBackend {
    fn id(&self) -> warper_core::BackendId {
        warper_core::BackendId(19)
    }
    fn capabilities(&self) -> warper_core::transport::Capabilities {
        warper_core::transport::Capabilities {
            ipv4: true,
            ipv6: false,
            tcp: true,
            udp: false,
        }
    }
    fn open_tcp(
        &self,
        _destination: std::net::SocketAddr,
        _request: Request,
    ) -> warper_core::transport::OpenTcp<'_> {
        Box::pin(std::future::pending())
    }
}
fn captured(id: u64) -> (tokio::io::DuplexStream, warper_core::transport::CapturedTcp) {
    let (app, stream) = tokio::io::duplex(1);
    (
        app,
        warper_core::transport::CapturedTcp {
            metadata: warper_core::transport::Metadata {
                id,
                source: "192.0.2.1:50001".parse().unwrap(),
                destination: "192.0.2.2:443".parse().unwrap(),
                backend: warper_core::BackendId(19),
            },
            stream: Box::new(stream),
        },
    )
}

#[tokio::test]
async fn exhausted_relay_capacity_rejects_only_the_new_flow_and_preserves_the_owner() {
    use tokio::io::AsyncReadExt;
    let mut relays = relay::Relays::new(
        vec![Arc::new(PendingBackend)],
        relay::Limits {
            flows: 1,
            ..relay::Limits::default()
        },
    )
    .unwrap();
    let mut report = Report::default();
    let (_first_app, first) = captured(1);
    let (mut rejected_app, rejected) = captured(2);
    assert_eq!(
        dispatch(&mut relays, &mut report, first),
        Ok(Dispatch::Admitted)
    );
    assert_eq!(
        dispatch(&mut relays, &mut report, rejected),
        Ok(Dispatch::Rejected)
    );
    assert_eq!(rejected_app.read(&mut [0]).await.unwrap(), 0);
    assert_eq!(report.rejected_flows, 1);
    assert_eq!(
        report.last_admission_failure,
        Some(relay::AdmissionError::Full)
    );
    assert_eq!(relays.retained(), 1);
    let shutdown = relays.shutdown().await;
    assert_eq!(shutdown.admitted, 1);
    assert_eq!(shutdown.cancelled, 1);
    assert_eq!(shutdown.worker_failures, 0);
}
