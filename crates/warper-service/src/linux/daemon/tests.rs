// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Task ownership faults without constructing privileged runtime evidence.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

fn inert() -> Daemon {
    let (commands, _inbox) = mpsc::channel(CHANNEL_CAPACITY);
    let (_out, events) = mpsc::channel(CHANNEL_CAPACITY);
    let (_policy, policy) = watch::channel(Arc::new(OwnerPolicy::new(None).unwrap()));
    let (stop, _) = watch::channel(false);
    let (join_keep, _) = watch::channel(false);
    Daemon {
        workers: native::Workers::new(1).unwrap(),
        actor: None,
        retirement: None,
        endpoint: None,
        listener: None,
        lease: None,
        endpoint_failed: false,
        network_lost: false,
        unstarted: None,
        events_closed: false,
        admission: None,
        commands,
        events,
        policy,
        stop,
        join_keep,
        clients: JoinSet::new(),
        running: None,
        stopped: None,
        notices: VecDeque::with_capacity(MAX_NOTICES),
        instance: [0; 16],
        accept_sent: false,
        used: true,
        report: Report::default(),
    }
}

#[tokio::test]
async fn cleanup_deadline_retains_native_work_until_a_later_explicit_join() {
    let mut daemon = inert();
    let (release, blocked) = std::sync::mpsc::channel();
    let (started, started_rx) = oneshot::channel();
    let finished = Arc::new(AtomicBool::new(false));
    let worker_finished = finished.clone();
    daemon.actor = Some(daemon.workers.try_reserve().unwrap().start(move || {
        started.send(()).unwrap();
        blocked.recv().unwrap();
        worker_finished.store(true, Ordering::Release);
        Ok(())
    }));
    started_rx.await.unwrap();
    let failure = daemon
        .finish_until(None, Instant::now() + Duration::from_millis(1))
        .await
        .unwrap_err();
    assert!(!failure.report.cleaned);
    assert!(
        failure
            .cleanup
            .iter()
            .any(|error| matches!(error, Error::Deadline))
    );
    assert!(daemon.actor.is_some());
    assert!(!finished.load(Ordering::Acquire));
    release.send(()).unwrap();
    assert!(daemon.cleanup().await.unwrap().cleaned);
    assert!(daemon.actor.is_none());
    assert!(finished.load(Ordering::Acquire));
}

#[tokio::test]
async fn initial_failure_survives_native_shutdown_failure() {
    let mut daemon = inert();
    daemon.actor = Some(
        daemon
            .workers
            .try_reserve()
            .unwrap()
            .start(|| Err(Error::Io(io::ErrorKind::BrokenPipe))),
    );
    let failure = daemon
        .finish(Some(Error::ClientProtocol))
        .await
        .unwrap_err();
    assert!(matches!(failure.primary, Some(Error::ClientProtocol)));
    assert!(
        failure
            .cleanup
            .iter()
            .any(|error| matches!(error, Error::Io(io::ErrorKind::BrokenPipe)))
    );
    assert!(daemon.actor.is_none());
}

#[tokio::test]
async fn client_worker_panic_is_joined_and_reported() {
    let mut daemon = inert();
    let (started, observed) = oneshot::channel();
    daemon.clients.spawn(async move {
        started.send(()).unwrap();
        panic!("injected client worker failure");
    });
    observed.await.unwrap();
    let failure = daemon.finish(None).await.unwrap_err();
    assert!(
        failure
            .cleanup
            .iter()
            .any(|error| matches!(error, Error::ClientTask))
    );
    assert!(daemon.clients.is_empty());
}

#[tokio::test]
async fn lost_network_task_cannot_be_reported_as_verified_retirement() {
    let mut daemon = inert();
    let (stop, _) = watch::channel(false);
    let task = tokio::spawn(async { panic!("injected network owner loss") });
    daemon.running = Some(Running {
        epoch: 1,
        stop,
        observed: None,
        notified: false,
        task,
    });
    let joined = network_result(&mut daemon.running).await;
    assert!(matches!(
        daemon.network_joined(joined),
        Err(Error::NetworkTask)
    ));
    let failure = daemon.finish(None).await.unwrap_err();
    assert!(!failure.report.cleaned);
    assert!(
        failure
            .cleanup
            .iter()
            .any(|error| matches!(error, Error::OwnershipUncertain))
    );
    assert!(daemon.network_lost);
}

#[test]
fn policy_refresh_failure_preserves_the_original_dispatch_rejection() {
    let error = Error::PolicyUpdate {
        primary: Some(Box::new(controller::Error::Rejected(
            warper_control::wire::Code::Busy,
        ))),
        secondary: Box::new(controller::Error::Owner(
            runtime::enrollment::Error::UnsafeState,
        )),
    };
    assert!(error.to_string().starts_with("ControlRejected: Busy;"));
}

#[tokio::test]
async fn unjoined_task_metadata_cannot_admit_another_client_task() {
    let mut daemon = inert();
    for _ in 0..MAX_CLIENT_TASKS {
        daemon.clients.spawn(pending());
    }
    let admission = Admission::new(admission::Plan::new(1, 1, 68, 114).unwrap());
    let (stream, _peer) = NativeStream::pair().unwrap();
    daemon
        .accept(stream, admission.try_client().unwrap())
        .unwrap();
    assert_eq!(daemon.clients.len(), MAX_CLIENT_TASKS);
    assert_eq!(daemon.report.rejected_clients, 1);
    drop(admission.try_client().unwrap());
    assert!(daemon.cleanup().await.unwrap().cleaned);
    assert!(daemon.clients.is_empty());
}

#[tokio::test]
async fn disconnect_can_settle_a_start_that_failed_before_native_mutation() {
    let mut daemon = inert();
    daemon.unstarted = Some(7);
    daemon.effect(Effect::Stop { epoch: 7 }).unwrap();
    daemon.event(Event::StartFailed(7), false).unwrap();
    assert!(daemon.unstarted.is_none());
    assert!(daemon.running.is_none());
    assert!(daemon.cleanup().await.unwrap().cleaned);
}
