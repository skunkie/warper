// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use crate::dns::routes::Controller;
use std::time::Duration;
use tokio::{sync::watch, time::Instant};
use warper_config::schema::RoutingMode;
use warper_core::{
    BackendId,
    dns::{
        Name,
        lease::{self, Contribution, QuestionKey},
    },
    routing::Policy,
};

fn controller() -> Controller {
    Controller::new(
        Arc::new(Policy::new(&[], 2).unwrap()),
        lease::Limits {
            lease_entries: 4,
            route_entries: 2,
            response_entries: 4,
            flow_entries: 2,
            addresses_per_response: 1,
            bytes: 128 * 1024,
        },
        Instant::now(),
    )
    .unwrap()
}
fn response(controller: &Controller, operation: &Request) -> Response {
    controller
        .reserve(
            RoutingMode::Dynamic,
            QuestionKey {
                backend: BackendId(7),
                name: Name::from_ascii("managed.example.test").unwrap(),
                record_type: 1,
                class: 1,
            },
            &[Contribution {
                address: "192.0.2.7".parse().unwrap(),
                expires_at: Duration::from_secs(20),
            }],
            operation.deadline,
        )
        .unwrap()
}
fn request(owner: &watch::Sender<bool>) -> Request {
    Request {
        deadline: Instant::now() + Duration::from_secs(10),
        cancellation: owner.subscribe(),
    }
}

#[tokio::test(start_paused = true)]
async fn maintenance_retries_keep_the_original_operation_deadline() {
    let controller = controller();
    let (owner, cancellation) = watch::channel(false);
    let mut maintenance = Maintenance {
        changes: controller.changes().unwrap(),
        timeout: Duration::from_secs(2),
        cancellation,
        operation: None,
    };
    let first = maintenance.request().unwrap();
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(maintenance.request().unwrap().deadline, first.deadline);
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(matches!(
        maintenance.request(),
        Err(NativeError::RequestExpired)
    ));
    maintenance.operation = None;
    assert!(maintenance.request().unwrap().deadline > first.deadline);
    owner.send_replace(true);
    assert!(matches!(
        maintenance.request(),
        Err(NativeError::RequestCancelled)
    ));
    controller.close().unwrap();
    controller.finish_drain().unwrap();
}

#[tokio::test(start_paused = true)]
async fn maintenance_idle_wait_survives_observation_loss_and_wakes_on_expiry() {
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    let controller = controller();
    let (_owner, cancellation) = watch::channel(false);
    let mut maintenance = Maintenance {
        changes: controller.changes().unwrap(),
        timeout: Duration::from_secs(2),
        cancellation,
        operation: None,
    };
    let expiry = Instant::now() + Duration::from_secs(1);
    {
        let mut wait = std::pin::pin!(maintenance.wait(Some(expiry)));
        assert!(
            wait.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    // Dropping observation does not consume the expiry or cancel its owner.
    tokio::time::advance(Duration::from_secs(1)).await;
    maintenance.wait(Some(expiry)).await.unwrap();
    {
        let mut wait = std::pin::pin!(maintenance.wait(None));
        assert!(
            wait.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    controller.close().unwrap();
    let mut wait = std::pin::pin!(maintenance.wait(None));
    assert_eq!(
        wait.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Ok(()))
    );
    controller.finish_drain().unwrap();
}

#[tokio::test(start_paused = true)]
async fn maintenance_session_loss_wakes_an_idle_owner() {
    let controller = controller();
    let (owner, cancellation) = watch::channel(false);
    let mut maintenance = Maintenance {
        changes: controller.changes().unwrap(),
        timeout: Duration::from_secs(2),
        cancellation,
        operation: None,
    };
    drop(owner);
    assert_eq!(
        maintenance.wait(None).await,
        Err(NativeError::RequestCancelled)
    );
    controller.close().unwrap();
    controller.finish_drain().unwrap();
}

#[tokio::test(start_paused = true)]
async fn completed_results_hold_admission_until_consumed() {
    let controller = controller();
    let (owner, _) = watch::channel(false);
    let operation = request(&owner);
    let (mailbox, mut inbox) = channel(1).unwrap();
    let mut receipt = mailbox
        .submit(response(&controller, &operation), operation.clone())
        .unwrap();
    let command = inbox.recv().await.unwrap();
    command.completion.finish(Ok(command.response));
    assert_eq!(mailbox.active(), 1);
    assert!(matches!(
        mailbox.submit(response(&controller, &operation), operation),
        Err(Error::Full)
    ));
    let returned = receipt.wait(request(&owner)).await.unwrap();
    assert_eq!(mailbox.active(), 0);
    assert_eq!(controller.response_len(&returned).unwrap(), 1);
    assert!(matches!(
        receipt.wait(request(&owner)).await,
        Err(Error::AlreadyJoined)
    ));
    drop(returned);
    drop(mailbox);
    assert!(inbox.recv().await.is_none());
    controller.advance().unwrap();
    assert_eq!(controller.stats().unwrap().responses, 0);
    controller.close().unwrap();
    controller.finish_drain().unwrap();
}

#[tokio::test(start_paused = true)]
async fn dropping_receipt_cannot_release_unjoined_command_admission() {
    let controller = controller();
    let (owner, _) = watch::channel(false);
    let operation = request(&owner);
    let (mailbox, mut inbox) = channel(1).unwrap();
    let receipt = mailbox
        .submit(response(&controller, &operation), operation.clone())
        .unwrap();
    drop(receipt);
    assert_eq!(mailbox.active(), 1);
    assert!(matches!(
        mailbox.submit(response(&controller, &operation), operation),
        Err(Error::Full)
    ));
    let command = inbox.recv().await.unwrap();
    assert_eq!(mailbox.active(), 1);
    command.completion.finish(Ok(command.response));
    assert_eq!(mailbox.active(), 0);
    controller.advance().unwrap();
    assert_eq!(controller.stats().unwrap().responses, 0);
    drop(mailbox);
    assert!(inbox.recv().await.is_none());
    controller.close().unwrap();
    controller.finish_drain().unwrap();
}

#[tokio::test(start_paused = true)]
async fn cancelled_expired_and_dropped_waits_keep_the_same_result() {
    let controller = controller();
    let (owner, _) = watch::channel(false);
    let operation = request(&owner);
    let (mailbox, mut inbox) = channel(1).unwrap();
    let mut receipt = mailbox
        .submit(response(&controller, &operation), operation)
        .unwrap();
    {
        let mut waiting = std::pin::pin!(receipt.wait(request(&owner)));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(std::future::Future::poll(waiting.as_mut(), &mut context).is_pending());
    }
    let (cancelled, _) = watch::channel(true);
    assert!(matches!(
        receipt.wait(request(&cancelled)).await,
        Err(Error::WaitCancelled)
    ));
    let command = inbox.recv().await.unwrap();
    drop(command.response);
    command.completion.finish(Err(NativeError::RequestExpired));
    let mut expired = request(&owner);
    expired.deadline = Instant::now();
    assert!(matches!(
        receipt.wait(expired).await,
        Err(Error::WaitDeadline)
    ));
    assert_eq!(mailbox.active(), 1);
    assert!(matches!(
        receipt.wait(request(&owner)).await,
        Err(Error::Operation(NativeError::RequestExpired))
    ));
    assert_eq!(mailbox.active(), 0);
    drop(mailbox);
    assert!(inbox.recv().await.is_none());
    controller.advance().unwrap();
    assert_eq!(controller.stats().unwrap().responses, 0);
    controller.close().unwrap();
    controller.finish_drain().unwrap();
}

#[tokio::test(start_paused = true)]
async fn owner_loss_and_closed_mailboxes_preserve_typed_failure() {
    assert!(matches!(channel(0), Err(Error::InvalidLimit)));
    assert!(matches!(
        channel(MAX_REQUESTS + 1),
        Err(Error::InvalidLimit)
    ));
    let controller = controller();
    let (owner, _) = watch::channel(false);
    let operation = request(&owner);
    let (mailbox, inbox) = channel(1).unwrap();
    let mut receipt = mailbox
        .submit(response(&controller, &operation), operation.clone())
        .unwrap();
    drop(inbox);
    assert!(matches!(
        receipt.wait(request(&owner)).await,
        Err(Error::WorkerStopped)
    ));
    assert_eq!(mailbox.active(), 0);
    assert!(matches!(
        mailbox.submit(response(&controller, &operation), operation),
        Err(Error::Closed)
    ));
    controller.advance().unwrap();
    assert_eq!(controller.stats().unwrap().responses, 0);
    controller.close().unwrap();
    controller.finish_drain().unwrap();
}

#[tokio::test(start_paused = true)]
async fn expired_original_requests_never_enter_the_mailbox() {
    let controller = controller();
    let (owner, _) = watch::channel(false);
    let operation = request(&owner);
    let (mailbox, mut inbox) = channel(1).unwrap();
    let reservation = response(&controller, &operation);
    let mut expired = operation.clone();
    expired.deadline = Instant::now();
    assert!(matches!(
        mailbox.submit(reservation, expired),
        Err(Error::Operation(NativeError::RequestExpired))
    ));
    let reservation = response(&controller, &operation);
    owner.send_replace(true);
    assert!(matches!(
        mailbox.submit(reservation, operation),
        Err(Error::Operation(NativeError::RequestCancelled))
    ));
    assert_eq!(mailbox.active(), 0);
    assert!(inbox.try_recv().is_err());
    controller.advance().unwrap();
    assert_eq!(controller.stats().unwrap().responses, 0);
    controller.close().unwrap();
    controller.finish_drain().unwrap();
}

#[tokio::test(start_paused = true)]
async fn closing_admission_drains_accepted_commands() {
    let controller = controller();
    let (owner, _) = watch::channel(false);
    let operation = request(&owner);
    let (mailbox, mut inbox) = channel(1).unwrap();
    let mut receipt = mailbox
        .submit(response(&controller, &operation), operation.clone())
        .unwrap();
    mailbox.admission.close();
    inbox.close();
    assert!(matches!(
        mailbox.submit(response(&controller, &operation), operation),
        Err(Error::Closed)
    ));
    let command = inbox.recv().await.unwrap();
    command.completion.finish(Ok(command.response));
    let returned = receipt.wait(request(&owner)).await.unwrap();
    drop(returned);
    assert!(inbox.recv().await.is_none());
    assert_eq!(mailbox.active(), 0);
    controller.advance().unwrap();
    assert_eq!(controller.stats().unwrap().responses, 0);
    controller.close().unwrap();
    controller.finish_drain().unwrap();
}
