// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use tokio::io::{AsyncReadExt, DuplexStream};
use warper_control::message::SessionState;

const NONCE: [u8; 8] = [3; 8];
const INSTANCE: [u8; 16] = [9; 16];
const STATUS: Status = Status {
    state: SessionState::Disconnected,
    configuration_generation: 17,
    owner_revision: 29,
    configuration_present: true,
    desired_revision: 7,
};

async fn read(stream: &mut DuplexStream) -> Frame {
    let (_keep, mut cancel) = watch::channel(false);
    Frame::read(stream, Instant::now() + RPC_TIMEOUT, &mut cancel)
        .await
        .unwrap()
}
async fn write(stream: &mut DuplexStream, frame: Frame) {
    let (_keep, mut cancel) = watch::channel(false);
    frame
        .write(stream, Instant::now() + RPC_TIMEOUT, &mut cancel)
        .await
        .unwrap();
}
async fn introduction(stream: &mut DuplexStream) {
    let hello = read(stream).await;
    assert_eq!(hello.kind(), Kind::Hello);
    assert_eq!(hello.request_id(), 1);
    write(
        stream,
        Frame::new(Kind::HelloReply, 1, INSTANCE.to_vec()).unwrap(),
    )
    .await;
    let status = read(stream).await;
    assert_eq!(status.kind(), Kind::Status);
    assert_eq!(status.request_id(), 2);
    write(stream, STATUS.frame(2).unwrap()).await;
}
async fn submission(stream: &mut DuplexStream, kind: Kind) -> [u8; 16] {
    introduction(stream).await;
    let request = read(stream).await;
    assert_eq!(request.kind(), kind);
    assert_eq!(request.request_id(), 3);
    let id = wire::operation_id(7, NONCE).unwrap();
    let mut expected = id.to_vec();
    expected.extend_from_slice(&17u64.to_be_bytes());
    expected.extend_from_slice(&7u64.to_be_bytes());
    expected.extend_from_slice(&INSTANCE);
    assert_eq!(request.body(), expected);
    id
}
async fn accept(stream: &mut DuplexStream, kind: Kind) -> [u8; 16] {
    let id = submission(stream, kind).await;
    write(stream, Frame::new(Kind::Accepted, 3, id.to_vec()).unwrap()).await;
    id
}
async fn operation(
    stream: &mut DuplexStream,
    id: [u8; 16],
    state: OperationState,
    code: Code,
    request_id: u64,
) {
    let request = read(stream).await;
    assert_eq!(request.kind(), Kind::OperationStatus);
    assert_eq!(request.request_id(), request_id);
    assert_eq!(request.body(), id);
    write(
        stream,
        Operation { id, state, code }.frame(request_id).unwrap(),
    )
    .await;
}

#[tokio::test]
async fn status_json_uses_observed_metadata_and_never_submits_a_mutation() {
    let (client, mut server) = tokio::io::duplex(256);
    let peer = tokio::spawn(async move {
        introduction(&mut server).await;
        assert_eq!(
            server.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    });
    let (_keep, mut cancel) = watch::channel(false);
    let result = execute(
        client,
        ServiceCommand::Status { json: true },
        [0; 8],
        &mut cancel,
    )
    .await
    .unwrap();
    assert_eq!(
        result,
        "{\"state\":\"disconnected\",\"configuration_generation\":17,\"owner_revision\":29,\"configuration_present\":true,\"desired_revision\":7}\n"
    );
    peer.await.unwrap();
    assert_eq!(
        format_status(STATUS, false),
        "State: disconnected\nConfiguration: installed (generation 17)\nOwner revision: 29\nDesired revision: 7\n"
    );
}

#[tokio::test]
async fn no_wait_stops_after_acceptance_and_client_detach_sends_no_disconnect() {
    for (command, kind) in [
        (ServiceCommand::Up { wait: Wait::None }, Kind::Connect),
        (ServiceCommand::Down { wait: Wait::None }, Kind::Disconnect),
    ] {
        let (client, mut server) = tokio::io::duplex(256);
        let peer = tokio::spawn(async move {
            let id = accept(&mut server, kind).await;
            assert_eq!(
                server.read_u8().await.unwrap_err().kind(),
                std::io::ErrorKind::UnexpectedEof
            );
            id
        });
        let (_keep, mut cancel) = watch::channel(false);
        let result = execute(client, command, NONCE, &mut cancel).await.unwrap();
        let id = peer.await.unwrap();
        assert_eq!(result, format!("Operation {}: accepted\n", identifier(&id)));
    }
}

#[tokio::test(start_paused = true)]
async fn wait_observes_running_then_success_without_resubmitting_connect() {
    let (client, mut server) = tokio::io::duplex(256);
    let peer = tokio::spawn(async move {
        let id = accept(&mut server, Kind::Connect).await;
        operation(&mut server, id, OperationState::Running, Code::None, 4).await;
        operation(&mut server, id, OperationState::Succeeded, Code::None, 5).await;
        id
    });
    let (_keep, mut cancel) = watch::channel(false);
    let result = execute(
        client,
        ServiceCommand::Up {
            wait: Wait::Milliseconds(1_000),
        },
        NONCE,
        &mut cancel,
    )
    .await
    .unwrap();
    let id = peer.await.unwrap();
    assert_eq!(
        result,
        format!("Operation {}: succeeded\n", identifier(&id))
    );
}

#[tokio::test(start_paused = true)]
async fn wait_expiry_preserves_operation_identity_and_only_closes_observation() {
    let (client, mut server) = tokio::io::duplex(256);
    let peer = tokio::spawn(async move {
        let id = accept(&mut server, Kind::Connect).await;
        operation(&mut server, id, OperationState::Running, Code::None, 4).await;
        assert_eq!(
            server.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        id
    });
    let (_keep, mut cancel) = watch::channel(false);
    let error = execute(
        client,
        ServiceCommand::Up {
            wait: Wait::Milliseconds(1),
        },
        NONCE,
        &mut cancel,
    )
    .await
    .unwrap_err();
    let id = peer.await.unwrap();
    assert!(matches!(error, Error::WaitExpired { operation } if operation == id));
    assert!(error.to_string().contains(&identifier(&id)));
    assert!(error.to_string().contains("accepted work continues"));
}

#[tokio::test(start_paused = true)]
async fn stalled_operation_reply_obeys_absolute_observer_deadline() {
    let (client, mut server) = tokio::io::duplex(256);
    let peer = tokio::spawn(async move {
        let id = accept(&mut server, Kind::Connect).await;
        let request = read(&mut server).await;
        assert_eq!(request.kind(), Kind::OperationStatus);
        assert_eq!(
            server.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        id
    });
    let (_keep, mut cancel) = watch::channel(false);
    let error = execute(
        client,
        ServiceCommand::Up {
            wait: Wait::Milliseconds(1),
        },
        NONCE,
        &mut cancel,
    )
    .await
    .unwrap_err();
    let id = peer.await.unwrap();
    assert!(matches!(error, Error::WaitExpired { operation } if operation == id));
}

#[tokio::test]
async fn lost_acceptance_returns_original_identity_and_does_not_retry() {
    let (client, mut server) = tokio::io::duplex(256);
    let peer = tokio::spawn(async move { submission(&mut server, Kind::Disconnect).await });
    let (_keep, mut cancel) = watch::channel(false);
    let error = execute(
        client,
        ServiceCommand::Down { wait: Wait::None },
        NONCE,
        &mut cancel,
    )
    .await
    .unwrap_err();
    let id = peer.await.unwrap();
    assert!(matches!(&error, Error::Observation { operation, .. } if *operation == id));
    assert!(error.to_string().contains(&identifier(&id)));
}

#[tokio::test]
async fn terminal_failures_and_supersession_are_unsuccessful_observations() {
    for (state, code) in [
        (OperationState::Failed, Code::RecoveryRequired),
        (OperationState::Superseded, Code::None),
    ] {
        let (client, mut server) = tokio::io::duplex(256);
        let peer = tokio::spawn(async move {
            let id = accept(&mut server, Kind::Connect).await;
            operation(&mut server, id, state, code, 4).await;
            id
        });
        let (_keep, mut cancel) = watch::channel(false);
        let error = execute(
            client,
            ServiceCommand::Up {
                wait: Wait::Milliseconds(1_000),
            },
            NONCE,
            &mut cancel,
        )
        .await
        .unwrap_err();
        let id = peer.await.unwrap();
        assert!(
            matches!(error, Error::Operation(result) if result == Operation { id, state, code })
        );
    }
}

#[tokio::test]
async fn request_correlation_and_service_rejection_are_enforced() {
    for (kind, request_id, body) in [
        (Kind::HelloReply, 2, INSTANCE.to_vec()),
        (Kind::StatusReply, 1, STATUS.frame(1).unwrap().into_body()),
        (
            Kind::ErrorReply,
            1,
            (Code::PermissionDenied as u16).to_be_bytes().to_vec(),
        ),
    ] {
        let (client, mut server) = tokio::io::duplex(256);
        let peer = tokio::spawn(async move {
            assert_eq!(read(&mut server).await.kind(), Kind::Hello);
            write(&mut server, Frame::new(kind, request_id, body).unwrap()).await;
        });
        let (_keep, mut cancel) = watch::channel(false);
        let error = execute(
            client,
            ServiceCommand::Status { json: false },
            NONCE,
            &mut cancel,
        )
        .await
        .unwrap_err();
        if kind == Kind::ErrorReply {
            assert!(matches!(error, Error::Service(Code::PermissionDenied)));
        } else {
            assert!(matches!(error, Error::UnexpectedReply));
        }
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn accepted_and_observed_operation_ids_must_match_submission() {
    for mismatch_at_acceptance in [true, false] {
        let (client, mut server) = tokio::io::duplex(256);
        let peer = tokio::spawn(async move {
            let id = submission(&mut server, Kind::Connect).await;
            let foreign = wire::operation_id(7, [4; 8]).unwrap();
            write(
                &mut server,
                Frame::new(
                    Kind::Accepted,
                    3,
                    if mismatch_at_acceptance { foreign } else { id }.to_vec(),
                )
                .unwrap(),
            )
            .await;
            if !mismatch_at_acceptance {
                let request = read(&mut server).await;
                write(
                    &mut server,
                    Operation {
                        id: foreign,
                        state: OperationState::Succeeded,
                        code: Code::None,
                    }
                    .frame(request.request_id())
                    .unwrap(),
                )
                .await;
            }
            id
        });
        let (_keep, mut cancel) = watch::channel(false);
        let error = execute(
            client,
            ServiceCommand::Up {
                wait: Wait::Milliseconds(1_000),
            },
            NONCE,
            &mut cancel,
        )
        .await
        .unwrap_err();
        let id = peer.await.unwrap();
        assert!(matches!(error, Error::Observation { operation, .. } if operation == id));
    }
}

#[tokio::test(start_paused = true)]
async fn cancellation_after_acceptance_keeps_identity_and_closes_only_observer() {
    let (client, mut server) = tokio::io::duplex(256);
    let (cancel, mut cancellation) = watch::channel(false);
    let peer = tokio::spawn(async move {
        let id = accept(&mut server, Kind::Connect).await;
        let request = read(&mut server).await;
        assert_eq!(request.kind(), Kind::OperationStatus);
        cancel.send(true).unwrap();
        assert_eq!(
            server.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        id
    });
    let error = execute(
        client,
        ServiceCommand::Up {
            wait: Wait::Milliseconds(1_000),
        },
        NONCE,
        &mut cancellation,
    )
    .await
    .unwrap_err();
    let id = peer.await.unwrap();
    assert!(matches!(error, Error::Observation { operation, .. } if operation == id));
}

#[tokio::test]
async fn invalid_observation_policy_and_unsupported_commands_send_no_frames() {
    for command in [
        ServiceCommand::Up {
            wait: Wait::Milliseconds(0),
        },
        ServiceCommand::Routes,
    ] {
        let (client, mut server) = tokio::io::duplex(256);
        let (_keep, mut cancel) = watch::channel(false);
        let error = execute(client, command, NONCE, &mut cancel)
            .await
            .unwrap_err();
        assert!(matches!(error, Error::InvalidWait | Error::Unsupported));
        assert_eq!(
            server.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }
}

#[tokio::test(start_paused = true)]
async fn spurious_false_cancellation_updates_do_not_abort_observation() {
    let (client, mut server) = tokio::io::duplex(256);
    let (cancel, mut cancellation) = watch::channel(false);
    let _keep = cancel.clone();
    let peer = tokio::spawn(async move {
        let id = accept(&mut server, Kind::Connect).await;
        operation(&mut server, id, OperationState::Running, Code::None, 4).await;
        tokio::time::sleep(Duration::from_millis(1)).await;
        cancel.send(false).unwrap();
        operation(&mut server, id, OperationState::Succeeded, Code::None, 5).await;
        id
    });
    let result = execute(
        client,
        ServiceCommand::Up {
            wait: Wait::Milliseconds(1_000),
        },
        NONCE,
        &mut cancellation,
    )
    .await
    .unwrap();
    let id = peer.await.unwrap();
    assert_eq!(
        result,
        format!("Operation {}: succeeded\n", identifier(&id))
    );
}

#[tokio::test(start_paused = true)]
async fn unavailable_hello_reply_has_a_bounded_wait() {
    let (client, mut server) = tokio::io::duplex(256);
    let peer = tokio::spawn(async move {
        assert_eq!(read(&mut server).await.kind(), Kind::Hello);
        assert_eq!(
            server.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    });
    let (_keep, mut cancel) = watch::channel(false);
    let error = execute(
        client,
        ServiceCommand::Status { json: false },
        NONCE,
        &mut cancel,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, Error::Wire(wire::Error::Deadline)));
    peer.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn cancellation_during_poll_pacing_closes_observer_without_another_request() {
    let (client, mut server) = tokio::io::duplex(256);
    let (cancel, mut cancellation) = watch::channel(false);
    let peer = tokio::spawn(async move {
        let id = accept(&mut server, Kind::Connect).await;
        operation(&mut server, id, OperationState::Running, Code::None, 4).await;
        tokio::time::sleep(Duration::from_millis(1)).await;
        cancel.send(true).unwrap();
        assert_eq!(
            server.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        id
    });
    let error = execute(
        client,
        ServiceCommand::Up {
            wait: Wait::Milliseconds(1_000),
        },
        NONCE,
        &mut cancellation,
    )
    .await
    .unwrap_err();
    let id = peer.await.unwrap();
    assert!(matches!(error, Error::Observation { operation, .. } if operation == id));
}

#[tokio::test]
async fn administrative_requests_preserve_observed_revisions_and_explicit_owner_presence() {
    for owner in [Some(1000u32), None] {
        let (client, mut server) = tokio::io::duplex(256);
        let peer = tokio::spawn(async move {
            introduction(&mut server).await;
            let request = read(&mut server).await;
            assert_eq!(request.kind(), Kind::Enroll);
            assert_eq!(request.request_id(), 3);
            let mut expected = 29u64.to_be_bytes().to_vec();
            expected.extend_from_slice(&u32::from(owner.is_some()).to_be_bytes());
            expected.extend_from_slice(&owner.unwrap_or(0).to_be_bytes());
            assert_eq!(request.body(), expected);
            write(
                &mut server,
                Frame::new(Kind::EnrollmentReply, 3, 30u64.to_be_bytes().to_vec()).unwrap(),
            )
            .await;
        });
        let (_keep, mut cancel) = watch::channel(false);
        assert_eq!(
            administer(client, Administrative::Enroll(owner), &mut cancel)
                .await
                .unwrap(),
            "Owner policy updated (revision 30).\n"
        );
        peer.await.unwrap();
    }
}
#[tokio::test]
async fn install_submits_only_normalized_bytes_and_never_retries_lost_acknowledgment() {
    use std::path::Path;
    use warper_core::configuration::paths::{Account, Paths};
    let paths = Paths::new(
        &Account {
            uid: 1000,
            name: "sample".into(),
            home: "/sample".into(),
        },
        Path::new("/sample"),
        None,
    )
    .unwrap();
    let encoded = warper_config::managed::Snapshot::import(b"tunnel: {ip: 198.18.0.1}\nprotocols: [{socks5: {host: '127.0.0.1:1080', ips: [198.18.0.2/32]}}]", &paths, warper_config::schema::Platform::Linux).unwrap().encode().unwrap();
    let expected = encoded.expose().to_vec();
    let (client, mut server) = tokio::io::duplex(4096);
    let peer = tokio::spawn(async move {
        introduction(&mut server).await;
        let request = read(&mut server).await;
        assert_eq!(request.kind(), Kind::InstallConfig);
        assert_eq!(&request.body()[..8], 17u64.to_be_bytes());
        assert_eq!(&request.body()[8..], expected);
        // Dropping the peer after receipt simulates uncertain acceptance.
    });
    let (_keep, mut cancel) = watch::channel(false);
    let error = administer(client, Administrative::Install(encoded), &mut cancel)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Administrative(_)));
    assert!(error.to_string().contains("inspect status before retrying"));
    peer.await.unwrap();
}

#[tokio::test]
async fn recovery_does_not_require_readable_status_or_retry_uncertain_mutation() {
    for inspect in [true, false] {
        let (client, mut server) = tokio::io::duplex(256);
        let peer = tokio::spawn(async move {
            let hello = read(&mut server).await;
            assert_eq!(hello.kind(), Kind::Hello);
            write(
                &mut server,
                Frame::new(Kind::HelloReply, 1, INSTANCE.to_vec()).unwrap(),
            )
            .await;
            let request = read(&mut server).await;
            assert_eq!(
                request.kind(),
                if inspect {
                    Kind::InspectRecovery
                } else {
                    Kind::Recover
                }
            );
            assert_eq!(request.request_id(), 2);
            assert!(request.body().is_empty());
            if inspect {
                write(
                    &mut server,
                    Frame::new(Kind::RecoveryReply, 2, vec![0, 3]).unwrap(),
                )
                .await;
                assert_eq!(
                    server.read_u8().await.unwrap_err().kind(),
                    std::io::ErrorKind::UnexpectedEof
                );
            }
            // Mutation loses its acknowledgement after receipt.
        });
        let (_keep, mut cancel) = watch::channel(false);
        let result = administer(client, Administrative::Recover { inspect }, &mut cancel).await;
        if inspect {
            assert_eq!(
                result.unwrap(),
                "Pending intent: yes\nRecovery required: yes\nBusy: no\n"
            );
        } else {
            let error = result.unwrap_err();
            assert!(matches!(error, Error::Recovery(_)));
            assert!(
                error
                    .to_string()
                    .contains("recover --inspect before retrying")
            );
        }
        peer.await.unwrap();
    }
}
