// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use crate::dns::{LocalReply, Question};
use tokio::{
    io::{DuplexStream, duplex},
    sync::watch,
};
use warper_core::dns::Name;

fn request(owner: &watch::Sender<bool>, seconds: u64) -> Request {
    Request {
        deadline: Instant::now() + Duration::from_secs(seconds),
        cancellation: owner.subscribe(),
    }
}
fn query() -> Packet {
    let mut bytes = vec![0, 17, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    bytes.extend_from_slice(Name::from_ascii("framed.example.test").unwrap().wire());
    bytes.extend_from_slice(&[0, 1, 0, 1]);
    Packet::request(&bytes, Limits::new(512, 8).unwrap()).unwrap()
}
fn frame(packet: &Packet) -> Vec<u8> {
    let bytes = packet.encode().unwrap();
    let mut result = (bytes.len() as u16).to_be_bytes().to_vec();
    result.extend_from_slice(&bytes);
    result
}
fn pair(capacity: usize) -> (Connection<DuplexStream>, DuplexStream) {
    let (stream, peer) = duplex(capacity);
    (Connection::new(stream, Limits::new(512, 8).unwrap()), peer)
}
fn expect_query(result: Result<Completion, Error>, expected: Question) {
    let Completion::Query(packet) = result.unwrap() else {
        panic!("expected a complete DNS query");
    };
    assert_eq!(packet.question(), expected);
    assert_eq!(packet.id(), 17);
}

#[tokio::test(start_paused = true)]
async fn partial_prefix_and_body_resume_after_expired_observation() {
    let query = query();
    let bytes = frame(&query);
    let (owner, _) = watch::channel(false);
    for cut in [1, 2, 7, bytes.len() - 1] {
        let (mut connection, mut peer) = pair(1024);
        connection.begin_read(request(&owner, 10)).unwrap();
        peer.write_all(&bytes[..cut]).await.unwrap();
        assert!(
            matches!(
                connection.wait(request(&owner, 1)).await,
                Err(Error::WaitDeadline)
            ),
            "cut {cut}"
        );
        assert_eq!(
            connection.begin_read(request(&owner, 10)),
            Err(Error::InvalidState)
        );
        peer.write_all(&bytes[cut..]).await.unwrap();
        expect_query(connection.wait(request(&owner, 2)).await, query.question());
        assert!(matches!(
            connection.wait(request(&owner, 2)).await,
            Err(Error::InvalidState)
        ));
    }
}

#[tokio::test(start_paused = true)]
async fn dropped_read_observation_keeps_consumed_bytes() {
    use std::task::{Context, Waker};
    let query = query();
    let bytes = frame(&query);
    let (owner, _) = watch::channel(false);
    let (mut connection, mut peer) = pair(1024);
    connection.begin_read(request(&owner, 10)).unwrap();
    peer.write_all(&bytes[..7]).await.unwrap();
    let mut waiting = Box::pin(connection.wait(request(&owner, 2)));
    assert!(
        waiting
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    drop(waiting);
    peer.write_all(&bytes[7..]).await.unwrap();
    expect_query(connection.wait(request(&owner, 2)).await, query.question());
}

#[tokio::test(start_paused = true)]
async fn multiple_pipelined_queries_keep_independent_frames_and_clean_eof() {
    let query = query();
    let (owner, _) = watch::channel(false);
    let (mut connection, mut peer) = pair(1024);
    for _ in 0..3 {
        peer.write_all(&frame(&query)).await.unwrap();
    }
    drop(peer);
    for _ in 0..3 {
        connection.begin_read(request(&owner, 2)).unwrap();
        expect_query(connection.wait(request(&owner, 2)).await, query.question());
    }
    connection.begin_read(request(&owner, 2)).unwrap();
    assert!(matches!(
        connection.wait(request(&owner, 2)).await,
        Ok(Completion::End)
    ));
    assert_eq!(
        connection.begin_read(request(&owner, 2)),
        Err(Error::Closed)
    );
}

#[tokio::test(start_paused = true)]
async fn invalid_or_incomplete_frames_make_the_connection_terminal() {
    struct Case {
        id: &'static str,
        input: Vec<u8>,
        expected: Error,
    }
    let (owner, _) = watch::channel(false);
    for case in [
        Case {
            id: "partial prefix",
            input: vec![0],
            expected: Error::UnexpectedEof,
        },
        Case {
            id: "partial body",
            input: vec![0, 12, 0],
            expected: Error::UnexpectedEof,
        },
        Case {
            id: "zero length",
            input: vec![0, 0],
            expected: Error::InvalidLength,
        },
        Case {
            id: "short header",
            input: vec![0, 11],
            expected: Error::InvalidLength,
        },
        Case {
            id: "oversize",
            input: vec![2, 1],
            expected: Error::ResourceLimit,
        },
        Case {
            id: "malformed query",
            input: vec![0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            expected: Error::Packet(super::super::Error::Malformed),
        },
    ] {
        let (mut connection, mut peer) = pair(1024);
        peer.write_all(&case.input).await.unwrap();
        drop(peer);
        connection.begin_read(request(&owner, 2)).unwrap();
        assert!(
            matches!(connection.wait(request(&owner, 2)).await, Err(error) if error == case.expected),
            "{}",
            case.id
        );
        assert_eq!(
            connection.begin_read(request(&owner, 2)),
            Err(case.expected),
            "{}",
            case.id
        );
    }
}

#[tokio::test(start_paused = true)]
async fn expired_original_read_never_reinterprets_remaining_input() {
    let (owner, _) = watch::channel(false);
    let (mut connection, mut peer) = pair(1024);
    connection.begin_read(request(&owner, 2)).unwrap();
    peer.write_all(&[0]).await.unwrap();
    assert!(matches!(
        connection.wait(request(&owner, 1)).await,
        Err(Error::WaitDeadline)
    ));
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(matches!(
        connection.wait(request(&owner, 2)).await,
        Err(Error::Operation(RequestError::Timeout))
    ));
    assert_eq!(
        connection.begin_read(request(&owner, 2)),
        Err(Error::Operation(RequestError::Timeout))
    );
}

#[tokio::test(start_paused = true)]
async fn interrupted_partial_reply_resumes_without_replaying_the_prefix() {
    let query = query();
    let reply = Packet::response(
        &query.local_reply(LocalReply::ServFail).unwrap(),
        &query,
        Limits::new(512, 8).unwrap(),
    )
    .unwrap();
    let expected = frame(&reply);
    let (owner, _) = watch::channel(false);
    let (observer, _) = watch::channel(false);
    let (mut connection, mut peer) = pair(2);
    connection.begin_reply(&reply, request(&owner, 10)).unwrap();
    let observation = request(&observer, 5);
    let client = tokio::spawn(async move {
        let mut prefix = [0; 2];
        peer.read_exact(&mut prefix).await.unwrap();
        observer.send_replace(true);
        (peer, prefix)
    });
    assert!(matches!(
        connection.wait(observation).await,
        Err(Error::WaitCancelled)
    ));
    let (mut peer, prefix) = client.await.unwrap();
    let mut remaining = vec![0; expected.len() - 2];
    let (written, read) = tokio::join!(
        connection.wait(request(&owner, 2)),
        peer.read_exact(&mut remaining)
    );
    assert!(matches!(written, Ok(Completion::Written)));
    read.unwrap();
    assert_eq!([prefix.as_slice(), &remaining].concat(), expected);
    assert!(matches!(
        connection.wait(request(&owner, 2)).await,
        Err(Error::InvalidState)
    ));
}

#[tokio::test(start_paused = true)]
async fn original_cancellation_after_partial_output_forbids_reuse() {
    let query = query();
    let reply = Packet::response(
        &query.local_reply(LocalReply::ServFail).unwrap(),
        &query,
        Limits::new(512, 8).unwrap(),
    )
    .unwrap();
    let (owner, _) = watch::channel(false);
    let (observer, _) = watch::channel(false);
    let (mut connection, mut peer) = pair(2);
    connection.begin_reply(&reply, request(&owner, 10)).unwrap();
    assert!(matches!(
        connection.wait(request(&observer, 1)).await,
        Err(Error::WaitDeadline)
    ));
    owner.send_replace(true);
    assert!(matches!(
        connection.wait(request(&observer, 2)).await,
        Err(Error::Operation(RequestError::Cancelled))
    ));
    assert_eq!(
        connection.begin_reply(&reply, request(&observer, 2)),
        Err(Error::Operation(RequestError::Cancelled))
    );
    let mut prefix = [0; 2];
    peer.read_exact(&mut prefix).await.unwrap();
    assert_eq!(prefix, (reply.encode().unwrap().len() as u16).to_be_bytes());
}

#[tokio::test(start_paused = true)]
async fn rejected_operations_leave_the_idle_stream_usable_and_io_failure_is_terminal() {
    let (owner, _) = watch::channel(false);
    let (mut connection, peer) = pair(1024);
    assert_eq!(
        connection.begin_read(request(&owner, 0)),
        Err(Error::Operation(RequestError::Timeout))
    );
    assert_eq!(
        connection.begin_read(request(&owner, 31)),
        Err(Error::InvalidRequest)
    );
    assert_eq!(
        connection.begin_reply(&query(), request(&owner, 2)),
        Err(Error::InvalidRequest)
    );
    let query = query();
    let reply = Packet::response(
        &query.local_reply(LocalReply::ServFail).unwrap(),
        &query,
        Limits::new(512, 8).unwrap(),
    )
    .unwrap();
    drop(peer);
    connection.begin_reply(&reply, request(&owner, 2)).unwrap();
    assert!(matches!(
        connection.wait(request(&owner, 2)).await,
        Err(Error::Io(io::ErrorKind::BrokenPipe))
    ));
    assert_eq!(
        connection.begin_read(request(&owner, 2)),
        Err(Error::Io(io::ErrorKind::BrokenPipe))
    );
}

#[tokio::test(start_paused = true)]
async fn oversized_reply_and_closed_original_owner_are_rejected_before_io() {
    let query = query();
    let reply = Packet::response(
        &query.local_reply(LocalReply::ServFail).unwrap(),
        &query,
        Limits::new(512, 8).unwrap(),
    )
    .unwrap();
    let (owner, _) = watch::channel(false);
    let (stream, mut peer) = duplex(1024);
    let mut connection = Connection::new(stream, Limits::new(12, 8).unwrap());
    assert_eq!(
        connection.begin_reply(&reply, request(&owner, 2)),
        Err(Error::ResourceLimit)
    );
    let operation = request(&owner, 2);
    drop(owner);
    assert_eq!(
        connection.begin_read(operation),
        Err(Error::Operation(RequestError::Cancelled))
    );
    drop(connection);
    assert_eq!(peer.read(&mut [0; 2]).await.unwrap(), 0);
}

#[tokio::test(start_paused = true)]
async fn zero_length_write_stops_without_retrying_a_frame() {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::ReadBuf;
    struct ZeroWriter;
    impl AsyncRead for ZeroWriter {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }
    impl AsyncWrite for ZeroWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(0))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    let query = query();
    let reply = Packet::response(
        &query.local_reply(LocalReply::ServFail).unwrap(),
        &query,
        Limits::new(512, 8).unwrap(),
    )
    .unwrap();
    let (owner, _) = watch::channel(false);
    let mut connection = Connection::new(ZeroWriter, Limits::new(512, 8).unwrap());
    connection.begin_reply(&reply, request(&owner, 2)).unwrap();
    assert!(matches!(
        connection.wait(request(&owner, 2)).await,
        Err(Error::Io(io::ErrorKind::WriteZero))
    ));
    assert_eq!(
        connection.begin_reply(&reply, request(&owner, 2)),
        Err(Error::Io(io::ErrorKind::WriteZero))
    );
}

#[tokio::test]
async fn framed_queries_keep_the_shared_decoded_charge_until_packet_drop() {
    let budget = crate::dns::memory::Budget::new(1_048_576).unwrap();
    let (stream, mut peer) = duplex(1024);
    let mut connection =
        Connection::with_budget(stream, Limits::new(512, 8).unwrap(), budget.clone());
    let (owner, _) = watch::channel(false);
    connection.begin_read(request(&owner, 1)).unwrap();
    peer.write_all(&frame(&query())).await.unwrap();
    let Completion::Query(packet) = connection.wait(request(&owner, 1)).await.unwrap() else {
        panic!("expected a budgeted query");
    };
    assert!(budget.used() > 0);
    drop(connection);
    assert!(budget.used() > 0);
    drop(packet);
    assert_eq!(budget.used(), 0);
    peer.shutdown().await.unwrap();
}
