// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;

#[tokio::test]
async fn queued_datagram_from_an_unexpected_peer_is_rejected() {
    // Model an already queued packet from the bind-to-connect interval.
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    other
        .send_to(b"foreign", receiver.local_addr().unwrap())
        .await
        .unwrap();
    let mut bytes = [0; 16];
    receiver.readable().await.unwrap();
    let error = receiver
        .try_io(Interest::READABLE, || {
            receive(&receiver, &mut bytes, sender.local_addr().unwrap())
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn receive_preserves_zero_length_and_reports_truncation_without_remainder() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    receiver
        .connect(sender.local_addr().unwrap())
        .await
        .unwrap();
    sender
        .connect(receiver.local_addr().unwrap())
        .await
        .unwrap();
    for (payload, capacity) in [
        (b"".as_slice(), 8),
        (b"first-datagram", 3),
        (b"next", 8),
        (b"discard", 0),
        (b"final", 8),
    ] {
        assert_eq!(sender.send(payload).await.unwrap(), payload.len());
        let mut bytes = vec![0; capacity];
        let received = loop {
            receiver.readable().await.unwrap();
            match receiver.try_io(Interest::READABLE, || {
                receive(&receiver, &mut bytes, sender.local_addr().unwrap())
            }) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                result => break result.unwrap(),
            }
        };
        assert_eq!(received.length, payload.len().min(capacity));
        assert_eq!(received.truncated, payload.len() > capacity);
        assert_eq!(&bytes[..received.length], &payload[..received.length]);
    }
}

#[tokio::test]
async fn connected_receive_filters_a_different_source_port() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    receiver
        .connect(sender.local_addr().unwrap())
        .await
        .unwrap();
    other
        .send_to(b"foreign", receiver.local_addr().unwrap())
        .await
        .unwrap();
    sender
        .send_to(b"expected", receiver.local_addr().unwrap())
        .await
        .unwrap();
    let mut bytes = [0; 16];
    let received = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            receiver.readable().await.unwrap();
            match receiver.try_io(Interest::READABLE, || {
                receive(&receiver, &mut bytes, sender.local_addr().unwrap())
            }) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                result => break result.unwrap(),
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        received,
        Received {
            length: 8,
            truncated: false
        }
    );
    assert_eq!(&bytes[..8], b"expected");
}
