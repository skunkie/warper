// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use crate::{
    Seed,
    host::Limits,
    runtime::{Error as RuntimeError, Runtime, delivery},
};
use std::{
    future::{Future, poll_fn},
    task::Poll,
};
use tokio::sync::watch;
use warper_core::routing::Policy;

fn addresses(ipv6: bool) -> (SocketAddr, SocketAddr) {
    if ipv6 {
        (
            "[2001:db8::9]:53".parse().unwrap(),
            "[2001:db8::2]:50000".parse().unwrap(),
        )
    } else {
        (
            "192.0.2.9:53".parse().unwrap(),
            "192.0.2.2:50000".parse().unwrap(),
        )
    }
}
fn request(owner: &watch::Sender<bool>) -> Request {
    Request {
        deadline: Instant::now() + Duration::from_secs(1),
        cancellation: owner.subscribe(),
    }
}
fn fixture(ipv6: bool, requests: usize) -> (Driver, Endpoint, watch::Sender<bool>) {
    let (driver, endpoint) = Driver::new(
        Config {
            endpoint: addresses(ipv6).0,
            requests,
        },
        Arc::new(Notify::new()),
    )
    .unwrap();
    (driver, endpoint, watch::channel(false).0)
}

#[tokio::test]
async fn datagrams_preserve_peers_boundaries_and_admission_until_delivery_is_joined() {
    for ipv6 in [false, true] {
        for payload in [Vec::new(), vec![1, 2, 3], vec![7; MAX_PAYLOAD]] {
            let (mut driver, mut endpoint, owner) = fixture(ipv6, 1);
            let (local, peer) = addresses(ipv6);
            let packet = encode(peer, local, &payload);
            assert!(driver.inject(&packet).unwrap());
            let datagram = endpoint.requests.try_recv().unwrap();
            assert_eq!(datagram.source(), peer);
            assert_eq!(datagram.destination(), local);
            assert_eq!(datagram.payload(), payload);
            assert!(datagram.received_at() <= Instant::now());
            let mut receipt = datagram.respond(&payload, request(&owner)).unwrap();
            assert_eq!(driver.inject(&packet), Err(AdmissionError::ResourceLimit));
            let output = driver.take_reply().unwrap();
            let (source, destination, body) = decode(&output).unwrap();
            assert_eq!((source, destination), (local, peer));
            assert_eq!(body, payload);
            assert_eq!(endpoint.retained_requests(), 1);
            let (observer, _) = watch::channel(true);
            assert_eq!(
                receipt.wait(request(&observer)).await,
                Err(delivery::Error::WaitCancelled)
            );
            output.complete(Ok(())).unwrap();
            assert_eq!(
                endpoint.retained_requests(),
                1,
                "unjoined delivery still owns admission"
            );
            receipt.wait(request(&owner)).await.unwrap();
            assert_eq!(endpoint.retained_requests(), 0);
            assert_eq!(
                receipt.wait(request(&owner)).await,
                Err(delivery::Error::AlreadyJoined)
            );
            assert!(driver.inject(&packet).unwrap());
            drop(endpoint.requests.try_recv().unwrap());
            assert_eq!(endpoint.retained_requests(), 0);
            driver.cancel();
        }
    }
}

#[tokio::test(start_paused = true)]
async fn cancelled_or_dropped_observers_do_not_turn_enqueueing_into_delivery() {
    let (mut driver, mut endpoint, owner) = fixture(false, 1);
    let (local, peer) = addresses(false);
    driver.inject(&encode(peer, local, b"sample")).unwrap();
    let mut receipt = endpoint
        .requests
        .try_recv()
        .unwrap()
        .respond(b"reply", request(&owner))
        .unwrap();
    assert_eq!(
        receipt.wait(request(&owner)).await,
        Err(delivery::Error::WaitDeadline)
    );
    assert_eq!(endpoint.retained_requests(), 1);
    let packet = driver.take_reply().unwrap();
    packet.complete(Err(delivery::Failure::Deadline)).unwrap();
    assert_eq!(
        receipt.wait(request(&owner)).await,
        Err(delivery::Error::Delivery(delivery::Failure::Deadline))
    );
    assert_eq!(endpoint.retained_requests(), 0);
    driver.inject(&encode(peer, local, b"sample")).unwrap();
    let receipt = endpoint
        .requests
        .try_recv()
        .unwrap()
        .respond(b"reply", request(&owner))
        .unwrap();
    drop(receipt);
    assert_eq!(endpoint.retained_requests(), 1);
    assert_eq!(
        driver.take_reply().unwrap().complete(Ok(())),
        Err(delivery::Error::OwnerLost)
    );
    assert_eq!(endpoint.retained_requests(), 0);
    driver.cancel();
}

#[tokio::test]
async fn dropped_wait_future_retains_its_receipt_and_quiescence_allows_owned_output() {
    let (mut driver, mut endpoint, owner) = fixture(false, 1);
    let (local, peer) = addresses(false);
    driver.inject(&encode(peer, local, b"sample")).unwrap();
    let datagram = endpoint.requests.try_recv().unwrap();
    driver.quiesce();
    let mut receipt = datagram.respond(b"reply", request(&owner)).unwrap();
    let polled = {
        let mut wait = std::pin::pin!(receipt.wait(request(&owner)));
        poll_fn(|cx| Poll::Ready(wait.as_mut().poll(cx))).await
    };
    assert!(matches!(polled, Poll::Pending));
    assert_eq!(endpoint.retained_requests(), 1);
    driver.take_reply().unwrap().complete(Ok(())).unwrap();
    receipt.wait(request(&owner)).await.unwrap();
    assert_eq!(endpoint.retained_requests(), 0);
    assert_eq!(
        driver.inject(&encode(peer, local, b"sample")),
        Err(AdmissionError::Quiescing)
    );
    driver.cancel();
}

#[tokio::test]
async fn rejected_reply_and_shutdown_release_bounded_ownership_without_claiming_delivery() {
    let (mut driver, mut endpoint, owner) = fixture(false, 1);
    let (local, peer) = addresses(false);
    for case in 0..4 {
        driver.inject(&encode(peer, local, b"sample")).unwrap();
        let datagram = endpoint.requests.try_recv().unwrap();
        let mut context = request(&owner);
        let mut payload = Vec::new();
        let expected = match case {
            0 => {
                payload.resize(MAX_PAYLOAD + 1, 0);
                Error::TooLarge
            }
            1 => {
                context.deadline = Instant::now();
                Error::RequestExpired
            }
            2 => {
                context.deadline += Duration::from_secs(31);
                Error::InvalidConfig
            }
            _ => {
                owner.send_replace(true);
                Error::RequestCancelled
            }
        };
        assert!(matches!(datagram.respond(&payload,context),Err(error) if error==expected));
        assert_eq!(endpoint.retained_requests(), 0);
    }
    owner.send_replace(false);
    driver.inject(&encode(peer, local, b"sample")).unwrap();
    let mut receipt = endpoint
        .requests
        .try_recv()
        .unwrap()
        .respond(b"reply", request(&owner))
        .unwrap();
    driver.quiesce();
    assert_eq!(
        driver.inject(&encode(peer, local, b"sample")),
        Err(AdmissionError::Quiescing)
    );
    driver.cancel();
    assert_eq!(
        receipt.wait(request(&owner)).await,
        Err(delivery::Error::Delivery(delivery::Failure::Uncertain))
    );
    assert_eq!(endpoint.retained_requests(), 0);
}

#[test]
fn endpoint_configuration_and_packet_validation_fail_before_admission() {
    for endpoint in [
        "0.0.0.0:53",
        "127.0.0.1:53",
        "224.0.0.1:53",
        "255.255.255.255:53",
        "192.0.2.9:54",
        "[::]:53",
        "[::1]:53",
        "[ff02::1]:53",
    ] {
        assert_eq!(
            Config {
                endpoint: endpoint.parse().unwrap(),
                requests: 1
            }
            .required_buffer_capacity(),
            Err(Error::InvalidConfig),
            "{endpoint}"
        );
    }
    for requests in [0, 65] {
        assert_eq!(
            Config {
                endpoint: addresses(false).0,
                requests
            }
            .required_buffer_capacity(),
            Err(Error::InvalidConfig)
        );
    }
    for (flowinfo, scope) in [(1, 0), (0, 1)] {
        let address =
            std::net::SocketAddrV6::new("2001:db8::9".parse().unwrap(), 53, flowinfo, scope);
        assert_eq!(
            Config {
                endpoint: address.into(),
                requests: 1
            }
            .required_buffer_capacity(),
            Err(Error::InvalidConfig)
        );
    }
    let (mut driver, _endpoint, _owner) = fixture(false, 1);
    let (local, peer) = addresses(false);
    assert_eq!(
        driver.inject(&encode(peer, "192.0.2.8:53".parse().unwrap(), b"sample")),
        Ok(false)
    );
    assert_eq!(
        driver.inject(&encode(peer, "192.0.2.9:54".parse().unwrap(), b"sample")),
        Err(AdmissionError::UnselectedDestination)
    );
    let mut corrupt = encode(peer, local, b"sample");
    corrupt[8] ^= 1;
    assert_eq!(
        driver.inject(&corrupt),
        Err(AdmissionError::MalformedPacket)
    );
    let mut bad_udp = encode(peer, local, b"sample");
    *bad_udp.last_mut().unwrap() ^= 1;
    assert_eq!(
        driver.inject(&bad_udp),
        Err(AdmissionError::MalformedPacket)
    );
    assert_eq!(
        driver.inject(&encode(peer, local, &vec![0; MAX_PAYLOAD + 1])),
        Err(AdmissionError::PacketTooLarge)
    );
    assert_eq!(
        driver.inject(&encode("0.0.0.0:50000".parse().unwrap(), local, b"sample")),
        Err(AdmissionError::MalformedPacket)
    );
    let mut fragment = encode(peer, local, b"sample");
    let mut ip = Ipv4Packet::new_unchecked(&mut fragment);
    ip.set_more_frags(true);
    ip.fill_checksum();
    assert_eq!(
        driver.inject(&fragment),
        Err(AdmissionError::UnsupportedProtocol)
    );
    let mut zero_port = encode(peer, local, b"sample");
    zero_port[20..22].fill(0);
    zero_port[26..28].fill(0);
    assert_eq!(
        driver.inject(&zero_port),
        Err(AdmissionError::MalformedPacket)
    );
    let mut trailing = encode(peer, local, b"sample");
    trailing.push(0);
    assert_eq!(
        driver.inject(&trailing),
        Err(AdmissionError::MalformedPacket)
    );
    let mut wrong_length = encode(peer, local, b"sample");
    wrong_length[24..26].copy_from_slice(&8_u16.to_be_bytes());
    wrong_length[26..28].fill(0);
    assert_eq!(
        driver.inject(&wrong_length),
        Err(AdmissionError::MalformedPacket)
    );
    let (mut v6, _endpoint, _owner) = fixture(true, 1);
    let (local, peer) = addresses(true);
    let mut zero_checksum = encode(peer, local, b"sample");
    zero_checksum[46..48].fill(0);
    assert_eq!(
        v6.inject(&zero_checksum),
        Err(AdmissionError::MalformedPacket)
    );
    let mut bad_length = encode(peer, local, b"sample");
    bad_length[4..6].fill(0);
    assert_eq!(v6.inject(&bad_length), Err(AdmissionError::MalformedPacket));
    let mut extension = encode(peer, local, b"sample");
    extension[6] = 0;
    assert_eq!(
        v6.inject(&extension),
        Err(AdmissionError::UnsupportedProtocol)
    );
    assert_eq!(decode(&[0]), Err(AdmissionError::MalformedPacket));
}

#[test]
fn a_received_datagram_cannot_submit_output_after_its_runtime_owner_stops() {
    let (mut driver, mut endpoint, owner) = fixture(false, 1);
    let (local, peer) = addresses(false);
    driver.inject(&encode(peer, local, b"sample")).unwrap();
    let datagram = endpoint.requests.try_recv().unwrap();
    driver.cancel();
    assert!(matches!(
        datagram.respond(b"reply", request(&owner)),
        Err(Error::ConsumerClosed)
    ));
    assert_eq!(endpoint.retained_requests(), 0);
    assert!(!driver.has_replies());
}

#[tokio::test(start_paused = true)]
async fn runtime_dispatches_udp_locally_and_only_native_completion_finishes_the_receipt() {
    let policy = Arc::new(Policy::new(&[], 1).unwrap());
    let config = Config {
        endpoint: addresses(false).0,
        requests: 1,
    };
    let (runtime, mut channels) =
        Runtime::with_udp_dns(Limits::default(), policy, 2, Seed::fixture(), config).unwrap();
    assert_eq!(
        runtime.buffer_capacity(),
        Runtime::required_buffer_capacity(Limits::default(), 2).unwrap() + 2 * MTU
    );
    let mut dns = channels.udp_dns.take().unwrap();
    let host = tokio::spawn(runtime.run());
    let (owner, _) = watch::channel(false);
    channels
        .ingress
        .try_inject(&encode(addresses(false).1, config.endpoint, b"sample"))
        .unwrap();
    let datagram = dns.requests.recv().await.unwrap();
    let mut receipt = datagram.respond(b"reply", request(&owner)).unwrap();
    let packet = channels.packets.recv().await.unwrap();
    let mut observer = request(&owner);
    observer.deadline = Instant::now() + Duration::from_millis(10);
    assert_eq!(
        receipt.wait(observer).await,
        Err(delivery::Error::WaitDeadline)
    );
    assert_eq!(decode(&packet).unwrap().2, b"reply");
    packet.complete(Ok(())).unwrap();
    receipt.wait(request(&owner)).await.unwrap();
    assert!(channels.tcp.try_recv().is_err());
    assert_eq!(channels.publication.retained_flows(), 0);
    channels.shutdown.send(()).unwrap();
    let report = host.await.unwrap().unwrap();
    assert_eq!(report.udp_dns.received, 1);
    assert_eq!(report.udp_dns.queued_replies, 1);
    assert_eq!(dns.retained_requests(), 0);
    assert!(!channels.publication.is_published());
}

#[tokio::test]
async fn consumer_loss_is_a_joined_runtime_failure_and_reserved_tcp_never_uses_a_backend() {
    let config = Config {
        endpoint: addresses(false).0,
        requests: 1,
    };
    let policy = Arc::new(
        Policy::new(
            &[warper_core::routing::Entry {
                network: config.endpoint.ip(),
                prefix_len: 32,
                backend: warper_core::BackendId(7),
            }],
            1,
        )
        .unwrap(),
    );
    let (runtime, mut channels) =
        Runtime::with_udp_dns(Limits::default(), policy, 2, Seed::fixture(), config).unwrap();
    let dns = channels.udp_dns.take().unwrap();
    let host = tokio::spawn(runtime.run());
    let mut peer = crate::fixture::Peer::new(false, 50000);
    channels.ingress.try_inject(&peer.syn()).unwrap();
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(channels.tcp.try_recv().is_err());
    drop(dns);
    let failure = host.await.unwrap().unwrap_err();
    assert_eq!(failure.cause, RuntimeError::ConsumerClosed);
    assert_eq!(failure.report.udp_dns.rejected, 1);
    assert_eq!(failure.report.tcp.admitted, 0);
    assert!(!channels.publication.is_published());
}
