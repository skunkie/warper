// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use netlink_packet_core::{ErrorMessage, NetlinkHeader};
use std::num::NonZeroI32;
use tokio::{sync::watch, time::Instant as TokioInstant};

fn request() -> Vec<u8> {
    packet(
        add_message(9, Ipv4Addr::new(198, 18, 0, 1)),
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        7,
        42,
    )
    .unwrap()
}
fn ack(request: &[u8], code: i32) -> Vec<u8> {
    let mut error = ErrorMessage::default();
    error.code = NonZeroI32::new(code);
    error.header = request[..16].to_vec();
    let mut message = NetlinkMessage::<RouteNetlinkMessage>::new(
        NetlinkHeader::default(),
        NetlinkPayload::Error(error),
    );
    message.header.sequence_number = 7;
    message.header.port_number = 42;
    message.finalize();
    let mut bytes = vec![0; message.buffer_len()];
    message.serialize(&mut bytes);
    bytes
}
#[test]
fn only_correlated_kernel_acknowledgements_confirm_mutation() {
    let request = request();
    let bytes = ack(&request, 0);
    let kernel = SocketAddr::new(0, 0);
    assert_eq!(decode_ack(&bytes, kernel, 7, 42, &request), Ok(()));
    for end in 0..bytes.len() {
        assert_eq!(
            decode_ack(&bytes[..end], kernel, 7, 42, &request),
            Err(Cause::Protocol)
        );
    }
    for sender in [SocketAddr::new(1, 0), SocketAddr::new(0, 1)] {
        assert_eq!(
            decode_ack(&bytes, sender, 7, 42, &request),
            Err(Cause::Protocol)
        );
    }
    for (sequence, port) in [(8, 42), (7, 43)] {
        assert_eq!(
            decode_ack(&bytes, kernel, sequence, port, &request),
            Err(Cause::Protocol)
        );
    }
    for offset in [4, 8, 12] {
        let mut changed = request.clone();
        changed[offset] ^= 1;
        assert_eq!(
            decode_ack(&bytes, kernel, 7, 42, &changed),
            Err(Cause::Protocol)
        );
    }
    for code in [-17, -1, 1, i32::MIN] {
        assert_eq!(
            decode_ack(&ack(&request, code), kernel, 7, 42, &request),
            Err(if code < 0 && code != i32::MIN {
                Cause::Kernel(-code)
            } else {
                Cause::Protocol
            })
        );
    }
    let mut extra = bytes.clone();
    extra.extend_from_slice(&bytes);
    assert_eq!(
        decode_ack(&extra, kernel, 7, 42, &request),
        Err(Cause::Protocol)
    );
    assert_eq!(
        decode_ack(&vec![0; MAX_DATAGRAM + 1], kernel, 7, 42, &request),
        Err(Cause::Lost)
    );
}
#[test]
fn address_snapshot_requires_an_exact_owned_host_address() {
    let address = Ipv4Addr::new(198, 18, 0, 1);
    let RouteNetlinkMessage::NewAddress(message) = add_message(9, address) else {
        unreachable!()
    };
    let mut snapshot = Snapshot::default();
    observe(&mut snapshot, message.clone(), 9, address).unwrap();
    assert_eq!(
        snapshot,
        Snapshot {
            matches: 1,
            owned_exact: 1
        }
    );
    let mut foreign = Snapshot::default();
    observe(&mut foreign, message.clone(), 10, address).unwrap();
    assert_eq!(
        foreign,
        Snapshot {
            matches: 1,
            owned_exact: 0
        }
    );
    let mut prefixed = message.clone();
    prefixed.header.prefix_len = 24;
    let mut snapshot = Snapshot::default();
    observe(&mut snapshot, prefixed, 9, address).unwrap();
    assert_eq!(snapshot.owned_exact, 0);
    let mut duplicate = message.clone();
    duplicate
        .attributes
        .push(AddressAttribute::Local(IpAddr::V4(address)));
    assert_eq!(
        observe(&mut Snapshot::default(), duplicate, 9, address),
        Err(Cause::Protocol)
    );
    let mut unknown = message;
    unknown.header.index = 0;
    assert_eq!(
        observe(&mut Snapshot::default(), unknown, 9, address),
        Err(Cause::Protocol)
    );
}
#[test]
fn exclusive_requests_cannot_replace_an_address_or_publish_a_prefix_route() {
    let bytes = request();
    let message = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&bytes).unwrap();
    assert_eq!(
        message.header.flags,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
    );
    let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(address)) = message.payload
    else {
        unreachable!()
    };
    assert_eq!(address.header.prefix_len, 32);
    assert_eq!(address.header.index, 9);
    assert!(address.attributes.contains(&AddressAttribute::Flags(
        AddressFlags::Permanent | AddressFlags::Noprefixroute
    )));
}
#[test]
fn cancelled_expired_and_unbounded_waits_fail_before_native_io() {
    let (owner, cancellation) = watch::channel(false);
    assert!(matches!(
        Wait::new(Request {
            deadline: TokioInstant::now(),
            cancellation: owner.subscribe()
        }),
        Err(Cause::Timeout)
    ));
    owner.send(true).unwrap();
    assert!(matches!(
        Wait::new(Request {
            deadline: TokioInstant::now() + Duration::from_secs(1),
            cancellation
        }),
        Err(Cause::Cancelled)
    ));
    let (owner, cancellation) = watch::channel(false);
    drop(owner);
    assert!(matches!(
        Wait::new(Request {
            deadline: TokioInstant::now() + Duration::from_secs(1),
            cancellation
        }),
        Err(Cause::Cancelled)
    ));
    let (_owner, cancellation) = watch::channel(false);
    assert!(matches!(
        Wait::new(Request {
            deadline: TokioInstant::now() + Duration::from_secs(31),
            cancellation
        }),
        Err(Cause::InvalidInput)
    ));
}
#[test]
fn native_read_only_snapshot_observes_loopback_without_external_traffic() {
    let (_owner, cancellation) = watch::channel(false);
    let wait = Wait::new(Request {
        deadline: TokioInstant::now() + Duration::from_secs(2),
        cancellation,
    })
    .unwrap();
    let loopback = nix::net::if_::if_nametoindex("lo").unwrap();
    let snapshot = inspect(loopback, Ipv4Addr::LOCALHOST, &wait).unwrap();
    assert!(snapshot.matches >= 1);
    assert_eq!(snapshot.owned_exact, 0);
}

#[test]
fn interrupted_malformed_and_over_budget_dumps_never_establish_ownership() {
    let address = Ipv4Addr::new(198, 18, 0, 1);
    let dump = || Dump {
        sequence: 7,
        port: 42,
        index: 9,
        address,
        snapshot: Snapshot::default(),
        messages: 0,
    };
    let serialize = |mut message: NetlinkMessage<RouteNetlinkMessage>| {
        message.header.sequence_number = 7;
        message.header.port_number = 42;
        message.finalize();
        let mut bytes = vec![0; message.buffer_len()];
        message.serialize(&mut bytes);
        bytes
    };
    let sample = serialize(NetlinkMessage::from(add_message(9, address)));
    let kernel = SocketAddr::new(0, 0);
    let mut state = dump();
    assert_eq!(state.observe(&sample, kernel), Ok(false));
    assert_eq!(state.snapshot.owned_exact, 1);
    let done = serialize(NetlinkMessage::new(
        NetlinkHeader::default(),
        NetlinkPayload::Done(netlink_packet_core::DoneMessage::default()),
    ));
    assert_eq!(state.observe(&done, kernel), Ok(true));
    for end in 0..sample.len() {
        assert_eq!(dump().observe(&sample[..end], kernel), Err(Cause::Protocol));
    }
    let mut interrupted = sample.clone();
    interrupted[6..8].copy_from_slice(&NLM_F_DUMP_INTR.to_ne_bytes());
    assert_eq!(dump().observe(&interrupted, kernel), Err(Cause::Lost));
    let mut wrong_sequence = sample.clone();
    wrong_sequence[8..12].copy_from_slice(&8u32.to_ne_bytes());
    assert_eq!(
        dump().observe(&wrong_sequence, kernel),
        Err(Cause::Protocol)
    );
    assert_eq!(
        dump().observe(&sample, SocketAddr::new(1, 0)),
        Err(Cause::Protocol)
    );
    assert_eq!(
        dump().observe(&vec![0; MAX_DATAGRAM + 1], kernel),
        Err(Cause::Lost)
    );
    let mut too_many = dump();
    too_many.messages = MAX_MESSAGES;
    assert_eq!(too_many.observe(&sample, kernel), Err(Cause::ResourceLimit));
    let mut trailing = done;
    trailing.extend_from_slice(&sample);
    assert_eq!(dump().observe(&trailing, kernel), Err(Cause::Protocol));
}
