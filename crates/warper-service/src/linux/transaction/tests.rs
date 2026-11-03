// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use netlink_packet_core::{DoneMessage, ErrorMessage, NLM_F_MULTIPART, NetlinkHeader};
use netlink_packet_route::route::RouteMessage;
use std::num::NonZeroI32;

fn packet(payload: NetlinkPayload<RouteNetlinkMessage>) -> Vec<u8> {
    let mut message = NetlinkMessage::new(NetlinkHeader::default(), payload);
    message.header.sequence_number = 7;
    message.header.port_number = 42;
    message.header.flags = NLM_F_MULTIPART;
    message.finalize();
    let mut bytes = vec![0; message.buffer_len()];
    message.serialize(&mut bytes);
    bytes
}
fn sample() -> Vec<u8> {
    packet(NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(
        RouteMessage::default(),
    )))
}
fn done() -> Vec<u8> {
    packet(NetlinkPayload::Done(DoneMessage::default()))
}
fn parse(bytes: &[u8]) -> Result<bool, Cause> {
    Dump::new(7, 42, 4).observe(bytes, SocketAddr::new(0, 0), |_| Ok(()))
}

#[test]
fn completion_requires_the_whole_correlated_kernel_dump() {
    let mut dump = Dump::new(7, 42, 3);
    let mut observed = 0;
    let mut bytes = sample();
    bytes.extend_from_slice(&sample());
    assert_eq!(
        dump.observe(&bytes, SocketAddr::new(0, 0), |_| {
            observed += 1;
            Ok(())
        }),
        Ok(false)
    );
    assert_eq!(observed, 2);
    assert_eq!(
        dump.observe(&done(), SocketAddr::new(0, 0), |_| Ok(())),
        Ok(true)
    );
    assert_eq!(
        dump.observe(&done(), SocketAddr::new(0, 0), |_| Ok(())),
        Err(Cause::Protocol)
    );
    let mut bytes = done();
    bytes.extend_from_slice(&sample());
    assert_eq!(parse(&bytes), Err(Cause::Protocol));
    assert_eq!(
        Dump::new(7, 42, 1).observe(&sample(), SocketAddr::new(0, 0), |_| Err(
            Cause::ResourceLimit
        )),
        Err(Cause::ResourceLimit)
    );
    let mut dump = Dump::new(7, 42, 1);
    assert_eq!(
        dump.observe(&sample(), SocketAddr::new(0, 0), |_| Ok(())),
        Ok(false)
    );
    assert_eq!(
        dump.observe(&done(), SocketAddr::new(0, 0), |_| Ok(())),
        Err(Cause::ResourceLimit)
    );
}

#[test]
fn malformed_interrupted_and_uncorrelated_dumps_never_complete() {
    let bytes = sample();
    for end in 0..bytes.len() {
        assert_eq!(
            parse(&bytes[..end]),
            Err(Cause::Protocol),
            "truncated length {end}"
        );
    }
    assert_eq!(parse(&vec![0; MAX_DATAGRAM + 1]), Err(Cause::Lost));
    for sender in [SocketAddr::new(1, 0), SocketAddr::new(0, 1)] {
        assert_eq!(
            Dump::new(7, 42, 4).observe(&bytes, sender, |_| Ok(())),
            Err(Cause::Protocol)
        );
    }
    for offset in [8, 12] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert_eq!(parse(&changed), Err(Cause::Protocol));
    }
    for flags in [0, NLM_F_DUMP_INTR | NLM_F_MULTIPART] {
        let mut changed = bytes.clone();
        changed[6..8].copy_from_slice(&flags.to_ne_bytes());
        assert_eq!(
            parse(&changed),
            Err(if flags == 0 {
                Cause::Protocol
            } else {
                Cause::Lost
            })
        );
    }
    let mut unaligned = bytes.clone();
    unaligned.push(0);
    assert_eq!(parse(&unaligned), Err(Cause::Protocol));
    assert_eq!(
        parse(&packet(NetlinkPayload::Overrun(vec![]))),
        Err(Cause::Lost)
    );
    assert_eq!(parse(&packet(NetlinkPayload::Noop)), Err(Cause::Protocol));
}

#[test]
fn terminal_kernel_failures_and_ack_cannot_be_dump_success() {
    for code in [-17, i32::MIN, 1, 0] {
        let mut error = ErrorMessage::default();
        error.code = NonZeroI32::new(code);
        assert_eq!(
            parse(&packet(NetlinkPayload::Error(error))),
            Err(if code < 0 && code != i32::MIN {
                Cause::Kernel(-code)
            } else {
                Cause::Protocol
            })
        );
        let mut done = DoneMessage::default();
        done.code = code;
        assert_eq!(
            parse(&packet(NetlinkPayload::Done(done))),
            if code == 0 {
                Ok(true)
            } else {
                Err(if code < 0 && code != i32::MIN {
                    Cause::Kernel(-code)
                } else {
                    Cause::Protocol
                })
            }
        );
    }
    let mut bytes = done();
    bytes[6..8].copy_from_slice(&0u16.to_ne_bytes());
    assert_eq!(parse(&bytes), Err(Cause::Protocol));
}
