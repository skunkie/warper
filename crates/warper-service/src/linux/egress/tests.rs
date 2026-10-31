// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use std::{
    future::pending,
    net::Ipv4Addr,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio::{sync::watch, time::Instant};

#[test]
fn supported_paths_exclude_capture_and_unknown_underlays() {
    let endpoint = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 1080);
    let route = route_lookup::Observation {
        interface: NonZeroU32::new(9).unwrap(),
        source: Ipv4Addr::new(192, 0, 2, 1),
        gateway: None,
        table: NonZeroU32::new(254).unwrap(),
        kind: route_lookup::Kind::Unicast,
    };
    let mut link = link_lookup::Observation {
        index: route.interface,
        name: "fixture-egress".into(),
        alias: None,
        kind: link_lookup::Kind::Ethernet,
        layer_type: 1,
        mtu: NonZeroU32::new(1500).unwrap(),
        flags: 1,
    };
    let excluded = NonZeroU32::new(10).unwrap();
    for (kind, expected) in [
        (link_lookup::Kind::Ethernet, true),
        (link_lookup::Kind::Veth, true),
        (link_lookup::Kind::Tun, false),
        (link_lookup::Kind::Loopback, false),
        (link_lookup::Kind::Other, false),
    ] {
        link.kind = kind;
        assert_eq!(
            supported(endpoint, route, &link, excluded),
            expected,
            "{kind:?}"
        );
    }
    link.kind = link_lookup::Kind::Ethernet;
    assert!(!supported(endpoint, route, &link, link.index));
    link.flags = 0;
    assert!(!supported(endpoint, route, &link, excluded));
    link.flags = 1;
    link.index = excluded;
    assert!(!supported(
        endpoint,
        route,
        &link,
        NonZeroU32::new(11).unwrap()
    ));
    link.index = route.interface;
    link.kind = link_lookup::Kind::Loopback;
    let local = route_lookup::Observation {
        source: Ipv4Addr::LOCALHOST,
        kind: route_lookup::Kind::Local,
        ..route
    };
    assert!(supported(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1080),
        local,
        &link,
        excluded
    ));
    assert!(!supported(endpoint, local, &link, excluded));
    let gateway_local = route_lookup::Observation {
        gateway: Some(Ipv4Addr::new(192, 0, 2, 1)),
        ..local
    };
    assert!(!supported(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1080),
        gateway_local,
        &link,
        excluded
    ));
}

struct Counter(AtomicUsize);
impl Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
#[test]
fn monitor_wakes_both_directions_and_replaces_only_the_current_reader() {
    let slots = Arc::new(Wakes::default());
    let read = Arc::new(Counter(AtomicUsize::new(0)));
    let write = Arc::new(Counter(AtomicUsize::new(0)));
    let replacement = Arc::new(Counter(AtomicUsize::new(0)));
    slots.register(&Waker::from(read.clone()), 0).unwrap();
    slots.register(&Waker::from(write.clone()), 1).unwrap();
    slots.wake_by_ref();
    assert_eq!(read.0.load(Ordering::Relaxed), 1);
    assert_eq!(write.0.load(Ordering::Relaxed), 1);
    slots
        .register(&Waker::from(replacement.clone()), 0)
        .unwrap();
    slots.wake_by_ref();
    assert_eq!(read.0.load(Ordering::Relaxed), 1);
    assert_eq!(replacement.0.load(Ordering::Relaxed), 1);
    assert_eq!(write.0.load(Ordering::Relaxed), 2);
}
#[test]
fn a_poisoned_waker_table_rejects_io_and_wakes_remaining_owners() {
    let slots = Arc::new(Wakes::default());
    let read = Arc::new(Counter(AtomicUsize::new(0)));
    slots.register(&Waker::from(read.clone()), 0).unwrap();
    let worker = slots.clone();
    let joined = std::thread::spawn(move || {
        let _guard = worker.0.lock().unwrap();
        panic!("synthetic waker table failure");
    })
    .join();
    assert!(joined.is_err());
    assert_eq!(slots.register(&Waker::from(read.clone()), 1), Err(()));
    slots.wake_by_ref();
    assert_eq!(read.0.load(Ordering::Relaxed), 1);
}
#[tokio::test(start_paused = true)]
async fn setup_deadline_and_owner_loss_end_owned_operations() {
    let (owner, cancellation) = watch::channel(false);
    assert_eq!(
        bounded(
            Request {
                deadline: Instant::now() + Duration::from_secs(1),
                cancellation
            },
            pending::<Result<(), Error>>()
        )
        .await,
        Err(Error::Deadline)
    );
    let cancellation = owner.subscribe();
    drop(owner);
    assert_eq!(
        bounded(
            Request {
                deadline: Instant::now() + Duration::from_secs(1),
                cancellation
            },
            pending::<Result<(), Error>>()
        )
        .await,
        Err(Error::Cancelled)
    );
}
#[test]
fn portable_setup_errors_keep_failure_categories_without_native_details() {
    for (error, expected) in [
        (Error::InvalidInput, transport::Error::InvalidDestination),
        (Error::ResourceLimit, transport::Error::ResourceLimit),
        (
            Error::Query(QueryError::ResourceLimit),
            transport::Error::ResourceLimit,
        ),
        (
            Error::Query(QueryError::Cancelled),
            transport::Error::Cancelled,
        ),
        (Error::Query(QueryError::Timeout), transport::Error::Timeout),
        (
            Error::UnsupportedPath,
            transport::Error::UnsupportedIntegration,
        ),
        (
            Error::PathMismatch,
            transport::Error::Io(io::ErrorKind::NetworkUnreachable),
        ),
        (
            Error::Io(io::ErrorKind::ConnectionRefused),
            transport::Error::Io(io::ErrorKind::ConnectionRefused),
        ),
    ] {
        assert_eq!(transport_error(error), expected);
    }
}
