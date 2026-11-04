// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use warper_core::{dns::Name, routing::Entry};

fn limits() -> lease::Limits {
    lease::Limits {
        lease_entries: 8,
        route_entries: 8,
        response_entries: 4,
        flow_entries: 4,
        addresses_per_response: 4,
        bytes: 128 * 1024,
    }
}
fn address() -> IpAddr {
    "192.0.2.9".parse().unwrap()
}
fn key(backend: u64) -> QuestionKey {
    QuestionKey {
        backend: BackendId(backend),
        name: Name::from_ascii("sample.example.test").unwrap(),
        record_type: 1,
        class: 1,
    }
}
fn create(entries: &[Entry]) -> Controller {
    Controller::new(
        Arc::new(Policy::new(entries, 8).unwrap()),
        limits(),
        Instant::now(),
    )
    .unwrap()
}
fn contribution(controller: &Controller) -> Contribution {
    Contribution {
        address: address(),
        expires_at: controller.elapsed(Instant::now() + Duration::from_secs(1)),
    }
}
fn reserve(controller: &Controller, backend: u64) -> (Response, Route) {
    let response = controller
        .reserve(
            RoutingMode::Mixed,
            key(backend),
            &[contribution(controller)],
            Instant::now() + Duration::from_secs(100),
        )
        .unwrap();
    let route = controller.response_route(&response, 0).unwrap();
    (response, route)
}
fn static_entry(backend: u64) -> Entry {
    Entry {
        network: "192.0.2.0".parse().unwrap(),
        prefix_len: 24,
        backend: BackendId(backend),
    }
}

#[tokio::test(start_paused = true)]
async fn selection_pins_shared_address_until_flow_drop_and_verified_retirement() {
    let controller = create(&[]);
    let selector = controller.selector();
    let (mut response, route) = reserve(&controller, 7);
    assert_eq!(selector.lookup(address()).unwrap(), BackendId(7));
    assert!(matches!(
        selector.select_flow(address()),
        Err(SelectionError::Unready)
    ));
    controller.confirm_publication(route).unwrap();
    controller.handoff(&mut response, Duration::ZERO).unwrap();
    let selection = selector.select_flow(address()).unwrap();
    assert_eq!(selection.backend(), BackendId(7));
    assert_eq!(controller.stats().unwrap().flows, 1);
    tokio::time::advance(Duration::from_secs(2)).await;
    controller.advance().unwrap();
    assert_eq!(controller.stats().unwrap().leases, 0);
    assert_eq!(
        controller.begin_retirement(route),
        Err(Error::Ledger(lease::Error::Referenced))
    );
    drop(selection);
    controller.advance().unwrap();
    assert_eq!(controller.retirement_candidate().unwrap(), Some(route));
    controller.begin_retirement(route).unwrap();
    assert_eq!(
        selector.lookup(address()).unwrap(),
        BackendId(7),
        "mapping persists until actual native withdrawal"
    );
    assert!(matches!(
        selector.select_flow(address()),
        Err(SelectionError::Unready)
    ));
    controller.finish_retirement(route).unwrap();
    assert_eq!(selector.lookup(address()), Err(SelectionError::Unselected));
}

#[tokio::test(start_paused = true)]
async fn static_conflicts_and_missing_coverage_fail_before_metadata_mutation() {
    let controller = create(&[static_entry(2)]);
    let before = controller.stats().unwrap();
    let contribution = contribution(&controller);
    assert!(matches!(
        controller.reserve(
            RoutingMode::Mixed,
            key(7),
            &[contribution],
            Instant::now() + Duration::from_secs(10)
        ),
        Err(Error::StaticConflict)
    ));
    let missing = Contribution {
        address: "198.51.100.1".parse().unwrap(),
        ..contribution
    };
    assert!(matches!(
        controller.reserve(
            RoutingMode::Static,
            key(2),
            &[missing],
            Instant::now() + Duration::from_secs(10)
        ),
        Err(Error::MissingStaticCoverage)
    ));
    assert!(matches!(
        controller.reserve(
            RoutingMode::Mixed,
            key(7),
            &[missing, contribution],
            Instant::now() + Duration::from_secs(10)
        ),
        Err(Error::StaticConflict)
    ));
    assert_eq!(controller.stats().unwrap(), before);
    assert_eq!(
        controller.selector().lookup(address()).unwrap(),
        BackendId(2)
    );
}

#[tokio::test(start_paused = true)]
async fn static_capture_remains_selected_after_dns_lease_expiry_without_a_new_dns_pin() {
    let controller = create(&[static_entry(7)]);
    let selector = controller.selector();
    let (mut response, route) = reserve(&controller, 7);
    controller.confirm_publication(route).unwrap();
    controller.handoff(&mut response, Duration::ZERO).unwrap();
    tokio::time::advance(Duration::from_secs(2)).await;
    let selection = selector.select_flow(address()).unwrap();
    assert_eq!(selection.backend(), BackendId(7));
    assert_eq!(controller.stats().unwrap().leases, 0);
    assert_eq!(controller.stats().unwrap().flows, 0);
    assert_eq!(selector.static_policy().entries(), &[static_entry(7)]);
    controller.begin_retirement(route).unwrap();
    assert!(matches!(
        selector.select_flow(address()),
        Err(SelectionError::Unready)
    ));
    controller.finish_retirement(route).unwrap();
    assert_eq!(
        selector.select_flow(address()).unwrap().backend(),
        BackendId(7)
    );
}

#[tokio::test]
async fn lock_contention_and_poison_never_fall_back_to_static_routes() {
    let controller = create(&[static_entry(7)]);
    let selector = controller.selector();
    {
        let _guard = controller.routes.owner.lock().unwrap();
        assert_eq!(selector.lookup(address()), Err(SelectionError::Busy));
        assert!(matches!(
            selector.select_flow(address()),
            Err(SelectionError::Busy)
        ));
        assert_eq!(controller.stats(), Err(Error::Busy));
        assert_eq!(
            selector.verify_retirement(address(), BackendId(7)),
            Err(SelectionError::Busy)
        );
    }
    let routes = controller.routes.clone();
    let poisoned = std::thread::spawn(move || {
        let _guard = routes.owner.lock().unwrap();
        panic!("synthetic owner failure");
    });
    assert!(poisoned.join().is_err());
    assert_eq!(selector.lookup(address()), Err(SelectionError::Unavailable));
    assert!(matches!(
        selector.select_flow(address()),
        Err(SelectionError::Unavailable)
    ));
    assert_eq!(controller.stats(), Err(Error::Unavailable));
    assert_eq!(
        selector.verify_retirement(address(), BackendId(7)),
        Err(SelectionError::Unavailable)
    );
}

#[tokio::test(start_paused = true)]
async fn retirement_proof_requires_matching_unreferenced_retiring_ownership() {
    let controller = create(&[]);
    let selector = controller.selector();
    assert_eq!(
        selector.verify_retirement(address(), BackendId(7)),
        Err(SelectionError::Unready)
    );
    let (mut response, route) = reserve(&controller, 7);
    assert_eq!(
        selector.verify_retirement(address(), BackendId(7)),
        Err(SelectionError::Unready)
    );
    controller.confirm_publication(route).unwrap();
    let pin = selector.select_flow(address()).unwrap();
    controller.cancel(&mut response).unwrap();
    assert_eq!(
        controller.begin_retirement(route),
        Err(Error::Ledger(lease::Error::Referenced))
    );
    assert_eq!(
        selector.verify_retirement(address(), BackendId(7)),
        Err(SelectionError::Unready)
    );
    drop(pin);
    controller.begin_retirement(route).unwrap();
    assert_eq!(
        selector.verify_retirement(address(), BackendId(8)),
        Err(SelectionError::Unready)
    );
    assert_eq!(selector.verify_retirement(address(), BackendId(7)), Ok(()));
    assert_eq!(selector.lookup(address()).unwrap(), BackendId(7));
    controller.close().unwrap();
    assert_eq!(selector.verify_retirement(address(), BackendId(7)), Ok(()));
    controller.finish_retirement(route).unwrap();
    assert_eq!(
        selector.verify_retirement(address(), BackendId(7)),
        Err(SelectionError::Unready)
    );
}

#[cfg(target_os = "linux")]
#[tokio::test(start_paused = true)]
async fn retirement_proof_uses_the_published_selector_through_admission_quiescence() {
    use warper_stack::{Seed, host::Limits, runtime::Runtime};
    let controller = create(&[]);
    let (mut response, route) = reserve(&controller, 7);
    controller.cancel(&mut response).unwrap();
    controller.begin_retirement(route).unwrap();
    let (runtime, channels) = Runtime::with_selector(
        Limits::default(),
        controller.selector(),
        1,
        Seed::generate().unwrap(),
    )
    .unwrap();
    let (static_runtime, static_channels) = Runtime::new(
        Limits::default(),
        Arc::new(Policy::new(&[static_entry(7)], 1).unwrap()),
        1,
        Seed::generate().unwrap(),
    )
    .unwrap();
    assert_eq!(
        static_channels
            .publication
            .verify_retirement(address(), BackendId(7)),
        Err(SelectionError::Unready)
    );
    drop(static_runtime);
    let task = tokio::spawn(runtime.run());
    let (owner, cancellation) = tokio::sync::watch::channel(false);
    let mut receipt = channels.admission.quiesce().unwrap();
    receipt
        .wait(warper_core::transport::Request {
            deadline: Instant::now() + Duration::from_secs(1),
            cancellation,
        })
        .await
        .unwrap();
    assert!(channels.publication.is_quiescent());
    assert_eq!(
        channels
            .publication
            .verify_retirement(address(), BackendId(7)),
        Ok(())
    );
    channels.shutdown.send(()).unwrap();
    task.await.unwrap().unwrap();
    assert_eq!(
        channels
            .publication
            .verify_retirement(address(), BackendId(7)),
        Err(SelectionError::Unavailable)
    );
    drop(owner);
    controller.finish_retirement(route).unwrap();
}

#[tokio::test(start_paused = true)]
async fn owned_drop_notifications_do_not_hold_the_ledger_mutex_across_waits() {
    let controller = create(&[]);
    let mut changes = controller.changes().unwrap();
    assert!(matches!(
        controller.changes(),
        Err(Error::Ledger(lease::Error::ResourceLimit))
    ));
    let (response, _) = reserve(&controller, 7);
    drop(response);
    tokio::time::timeout(Duration::from_secs(1), changes.wait())
        .await
        .unwrap();
    controller.advance().unwrap();
    assert_eq!(controller.stats().unwrap().leases, 0);
    drop(changes);
    let _replacement = controller.changes().unwrap();
}

#[tokio::test(start_paused = true)]
async fn uncertainty_and_shutdown_preserve_existing_selection_but_close_admission() {
    let controller = create(&[]);
    let (mut response, route) = reserve(&controller, 7);
    controller.confirm_publication(route).unwrap();
    let selector = controller.selector();
    let selection = selector.select_flow(address()).unwrap();
    controller.mark_uncertain(route).unwrap();
    assert!(matches!(
        selector.select_flow(address()),
        Err(SelectionError::Unready)
    ));
    assert_eq!(selection.backend(), BackendId(7));
    controller.confirm_publication(route).unwrap();
    controller
        .handoff(&mut response, Duration::from_secs(30))
        .unwrap();
    controller.close().unwrap();
    assert!(matches!(
        selector.select_flow(address()),
        Err(SelectionError::Unready)
    ));
    assert_eq!(
        controller.finish_drain(),
        Err(Error::Ledger(lease::Error::Referenced))
    );
    drop(selection);
    controller.finish_drain().unwrap();
    controller.begin_retirement(route).unwrap();
    controller.restore_committed(route).unwrap();
    controller.begin_retirement(route).unwrap();
    controller.finish_retirement(route).unwrap();
    assert_eq!(controller.stats().unwrap().routes, 0);
}

#[cfg(target_os = "linux")]
#[tokio::test(start_paused = true)]
async fn runtime_publication_observes_the_same_live_selector_without_creating_pins() {
    let controller = create(&[]);
    let (response, route) = reserve(&controller, 7);
    let (runtime, channels) = warper_stack::runtime::Runtime::with_selector(
        warper_stack::host::Limits::default(),
        controller.selector(),
        2,
        warper_stack::Seed::generate().unwrap(),
    )
    .unwrap();
    assert_eq!(
        channels.publication.selected_backend(address()).unwrap(),
        BackendId(7)
    );
    assert!(channels.publication.entries().is_empty());
    assert_eq!(controller.route_info(route).unwrap().flows, 0);
    drop(runtime);
    assert_eq!(
        channels.publication.selected_backend(address()),
        Err(SelectionError::Unavailable)
    );
    drop(response);
}

#[tokio::test(start_paused = true)]
async fn controller_storage_and_clock_validation_preserve_global_byte_admission() {
    let controller = create(&[]);
    assert!(controller.reserved_bytes().unwrap() <= limits().bytes);
    assert!(controller.reserved_bytes().unwrap() > controller.stats().unwrap().reserved_bytes);
    assert_eq!(
        controller.elapsed(Instant::now() - Duration::from_secs(1)),
        Duration::ZERO
    );
    assert_eq!(controller.next_expiry().unwrap(), None);
    let (mut response, route) = reserve(&controller, 7);
    controller.confirm_publication(route).unwrap();
    controller.handoff(&mut response, Duration::ZERO).unwrap();
    assert_eq!(
        controller.next_expiry().unwrap(),
        Some(Instant::now() + Duration::from_secs(1))
    );
    assert!(matches!(
        Controller::new(
            Arc::new(Policy::new(&[], 1).unwrap()),
            limits(),
            Instant::now() + Duration::from_secs(1)
        ),
        Err(Error::InvalidClock)
    ));
    assert!(matches!(
        Controller::new(
            Arc::new(Policy::new(&[], 1).unwrap()),
            lease::Limits {
                bytes: 1,
                ..limits()
            },
            Instant::now()
        ),
        Err(Error::Ledger(lease::Error::ResourceLimit))
    ));
}

#[tokio::test(start_paused = true)]
async fn duplicate_reservations_cancel_cleanly_and_flow_budget_failure_does_not_bypass_dns_pins() {
    let controller = Controller::new(
        Arc::new(Policy::new(&[static_entry(7)], 1).unwrap()),
        lease::Limits {
            flow_entries: 0,
            ..limits()
        },
        Instant::now(),
    )
    .unwrap();
    let sample = contribution(&controller);
    let mut response = controller
        .reserve(
            RoutingMode::Static,
            key(7),
            &[sample, sample],
            Instant::now() + Duration::from_secs(100),
        )
        .unwrap();
    assert_eq!(controller.response_len(&response).unwrap(), 1);
    let route = controller.response_route(&response, 0).unwrap();
    controller.confirm_publication(route).unwrap();
    assert!(
        matches!(
            controller.selector().select_flow(address()),
            Err(SelectionError::Busy)
        ),
        "static coverage must not bypass exhausted DNS ownership admission"
    );
    controller.cancel(&mut response).unwrap();
    assert_eq!(controller.stats().unwrap().leases, 0);
    assert_eq!(controller.stats().unwrap().responses, 0);
    assert!(matches!(
        controller.reserve(RoutingMode::Static, key(7), &[], Instant::now()),
        Err(Error::Ledger(lease::Error::ResourceLimit))
    ));
    let large = (1..=5)
        .map(|last| Contribution {
            address: IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, last)),
            ..sample
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        controller.reserve(
            RoutingMode::Static,
            key(7),
            &large,
            Instant::now() + Duration::from_secs(1)
        ),
        Err(Error::Ledger(lease::Error::ResourceLimit))
    ));
    assert_eq!(controller.stats().unwrap().leases, 0);
}
