// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;

fn seconds(value: u64) -> Duration {
    Duration::from_secs(value)
}
fn limits() -> Limits {
    Limits {
        lease_entries: 8,
        route_entries: 8,
        response_entries: 4,
        flow_entries: 4,
        addresses_per_response: 4,
        bytes: 128 * 1024,
    }
}
fn question(label: &str, backend: u64) -> QuestionKey {
    QuestionKey {
        backend: BackendId(backend),
        name: Name::from_ascii(&format!("{label}.example.test")).unwrap(),
        record_type: 1,
        class: 1,
    }
}
fn endpoint(last: u8, expires: u64) -> Contribution {
    Contribution {
        address: IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, last)),
        expires_at: seconds(expires),
    }
}
fn reserve(ledger: &mut Ledger, question: QuestionKey, endpoints: &[Contribution]) -> Response {
    ledger
        .reserve(Duration::ZERO, question, endpoints, seconds(100))
        .unwrap()
}
fn publish(ledger: &mut Ledger, response: &Response) -> Vec<Route> {
    let routes = (0..ledger.response_len(response).unwrap())
        .map(|index| ledger.response_route(response, index).unwrap())
        .collect::<Vec<_>>();
    for route in &routes {
        ledger.confirm_publication(*route).unwrap();
    }
    routes
}

#[test]
fn pending_output_survives_ttl_expiry_and_handoff_anchors_grace_without_caching() {
    let mut ledger = Ledger::new(limits()).unwrap();
    let key = question("sample", 1);
    let mut response = reserve(&mut ledger, key, &[endpoint(1, 0)]);
    let route = ledger.response_route(&response, 0).unwrap();
    assert_eq!(
        ledger.handoff(seconds(1), &mut response, seconds(30)),
        Err(Error::NotCommitted)
    );
    ledger.advance(seconds(20)).unwrap();
    assert_eq!(
        ledger.stats().leases,
        1,
        "queued and partially written output retains its original reservation"
    );
    assert_eq!(ledger.retention(key, endpoint(1, 0).address), None);
    assert_eq!(
        ledger.begin_retirement(seconds(20), route),
        Err(Error::Referenced)
    );
    ledger.confirm_publication(route).unwrap();
    ledger
        .handoff(seconds(20), &mut response, seconds(30))
        .unwrap();
    assert_eq!(
        ledger.retention(key, endpoint(1, 0).address),
        Some(seconds(50))
    );
    let flow = ledger.acquire_flow(seconds(21), route).unwrap();
    ledger.advance(seconds(51)).unwrap();
    assert_eq!(
        ledger.stats().leases,
        0,
        "expired name metadata does not need to survive its flow"
    );
    assert_eq!(ledger.route_info(route).unwrap().flows, 1);
    assert_eq!(
        ledger.begin_retirement(seconds(51), route),
        Err(Error::Referenced)
    );
    drop(flow);
    ledger.advance(seconds(52)).unwrap();
    assert_eq!(ledger.retirement_candidate(), Some(route));
    ledger.begin_retirement(seconds(52), route).unwrap();
    ledger.finish_retirement(route).unwrap();
    assert!(ledger.route_for(endpoint(1, 0).address).is_none());
}

#[test]
fn all_routes_must_commit_before_atomic_handoff_and_each_ip_keeps_its_own_expiry() {
    let mut ledger = Ledger::new(limits()).unwrap();
    let key = question("sample", 1);
    let mut response = reserve(
        &mut ledger,
        key,
        &[endpoint(1, 10), endpoint(2, 100), endpoint(1, 20)],
    );
    assert_eq!(ledger.response_len(&response).unwrap(), 2);
    let first = ledger.response_route(&response, 0).unwrap();
    let second = ledger.response_route(&response, 1).unwrap();
    ledger.confirm_publication(first).unwrap();
    assert_eq!(
        ledger.handoff(seconds(5), &mut response, seconds(30)),
        Err(Error::NotCommitted)
    );
    assert_eq!(ledger.retention(key, endpoint(1, 0).address), None);
    assert_eq!(ledger.retention(key, endpoint(2, 0).address), None);
    assert_eq!(ledger.stats().responses, 1);
    ledger.confirm_publication(second).unwrap();
    ledger
        .handoff(seconds(5), &mut response, seconds(30))
        .unwrap();
    assert_eq!(
        ledger.retention(key, endpoint(1, 0).address),
        Some(seconds(35))
    );
    assert_eq!(
        ledger.retention(key, endpoint(2, 0).address),
        Some(seconds(100))
    );
    assert_eq!(ledger.cancel(&mut response), Err(Error::InvalidHandle));
    assert_eq!(
        ledger.response_route(&response, 0),
        Err(Error::InvalidHandle)
    );
    ledger.advance(seconds(35)).unwrap();
    assert_eq!(ledger.stats().leases, 1);
    assert_eq!(ledger.begin_retirement(seconds(35), first), Ok(()));
    assert_eq!(
        ledger.begin_retirement(seconds(35), second),
        Err(Error::Referenced)
    );
}

#[test]
fn duplicate_paths_use_greatest_justified_retention_and_renewal_never_shortens_it() {
    let mut ledger = Ledger::new(limits()).unwrap();
    let key = question("sample", 1);
    let mut initial = reserve(&mut ledger, key, &[endpoint(1, 5), endpoint(1, 90)]);
    let route = publish(&mut ledger, &initial)[0];
    ledger
        .handoff(Duration::ZERO, &mut initial, seconds(1))
        .unwrap();
    let baseline = ledger.stats();
    let mut first = reserve(&mut ledger, key, &[endpoint(1, 1000)]);
    let mut second = reserve(&mut ledger, key, &[endpoint(1, 20)]);
    assert_eq!(ledger.stats().leases, 1);
    assert_eq!(ledger.stats().routes, 1);
    ledger.cancel(&mut first).unwrap();
    ledger
        .handoff(seconds(1), &mut second, seconds(30))
        .unwrap();
    assert_eq!(
        ledger.retention(key, endpoint(1, 0).address),
        Some(seconds(90))
    );
    for _ in 0..1000 {
        let mut response = ledger
            .reserve(seconds(1), key, &[endpoint(1, 200)], seconds(100))
            .unwrap();
        ledger
            .handoff(seconds(1), &mut response, seconds(30))
            .unwrap();
        assert_eq!(ledger.stats(), baseline);
    }
    assert_eq!(
        ledger.retention(key, endpoint(1, 0).address),
        Some(seconds(200))
    );
    ledger.advance(seconds(201)).unwrap();
    assert_eq!(ledger.stats().leases, 0);
    assert_eq!(ledger.retirement_candidate(), Some(route));
}

#[test]
fn cancellation_and_drop_release_only_their_own_pending_references_without_grace() {
    let mut ledger = Ledger::new(limits()).unwrap();
    let key = question("sample", 1);
    let first = reserve(&mut ledger, key, &[endpoint(1, 1000)]);
    let mut second = reserve(&mut ledger, key, &[endpoint(1, 2000)]);
    let route = publish(&mut ledger, &first)[0];
    drop(first);
    ledger.advance(Duration::ZERO).unwrap();
    assert_eq!(ledger.stats().responses, 1);
    assert_eq!(ledger.stats().leases, 1);
    assert_eq!(ledger.retention(key, endpoint(1, 0).address), None);
    assert_eq!(
        ledger.begin_retirement(Duration::ZERO, route),
        Err(Error::Referenced)
    );
    ledger.cancel(&mut second).unwrap();
    assert_eq!(ledger.stats().leases, 0);
    assert_eq!(ledger.stats().responses, 0);
    assert_eq!(ledger.retirement_candidate(), Some(route));
}

#[test]
fn active_flows_keep_backend_ownership_after_all_dns_names_expire() {
    let mut ledger = Ledger::new(limits()).unwrap();
    let key = question("sample", 1);
    let mut response = reserve(&mut ledger, key, &[endpoint(1, 1)]);
    let route = publish(&mut ledger, &response)[0];
    ledger
        .handoff(Duration::ZERO, &mut response, Duration::ZERO)
        .unwrap();
    let mut first = ledger.acquire_flow(Duration::ZERO, route).unwrap();
    ledger.advance(seconds(2)).unwrap();
    let second = ledger.acquire_flow(seconds(2), route).unwrap();
    assert_eq!(ledger.stats().leases, 0);
    assert!(matches!(
        ledger.reserve(
            seconds(2),
            question("foreign", 2),
            &[endpoint(1, 100)],
            seconds(10)
        ),
        Err(Error::Conflict)
    ));
    ledger.release_flow(&mut first).unwrap();
    assert_eq!(ledger.release_flow(&mut first), Err(Error::InvalidHandle));
    assert_eq!(ledger.route_info(route).unwrap().flows, 1);
    drop(second);
    ledger.advance(seconds(3)).unwrap();
    assert!(matches!(
        ledger.acquire_flow(seconds(3), route),
        Err(Error::NotCommitted)
    ));
    assert!(
        matches!(
            ledger.reserve(
                seconds(3),
                question("foreign", 2),
                &[endpoint(1, 100)],
                seconds(10)
            ),
            Err(Error::Conflict)
        ),
        "kernel retirement still owns the address after logical refs expire"
    );
    ledger.begin_retirement(seconds(3), route).unwrap();
    ledger.finish_retirement(route).unwrap();
    let response = ledger
        .reserve(
            seconds(3),
            question("foreign", 2),
            &[endpoint(1, 100)],
            seconds(10),
        )
        .unwrap();
    let replacement = ledger.response_route(&response, 0).unwrap();
    assert_ne!(replacement, route);
    assert_eq!(ledger.confirm_publication(route), Err(Error::InvalidHandle));
    assert_eq!(
        ledger.route_info(replacement).unwrap().key.backend,
        BackendId(2)
    );
}

#[test]
fn retiring_routes_block_renewals_and_uncertain_operations_remain_unavailable() {
    let mut ledger = Ledger::new(limits()).unwrap();
    let mut response = reserve(&mut ledger, question("sample", 1), &[endpoint(1, 1)]);
    let route = publish(&mut ledger, &response)[0];
    ledger.cancel(&mut response).unwrap();
    ledger.begin_retirement(Duration::ZERO, route).unwrap();
    assert_eq!(
        ledger.begin_retirement(Duration::ZERO, route),
        Err(Error::Retiring)
    );
    assert_eq!(ledger.confirm_publication(route), Err(Error::Retiring));
    assert!(matches!(
        ledger.reserve(
            Duration::ZERO,
            question("sample", 1),
            &[endpoint(1, 10)],
            seconds(10)
        ),
        Err(Error::Retiring)
    ));
    assert!(matches!(
        ledger.acquire_flow(Duration::ZERO, route),
        Err(Error::NotCommitted)
    ));
    ledger.advance(seconds(1000)).unwrap();
    assert_eq!(
        ledger.route_info(route).unwrap().publication,
        Publication::Retiring
    );
    assert_eq!(
        ledger.retirement_candidate(),
        None,
        "uncertain retirement must not be automatically replayed"
    );
    ledger.restore_committed(route).unwrap();
    assert_eq!(ledger.restore_committed(route), Err(Error::Retiring));
    assert_eq!(ledger.finish_retirement(route), Err(Error::Retiring));
    let response = ledger
        .reserve(
            seconds(1000),
            question("renewed", 1),
            &[endpoint(1, 2000)],
            seconds(1010),
        )
        .unwrap();
    assert_eq!(ledger.response_route(&response, 0).unwrap(), route);
}

#[test]
fn entry_and_byte_admission_exhaust_independently_even_for_one_kernel_address() {
    for byte_limited in [false, true] {
        let mut bound = Limits {
            lease_entries: if byte_limited { 32 } else { 4 },
            flow_entries: 0,
            ..limits()
        };
        if byte_limited {
            bound.bytes = required_bytes(bound, 4).unwrap();
        }
        let mut ledger = Ledger::new(bound).unwrap();
        assert_eq!(ledger.stats().lease_capacity, 4);
        assert!(ledger.stats().reserved_bytes <= bound.bytes);
        let initial_bytes = ledger.stats().reserved_bytes;
        for index in 0..4 {
            let mut response = reserve(
                &mut ledger,
                question(&format!("name{index}"), 1),
                &[endpoint(1, 1000)],
            );
            publish(&mut ledger, &response);
            ledger
                .handoff(Duration::ZERO, &mut response, seconds(30))
                .unwrap();
        }
        assert_eq!(ledger.stats().routes, 1);
        assert_eq!(ledger.stats().leases, 4);
        assert!(matches!(
            ledger.reserve(
                Duration::ZERO,
                question("excess", 1),
                &[endpoint(1, 1000)],
                seconds(100)
            ),
            Err(Error::ResourceLimit)
        ));
        let mut renewal = reserve(&mut ledger, question("name0", 1), &[endpoint(1, 2000)]);
        ledger
            .handoff(Duration::ZERO, &mut renewal, seconds(30))
            .unwrap();
        assert_eq!(ledger.stats().leases, 4);
        assert_eq!(ledger.stats().reserved_bytes, initial_bytes);
        ledger.advance(seconds(1001)).unwrap();
        assert_eq!(ledger.stats().leases, 1);
        let response = ledger
            .reserve(
                seconds(1001),
                question("reclaimed", 1),
                &[endpoint(1, 2000)],
                seconds(1010),
            )
            .unwrap();
        assert_eq!(ledger.response_len(&response).unwrap(), 1);
    }
}

#[test]
fn whole_response_preflight_preserves_existing_leases_on_count_or_conflict_failure() {
    let mut ledger = Ledger::new(Limits {
        lease_entries: 2,
        ..limits()
    })
    .unwrap();
    let first_key = question("first", 1);
    let mut first = reserve(&mut ledger, first_key, &[endpoint(1, 100)]);
    publish(&mut ledger, &first);
    ledger
        .handoff(Duration::ZERO, &mut first, seconds(30))
        .unwrap();
    let before = ledger.stats();
    assert!(matches!(
        ledger.reserve(
            Duration::ZERO,
            question("new", 1),
            &[endpoint(1, 2000), endpoint(2, 2000)],
            seconds(100)
        ),
        Err(Error::ResourceLimit)
    ));
    assert_eq!(ledger.stats(), before);
    assert!(ledger.route_for(endpoint(2, 0).address).is_none());
    assert_eq!(
        ledger.retention(first_key, endpoint(1, 0).address),
        Some(seconds(100))
    );
    let mut other = reserve(&mut ledger, question("other", 2), &[endpoint(2, 100)]);
    publish(&mut ledger, &other);
    ledger
        .handoff(Duration::ZERO, &mut other, seconds(30))
        .unwrap();
    let before = ledger.stats();
    assert!(matches!(
        ledger.reserve(
            Duration::ZERO,
            first_key,
            &[endpoint(1, 2000), endpoint(2, 2000)],
            seconds(100)
        ),
        Err(Error::Conflict)
    ));
    assert_eq!(ledger.stats(), before);
    assert_eq!(
        ledger.retention(first_key, endpoint(1, 0).address),
        Some(seconds(100))
    );
}

#[test]
fn request_and_flow_slots_have_independent_fixed_limits() {
    let mut ledger = Ledger::new(Limits {
        response_entries: 1,
        flow_entries: 1,
        ..limits()
    })
    .unwrap();
    let mut response = reserve(&mut ledger, question("sample", 1), &[endpoint(1, 100)]);
    assert!(matches!(
        ledger.reserve(
            Duration::ZERO,
            question("other", 1),
            &[endpoint(1, 100)],
            seconds(100)
        ),
        Err(Error::ResourceLimit)
    ));
    let route = publish(&mut ledger, &response)[0];
    let first_flow = ledger.acquire_flow(Duration::ZERO, route).unwrap();
    assert!(matches!(
        ledger.acquire_flow(Duration::ZERO, route),
        Err(Error::ResourceLimit)
    ));
    ledger
        .handoff(Duration::ZERO, &mut response, seconds(30))
        .unwrap();
    drop(first_flow);
    ledger.advance(Duration::ZERO).unwrap();
    let _second_flow = ledger.acquire_flow(Duration::ZERO, route).unwrap();
    assert_eq!(ledger.stats().flows, 1);
    let _response = reserve(&mut ledger, question("other", 1), &[endpoint(1, 100)]);
    assert_eq!(ledger.stats().responses, 1);
}

#[test]
fn stale_and_foreign_handles_cannot_mutate_another_reservation_or_route() {
    let mut first = Ledger::new(limits()).unwrap();
    let mut second = Ledger::new(limits()).unwrap();
    let mut response = reserve(&mut first, question("sample", 1), &[endpoint(1, 100)]);
    let route = publish(&mut first, &response)[0];
    assert_eq!(second.cancel(&mut response), Err(Error::InvalidHandle));
    assert_eq!(
        second.handoff(Duration::ZERO, &mut response, seconds(1)),
        Err(Error::InvalidHandle)
    );
    assert_eq!(second.confirm_publication(route), Err(Error::InvalidHandle));
    let mut flow = first.acquire_flow(Duration::ZERO, route).unwrap();
    assert_eq!(second.release_flow(&mut flow), Err(Error::InvalidHandle));
    first.release_flow(&mut flow).unwrap();
    first.cancel(&mut response).unwrap();
    assert_eq!(first.response_len(&response), Err(Error::InvalidHandle));
    let mut replacement = reserve(&mut first, question("replacement", 1), &[endpoint(1, 100)]);
    drop(response);
    first.advance(Duration::ZERO).unwrap();
    assert_eq!(first.response_len(&replacement).unwrap(), 1);
    first.cancel(&mut replacement).unwrap();
}

#[test]
fn deadline_expiry_does_not_release_live_partial_output_and_invalid_time_is_atomic() {
    let mut ledger = Ledger::new(limits()).unwrap();
    let key = question("sample", 1);
    let mut response = ledger
        .reserve(Duration::ZERO, key, &[endpoint(1, 0)], seconds(1))
        .unwrap();
    let route = publish(&mut ledger, &response)[0];
    ledger.advance(seconds(2)).unwrap();
    assert_eq!(ledger.stats().leases, 1);
    assert_eq!(
        ledger.handoff(seconds(2), &mut response, seconds(30)),
        Err(Error::Expired)
    );
    assert_eq!(
        ledger.begin_retirement(seconds(2), route),
        Err(Error::Referenced)
    );
    let before = ledger.stats();
    assert_eq!(ledger.advance(seconds(1)), Err(Error::InvalidTime));
    assert_eq!(ledger.stats(), before);
    drop(response);
    ledger.advance(seconds(2)).unwrap();
    assert_eq!(ledger.stats().leases, 0);
    let mut response = ledger
        .reserve(seconds(2), key, &[endpoint(1, 10)], seconds(100))
        .unwrap();
    assert_eq!(
        ledger.handoff(seconds(2), &mut response, Duration::MAX),
        Err(Error::InvalidTime)
    );
    assert_eq!(ledger.retention(key, endpoint(1, 0).address), None);
    ledger.cancel(&mut response).unwrap();
}

#[tokio::test(start_paused = true)]
async fn cross_thread_drops_wake_one_owner_and_reclaim_all_their_exact_references() {
    let mut ledger = Ledger::new(Limits {
        response_entries: 16,
        ..limits()
    })
    .unwrap();
    let mut threads = Vec::new();
    for _ in 0..16 {
        let response = reserve(&mut ledger, question("sample", 1), &[endpoint(1, 100)]);
        threads.push(std::thread::spawn(move || drop(response)));
    }
    for thread in threads {
        thread.join().unwrap();
    }
    tokio::time::timeout(seconds(1), ledger.changed())
        .await
        .unwrap();
    ledger.advance(Duration::ZERO).unwrap();
    assert_eq!(ledger.stats().responses, 0);
    assert_eq!(ledger.stats().leases, 0);
    assert!(
        tokio::time::timeout(seconds(1), ledger.changed())
            .await
            .is_err(),
        "drop notifications use one coalesced permit rather than an unbounded cleanup queue"
    );
}

#[test]
fn repeated_expiry_and_hash_index_compaction_do_not_grow_or_lose_protected_keys() {
    let mut ledger = Ledger::new(Limits {
        lease_entries: 4,
        flow_entries: 0,
        ..limits()
    })
    .unwrap();
    let anchor = question("anchor", 1);
    let mut response = reserve(&mut ledger, anchor, &[endpoint(1, 1000)]);
    publish(&mut ledger, &response);
    ledger
        .handoff(Duration::ZERO, &mut response, seconds(30))
        .unwrap();
    let baseline = ledger.stats();
    for index in 0..1000 {
        let mut response = reserve(
            &mut ledger,
            question(&format!("temporary{index}"), 1),
            &[endpoint(1, 0)],
        );
        ledger
            .handoff(Duration::ZERO, &mut response, Duration::ZERO)
            .unwrap();
        assert_eq!(ledger.stats(), baseline);
        assert_eq!(
            ledger.retention(anchor, endpoint(1, 0).address),
            Some(seconds(1000))
        );
    }
}

#[test]
fn invalid_limits_overflow_empty_input_and_identity_exhaustion_fail_before_reservation() {
    for bound in [
        Limits {
            lease_entries: 0,
            ..limits()
        },
        Limits {
            route_entries: 0,
            ..limits()
        },
        Limits {
            response_entries: 0,
            ..limits()
        },
        Limits {
            addresses_per_response: 0,
            ..limits()
        },
        Limits {
            addresses_per_response: MAX_CONTRIBUTIONS + 1,
            ..limits()
        },
        Limits {
            response_entries: usize::MAX,
            ..limits()
        },
    ] {
        assert!(matches!(Ledger::new(bound), Err(Error::InvalidLimits)));
    }
    assert!(matches!(
        Ledger::new(Limits {
            bytes: 1,
            ..limits()
        }),
        Err(Error::ResourceLimit)
    ));
    let mut ledger = Ledger::new(limits()).unwrap();
    assert!(matches!(
        ledger.reserve(Duration::ZERO, question("sample", 1), &[], seconds(1)),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        ledger.reserve(
            seconds(1),
            question("sample", 1),
            &[endpoint(1, 0)],
            seconds(1)
        ),
        Err(Error::Expired)
    ));
    let before = ledger.stats();
    ledger.next_id = u64::MAX - 1;
    assert!(matches!(
        ledger.reserve(
            seconds(1),
            question("sample", 1),
            &[endpoint(1, 0)],
            seconds(10)
        ),
        Err(Error::ResourceLimit)
    ));
    assert_eq!(ledger.stats(), before);
}

#[test]
fn canonical_default_counts_fit_the_retained_state_budget() {
    let bound = Limits {
        lease_entries: 32768,
        route_entries: 16384,
        response_entries: 128,
        flow_entries: 2048,
        addresses_per_response: 64,
        bytes: 16 * 1024 * 1024,
    };
    let ledger = Ledger::new(bound).unwrap();
    assert_eq!(ledger.stats().lease_capacity, bound.lease_entries);
    assert_eq!(ledger.stats().route_capacity, bound.route_entries);
    assert!(ledger.stats().reserved_bytes <= bound.bytes);
}

#[test]
fn one_expiry_timestamp_handles_renewal_early_wakes_and_pending_expired_leases() {
    let mut ledger = Ledger::new(limits()).unwrap();
    let key = question("sample", 1);
    let mut response = reserve(&mut ledger, key, &[endpoint(1, 10), endpoint(2, 20)]);
    publish(&mut ledger, &response);
    ledger
        .handoff(Duration::ZERO, &mut response, Duration::ZERO)
        .unwrap();
    assert_eq!(ledger.next_expiry(), Some(seconds(10)));
    let mut renewal = ledger
        .reserve(seconds(1), key, &[endpoint(1, 30)], seconds(100))
        .unwrap();
    ledger
        .handoff(seconds(1), &mut renewal, Duration::ZERO)
        .unwrap();
    ledger.advance(seconds(10)).unwrap();
    assert_eq!(ledger.stats().leases, 2);
    assert_eq!(ledger.next_expiry(), Some(seconds(20)));
    ledger.advance(seconds(20)).unwrap();
    assert_eq!(ledger.stats().leases, 1);
    assert_eq!(ledger.next_expiry(), Some(seconds(30)));
    let mut queued = ledger
        .reserve(seconds(21), key, &[endpoint(1, 100)], seconds(200))
        .unwrap();
    ledger.advance(seconds(31)).unwrap();
    assert_eq!(ledger.stats().leases, 1);
    assert_eq!(
        ledger.next_expiry(),
        None,
        "an expired lease protected by output must not spin the owner timer"
    );
    ledger.cancel(&mut queued).unwrap();
    assert_eq!(ledger.stats().leases, 0);
}

#[test]
#[ignore = "controlled ledger workload; run explicitly in release mode"]
fn lease_renewal_workload() {
    let bound = Limits {
        lease_entries: 32768,
        route_entries: 16384,
        response_entries: 128,
        flow_entries: 2048,
        addresses_per_response: 64,
        bytes: 16 * 1024 * 1024,
    };
    let mut ledger = Ledger::new(bound).unwrap();
    let keys = (0..5000)
        .map(|index| question(&format!("name{index}"), 1))
        .collect::<Vec<_>>();
    for key in &keys {
        let mut response = reserve(&mut ledger, *key, &[endpoint(1, 1000)]);
        publish(&mut ledger, &response);
        ledger
            .handoff(Duration::ZERO, &mut response, seconds(30))
            .unwrap();
    }
    let before = ledger.stats();
    let start = std::time::Instant::now();
    let mut latencies = Vec::new();
    for index in 0..1000 {
        let started = std::time::Instant::now();
        let key = keys[index * 7919 % keys.len()];
        let mut response = reserve(&mut ledger, key, &[endpoint(1, 2000)]);
        ledger
            .handoff(Duration::ZERO, &mut response, seconds(30))
            .unwrap();
        latencies.push(started.elapsed().as_nanos());
    }
    let elapsed = start.elapsed();
    let after = ledger.stats();
    assert_eq!(after, before);
    assert_eq!(after.routes, 1);
    assert_eq!(after.leases, 5000);
    assert_eq!(ledger.next_expiry(), Some(seconds(1000)));
    latencies.sort_unstable();
    println!(
        "lease workload retained_names=5000 address_owners=1 renewals=1000 reserved_bytes={} lease_capacity={} elapsed_ns={} p50_ns={} p95_ns={} p99_ns={}; synthetic fixed clock, no sockets or packet loss",
        after.reserved_bytes,
        after.lease_capacity,
        elapsed.as_nanos(),
        latencies[499],
        latencies[949],
        latencies[989]
    );
}

#[test]
fn uncertain_publication_preserves_references_and_blocks_positive_handoff_and_new_flows() {
    let mut ledger = Ledger::new(limits()).unwrap();
    let key = question("sample", 1);
    let mut response = reserve(&mut ledger, key, &[endpoint(1, 100)]);
    let route = publish(&mut ledger, &response)[0];
    let flow = ledger.acquire_flow(Duration::ZERO, route).unwrap();
    ledger.mark_uncertain(route).unwrap();
    assert_eq!(
        ledger.route_info(route).unwrap().publication,
        Publication::Uncertain
    );
    assert_eq!(
        ledger.handoff(Duration::ZERO, &mut response, seconds(30)),
        Err(Error::NotCommitted)
    );
    assert!(matches!(
        ledger.acquire_flow(Duration::ZERO, route),
        Err(Error::NotCommitted)
    ));
    assert_eq!(ledger.retention(key, endpoint(1, 0).address), None);
    assert_eq!(ledger.stats().leases, 1);
    assert_eq!(ledger.stats().flows, 1);
    ledger.confirm_publication(route).unwrap();
    ledger
        .handoff(Duration::ZERO, &mut response, seconds(30))
        .unwrap();
    drop(flow);
    ledger.advance(Duration::ZERO).unwrap();
    assert_eq!(
        ledger.retention(key, endpoint(1, 0).address),
        Some(seconds(100))
    );
}

#[test]
fn shutdown_closes_admission_and_waits_for_actual_output_and_flow_owners_before_clearing_ttls() {
    let mut ledger = Ledger::new(limits()).unwrap();
    let key = question("sample", 1);
    let mut response = reserve(&mut ledger, key, &[endpoint(1, 10000)]);
    let route = publish(&mut ledger, &response)[0];
    ledger
        .handoff(Duration::ZERO, &mut response, seconds(30))
        .unwrap();
    let flow = ledger.acquire_flow(Duration::ZERO, route).unwrap();
    let mut queued = reserve(&mut ledger, key, &[endpoint(1, 20000)]);
    assert_eq!(ledger.finish_drain(Duration::ZERO), Err(Error::Referenced));
    ledger.close();
    assert!(matches!(
        ledger.reserve(Duration::ZERO, key, &[endpoint(1, 0)], seconds(100)),
        Err(Error::Closed)
    ));
    assert!(matches!(
        ledger.acquire_flow(Duration::ZERO, route),
        Err(Error::Closed)
    ));
    assert_eq!(
        ledger.handoff(Duration::ZERO, &mut queued, seconds(30)),
        Err(Error::Closed)
    );
    assert_eq!(ledger.finish_drain(Duration::ZERO), Err(Error::Referenced));
    drop(queued);
    assert_eq!(ledger.finish_drain(Duration::ZERO), Err(Error::Referenced));
    drop(flow);
    ledger.finish_drain(Duration::ZERO).unwrap();
    assert_eq!(ledger.stats().leases, 0);
    assert_eq!(
        ledger.stats().routes,
        1,
        "native cleanup is still required after metadata drain"
    );
    ledger.begin_retirement(Duration::ZERO, route).unwrap();
    assert_eq!(ledger.mark_uncertain(route), Err(Error::Retiring));
    ledger.finish_retirement(route).unwrap();
    assert_eq!(ledger.stats().routes, 0);
}

#[test]
fn invalid_foreign_handles_do_not_advance_time_or_expire_other_ledger_state() {
    let mut first = Ledger::new(limits()).unwrap();
    let mut foreign = reserve(&mut first, question("foreign", 1), &[endpoint(2, 100)]);
    let foreign_route = first.response_route(&foreign, 0).unwrap();
    let mut second = Ledger::new(limits()).unwrap();
    let key = question("protected", 1);
    let mut own = reserve(&mut second, key, &[endpoint(1, 10)]);
    publish(&mut second, &own);
    second
        .handoff(Duration::ZERO, &mut own, Duration::ZERO)
        .unwrap();
    let before = second.stats();
    assert_eq!(
        second.handoff(seconds(20), &mut foreign, seconds(1)),
        Err(Error::InvalidHandle)
    );
    assert_eq!(
        second.stats(),
        before,
        "foreign commands must fail validation before clock mutation"
    );
    assert!(matches!(
        second.acquire_flow(seconds(20), foreign_route),
        Err(Error::InvalidHandle)
    ));
    assert_eq!(
        second.begin_retirement(seconds(20), foreign_route),
        Err(Error::InvalidHandle)
    );
    second.advance(seconds(1)).unwrap();
    assert_eq!(
        second.retention(key, endpoint(1, 0).address),
        Some(seconds(10))
    );
}

#[test]
fn address_index_reclamation_preserves_foreign_generations_and_protected_owner() {
    let mut ledger = Ledger::new(Limits {
        lease_entries: 4,
        flow_entries: 0,
        ..limits()
    })
    .unwrap();
    let key = question("anchor", 1);
    let mut response = reserve(&mut ledger, key, &[endpoint(1, 1000)]);
    let anchor = publish(&mut ledger, &response)[0];
    ledger
        .handoff(Duration::ZERO, &mut response, seconds(30))
        .unwrap();
    let baseline = ledger.stats();
    for index in 2..1026_u128 {
        let address = IpAddr::V6(std::net::Ipv6Addr::from(
            0x20010db8000000000000000000000000_u128 + index,
        ));
        let contribution = Contribution {
            address,
            expires_at: Duration::ZERO,
        };
        let key = QuestionKey {
            record_type: 65,
            ..question("temporary", 2)
        };
        let mut response = reserve(&mut ledger, key, &[contribution]);
        let temporary = publish(&mut ledger, &response)[0];
        ledger
            .handoff(Duration::ZERO, &mut response, Duration::ZERO)
            .unwrap();
        ledger.begin_retirement(Duration::ZERO, temporary).unwrap();
        ledger.finish_retirement(temporary).unwrap();
        assert_eq!(
            ledger.route_info(temporary).err(),
            Some(Error::InvalidHandle)
        );
        assert_eq!(ledger.route_for(endpoint(1, 0).address), Some(anchor));
        assert_eq!(ledger.stats(), baseline);
    }
}
