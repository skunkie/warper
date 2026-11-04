// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::{
    tests::{endpoint, limits, publish, question, reserve, seconds},
    *,
};

#[test]
fn authorized_output_completion_after_deadline_keeps_pending_coverage_and_full_grace() {
    let mut ledger = Ledger::new(limits()).unwrap();
    let key = question("late", 7);
    let response = ledger
        .reserve(
            Duration::ZERO,
            key,
            &[endpoint(1, 0), endpoint(2, 0)],
            seconds(2),
        )
        .unwrap();
    let routes = publish(&mut ledger, &response);
    let mut output = ledger.begin_output(seconds(1), response).unwrap();
    ledger.advance(seconds(10)).unwrap();
    assert_eq!(ledger.stats().responses, 1);
    for route in &routes {
        assert_eq!(
            ledger.begin_retirement(seconds(10), *route),
            Err(Error::Referenced)
        );
    }
    ledger
        .complete_output(seconds(10), &mut output, seconds(5))
        .unwrap();
    assert_eq!(ledger.stats().responses, 0);
    for last in [1, 2] {
        assert_eq!(
            ledger.retention(key, endpoint(last, 0).address),
            Some(seconds(15))
        );
    }
    let flow = ledger.acquire_flow(seconds(14), routes[0]).unwrap();
    ledger.advance(seconds(16)).unwrap();
    assert_eq!(ledger.stats().leases, 0);
    assert_eq!(ledger.route_info(routes[0]).unwrap().flows, 1);
    drop(flow);
    ledger.advance(seconds(16)).unwrap();
    for route in routes {
        ledger.begin_retirement(seconds(16), route).unwrap();
        ledger.finish_retirement(route).unwrap();
    }
}

#[test]
fn completed_output_keeps_retention_after_closure_or_publication_uncertainty() {
    for uncertain in [false, true] {
        let mut ledger = Ledger::new(limits()).unwrap();
        let key = question("stopping", 7);
        let response = reserve(&mut ledger, key, &[endpoint(1, 0)]);
        let route = publish(&mut ledger, &response)[0];
        let mut output = ledger.begin_output(seconds(1), response).unwrap();
        if uncertain {
            ledger.mark_uncertain(route).unwrap();
        } else {
            ledger.close();
        }
        ledger
            .complete_output(seconds(101), &mut output, seconds(5))
            .unwrap();
        assert_eq!(
            ledger.retention(key, endpoint(1, 0).address),
            Some(seconds(106))
        );
        assert_eq!(
            ledger.route_info(route).unwrap().publication,
            if uncertain {
                Publication::Uncertain
            } else {
                Publication::Committed
            }
        );
        assert!(
            ledger.acquire_flow(seconds(102), route).is_err(),
            "completion does not reopen admission"
        );
    }
}

#[test]
fn output_authorization_rejects_expired_closed_or_partly_unpublished_responses() {
    struct Case {
        id: &'static str,
        closed: bool,
        now: Duration,
        published: usize,
        expected: Error,
    }
    let cases = [
        Case {
            id: "expired",
            closed: false,
            now: seconds(100),
            published: 2,
            expected: Error::Expired,
        },
        Case {
            id: "closed",
            closed: true,
            now: seconds(1),
            published: 2,
            expected: Error::Closed,
        },
        Case {
            id: "partial publication",
            closed: false,
            now: seconds(1),
            published: 1,
            expected: Error::NotCommitted,
        },
    ];
    for case in cases {
        let mut ledger = Ledger::new(limits()).unwrap();
        let response = reserve(
            &mut ledger,
            question("rejected", 7),
            &[endpoint(1, 0), endpoint(2, 0)],
        );
        for index in 0..case.published {
            let route = ledger.response_route(&response, index).unwrap();
            ledger.confirm_publication(route).unwrap();
        }
        if case.closed {
            ledger.close();
        }
        assert!(
            matches!(ledger.begin_output(case.now,response),Err(error) if error==case.expected),
            "{}",
            case.id
        );
        ledger.advance(case.now).unwrap();
        assert_eq!(ledger.stats().responses, 0, "{}", case.id);
        assert_eq!(ledger.stats().leases, 0, "{}", case.id);
    }
}

#[test]
fn cancelled_partial_output_creates_no_grace_and_releases_only_its_own_references() {
    let mut ledger = Ledger::new(limits()).unwrap();
    let key = question("partial", 7);
    let response = reserve(&mut ledger, key, &[endpoint(1, 0)]);
    let route = publish(&mut ledger, &response)[0];
    let another = reserve(&mut ledger, key, &[endpoint(1, 0)]);
    let output = ledger.begin_output(seconds(1), response).unwrap();
    drop(output);
    ledger.advance(seconds(101)).unwrap();
    assert_eq!(ledger.stats().responses, 1);
    assert_eq!(ledger.retention(key, endpoint(1, 0).address), None);
    assert_eq!(
        ledger.begin_retirement(seconds(101), route),
        Err(Error::Referenced)
    );
    drop(another);
    ledger.advance(seconds(101)).unwrap();
    ledger.begin_retirement(seconds(101), route).unwrap();
    ledger.finish_retirement(route).unwrap();
}

#[test]
fn backwards_clock_rejects_authorization_without_leaking_an_unwritten_response() {
    let mut ledger = Ledger::new(limits()).unwrap();
    let response = reserve(&mut ledger, question("clock", 7), &[endpoint(1, 0)]);
    publish(&mut ledger, &response);
    ledger.advance(seconds(2)).unwrap();
    assert!(matches!(
        ledger.begin_output(seconds(1), response),
        Err(Error::InvalidTime)
    ));
    ledger.advance(seconds(2)).unwrap();
    assert_eq!(ledger.stats().responses, 0);
    assert_eq!(ledger.stats().leases, 0);
}

#[test]
fn completion_errors_retain_the_guard_and_cannot_mutate_another_ledger() {
    let mut ledger = Ledger::new(limits()).unwrap();
    let response = reserve(&mut ledger, question("retry", 7), &[endpoint(1, 0)]);
    let route = publish(&mut ledger, &response)[0];
    let mut output = ledger.begin_output(seconds(1), response).unwrap();
    let mut other = Ledger::new(limits()).unwrap();
    assert_eq!(
        other.complete_output(seconds(50), &mut output, seconds(5)),
        Err(Error::InvalidHandle)
    );
    let other_response = reserve(&mut other, question("other", 8), &[endpoint(2, 0)]);
    assert_eq!(
        ledger.complete_output(seconds(2), &mut output, Duration::MAX),
        Err(Error::InvalidTime)
    );
    assert_eq!(ledger.stats().responses, 1);
    assert_eq!(
        ledger.begin_retirement(seconds(2), route),
        Err(Error::Referenced)
    );
    ledger
        .complete_output(seconds(3), &mut output, seconds(5))
        .unwrap();
    assert_eq!(
        ledger.complete_output(seconds(3), &mut output, seconds(5)),
        Err(Error::InvalidHandle)
    );
    drop(other_response);
}
