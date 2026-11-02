// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use warper_control::{runtime::connection::Desired, wire};

fn request(revision: u64) -> Request {
    Request {
        operation: wire::operation_id(revision, [3; 8]).unwrap(),
        expected_configuration: 7,
        expected_revision: revision,
        expected_instance: [9; 16],
        desired: Desired::Up,
    }
}
fn insert(history: &mut History, request: Request) {
    let reservation = history.reserve(None).unwrap();
    history.commit(reservation, request).unwrap();
}

#[test]
fn active_capacity_is_protected_and_terminal_eviction_is_oldest_first() {
    let mut history = History::new(2).unwrap();
    let first = request(0);
    let second = request(1);
    insert(&mut history, first);
    insert(&mut history, second);
    assert!(matches!(history.reserve(None), Err(Code::Busy)));
    history
        .finish(second.operation, OperationState::Succeeded, Code::None)
        .unwrap();
    let third = request(2);
    insert(&mut history, third);
    assert!(history.get(&first.operation).is_ok());
    assert_eq!(history.get(&second.operation), Err(Code::Conflict));
    assert_eq!(
        history.get(&third.operation).unwrap().state,
        OperationState::Running
    );
    history
        .finish(first.operation, OperationState::Failed, Code::Timeout)
        .unwrap();
    history
        .finish(third.operation, OperationState::Succeeded, Code::None)
        .unwrap();
    insert(&mut history, request(3));
    assert_eq!(history.get(&first.operation), Err(Code::Conflict));
    assert!(history.get(&third.operation).is_ok());
}

#[test]
fn lookup_requires_the_original_command_and_all_fences() {
    let mut history = History::new(1).unwrap();
    let original = request(0);
    insert(&mut history, original);
    assert_eq!(
        history.lookup(&original).unwrap().unwrap().state,
        OperationState::Running
    );
    let mut changed = original;
    changed.desired = Desired::Down;
    assert_eq!(history.lookup(&changed), Err(Code::Conflict));
    changed = original;
    changed.expected_configuration += 1;
    assert_eq!(history.lookup(&changed), Err(Code::Conflict));
    changed = original;
    changed.expected_revision += 1;
    assert_eq!(history.lookup(&changed), Err(Code::Conflict));
    changed = original;
    changed.expected_instance = [1; 16];
    assert_eq!(history.lookup(&changed), Err(Code::Conflict));
    assert_eq!(history.lookup(&request(2)), Ok(None));
}

#[test]
fn rejected_or_abandoned_reservations_preserve_retained_results() {
    let mut history = History::new(1).unwrap();
    let original = request(0);
    insert(&mut history, original);
    history
        .finish(original.operation, OperationState::Succeeded, Code::None)
        .unwrap();
    let _abandoned = history.reserve(None).unwrap();
    assert_eq!(
        history.get(&original.operation).unwrap().state,
        OperationState::Succeeded
    );
    let reservation = history.reserve(None).unwrap();
    assert_eq!(
        history.commit(reservation, original),
        Err(Code::RecoveryRequired)
    );
    assert!(history.get(&original.operation).is_ok());
}

#[test]
fn completion_is_terminal_and_cannot_rewrite_historical_success() {
    let mut history = History::new(2).unwrap();
    let original = request(0);
    insert(&mut history, original);
    for (state, code) in [
        (OperationState::Accepted, Code::None),
        (OperationState::Running, Code::None),
        (OperationState::Failed, Code::None),
        (OperationState::Succeeded, Code::Failed),
        (OperationState::Superseded, Code::Timeout),
    ] {
        assert_eq!(
            history.finish(original.operation, state, code),
            Err(Code::RecoveryRequired)
        );
    }
    history
        .finish(original.operation, OperationState::Succeeded, Code::None)
        .unwrap();
    history
        .finish(original.operation, OperationState::Succeeded, Code::None)
        .unwrap();
    assert_eq!(
        history.finish(original.operation, OperationState::Failed, Code::Failed),
        Err(Code::Conflict)
    );
    assert_eq!(
        history.finish(request(1).operation, OperationState::Failed, Code::Failed),
        Err(Code::RecoveryRequired)
    );
}

#[test]
fn resizing_retains_recent_results_and_never_discards_active_operations() {
    let mut history = History::new(2).unwrap();
    let first = request(0);
    let second = request(1);
    insert(&mut history, first);
    assert!(matches!(history.resized(1), Err(Code::Busy)));
    history
        .finish(first.operation, OperationState::Superseded, Code::None)
        .unwrap();
    insert(&mut history, second);
    history
        .finish(second.operation, OperationState::Failed, Code::Failed)
        .unwrap();
    let replacement = history.resized(1).unwrap();
    assert_eq!(replacement.get(&first.operation), Err(Code::Conflict));
    assert_eq!(
        replacement.get(&second.operation).unwrap().code,
        Code::Failed
    );
    assert!(history.get(&first.operation).is_ok());
    assert!(matches!(history.resized(0), Err(Code::Malformed)));
    assert!(matches!(
        history.resized(MAX_OPERATIONS + 1),
        Err(Code::Malformed)
    ));
    History::new(MAX_OPERATIONS).unwrap();
}

#[test]
fn single_record_capacity_can_reserve_disconnect_without_evicting_active_connect() {
    let mut history = History::new(1).unwrap();
    let connect = request(0);
    insert(&mut history, connect);
    let _abandoned = history.reserve(Some(connect.operation)).unwrap();
    assert_eq!(
        history.get(&connect.operation).unwrap().state,
        OperationState::Running
    );
    let reservation = history.reserve(Some(connect.operation)).unwrap();
    // Only after durable Disconnect acceptance may Connect become terminal.
    history
        .finish(connect.operation, OperationState::Superseded, Code::None)
        .unwrap();
    let mut disconnect = request(1);
    disconnect.desired = Desired::Down;
    history.commit(reservation, disconnect).unwrap();
    assert_eq!(history.get(&connect.operation), Err(Code::Conflict));
    assert_eq!(
        history.get(&disconnect.operation).unwrap().state,
        OperationState::Running
    );
}

#[test]
fn stale_or_premature_eviction_never_discards_a_protected_or_replacement_result() {
    let mut history = History::new(1).unwrap();
    let first = request(0);
    insert(&mut history, first);
    let premature = history.reserve(Some(first.operation)).unwrap();
    assert_eq!(
        history.commit(premature, request(1)),
        Err(Code::RecoveryRequired)
    );
    assert_eq!(
        history.get(&first.operation).unwrap().state,
        OperationState::Running
    );
    history
        .finish(first.operation, OperationState::Succeeded, Code::None)
        .unwrap();
    let stale = history.reserve(None).unwrap();
    let second = request(1);
    insert(&mut history, second);
    history
        .finish(second.operation, OperationState::Succeeded, Code::None)
        .unwrap();
    assert_eq!(
        history.commit(stale, request(2)),
        Err(Code::RecoveryRequired)
    );
    assert_eq!(
        history.get(&second.operation).unwrap().state,
        OperationState::Succeeded
    );
}
