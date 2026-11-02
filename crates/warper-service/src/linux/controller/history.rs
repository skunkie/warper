// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded results; durable revision/instance fences reject evicted replays.

use std::collections::VecDeque;
use warper_control::{
    message::{Operation, OperationState},
    runtime::connection::Request,
    wire::Code,
};

pub(crate) const MAX_OPERATIONS: usize = 4096;

#[derive(Clone, Copy)]
struct Entry {
    request: Request,
    operation: Operation,
}
pub(super) struct History {
    entries: VecDeque<Entry>,
    capacity: usize,
}
pub(super) struct Reservation {
    length: usize,
    victim: Option<Eviction>,
}
struct Eviction {
    id: [u8; 16],
    index: usize,
}
impl History {
    pub(super) fn new(capacity: usize) -> Result<Self, Code> {
        if !(1..=MAX_OPERATIONS).contains(&capacity) {
            return Err(Code::Malformed);
        }
        let mut entries = VecDeque::new();
        entries
            .try_reserve_exact(capacity)
            .map_err(|_| Code::Busy)?;
        Ok(Self { entries, capacity })
    }
    pub(super) fn lookup(&self, request: &Request) -> Result<Option<Operation>, Code> {
        let Some(entry) = self
            .entries
            .iter()
            .find(|entry| entry.operation.id == request.operation)
        else {
            return Ok(None);
        };
        if !same_request(&entry.request, request) {
            return Err(Code::Conflict);
        }
        Ok(Some(entry.operation))
    }
    pub(super) fn get(&self, id: &[u8; 16]) -> Result<Operation, Code> {
        self.entries
            .iter()
            .find(|entry| &entry.operation.id == id)
            .map(|entry| entry.operation)
            .ok_or(Code::Conflict)
    }
    pub(super) fn reserve(&self, superseding: Option<[u8; 16]>) -> Result<Reservation, Code> {
        let victim = if self.entries.len() < self.capacity {
            None
        } else {
            Some(
                self.entries
                    .iter()
                    .position(|entry| entry.operation.state.terminal())
                    .or_else(|| {
                        self.entries
                            .iter()
                            .position(|entry| Some(entry.operation.id) == superseding)
                    })
                    .ok_or(Code::Busy)?,
            )
        };
        Ok(Reservation {
            length: self.entries.len(),
            victim: victim.map(|index| Eviction {
                id: self.entries[index].operation.id,
                index,
            }),
        })
    }
    pub(super) fn commit(
        &mut self,
        reservation: Reservation,
        request: Request,
    ) -> Result<(), Code> {
        if self.entries.len() != reservation.length || self.lookup(&request)?.is_some() {
            return Err(Code::RecoveryRequired);
        }
        if let Some(victim) = reservation.victim {
            if !self.entries.get(victim.index).is_some_and(|entry| {
                entry.operation.id == victim.id && entry.operation.state.terminal()
            }) {
                return Err(Code::RecoveryRequired);
            }
            self.entries.remove(victim.index);
        }
        if self.entries.len() >= self.capacity {
            return Err(Code::RecoveryRequired);
        }
        self.entries.push_back(Entry {
            request,
            operation: Operation {
                id: request.operation,
                state: OperationState::Running,
                code: Code::None,
            },
        });
        Ok(())
    }
    pub(super) fn finish(
        &mut self,
        id: [u8; 16],
        state: OperationState,
        code: Code,
    ) -> Result<(), Code> {
        if !state.terminal() || ((state == OperationState::Failed) != (code != Code::None)) {
            return Err(Code::RecoveryRequired);
        }
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.operation.id == id)
            .ok_or(Code::RecoveryRequired)?;
        if entry.operation.state.terminal() {
            return if entry.operation.state == state && entry.operation.code == code {
                Ok(())
            } else {
                Err(Code::Conflict)
            };
        }
        entry.operation.state = state;
        entry.operation.code = code;
        Ok(())
    }
    pub(super) fn resized(&self, capacity: usize) -> Result<Self, Code> {
        let mut replacement = Self::new(capacity)?;
        if self
            .entries
            .iter()
            .any(|entry| !entry.operation.state.terminal())
        {
            return Err(Code::Busy);
        }
        replacement.entries.extend(
            self.entries
                .iter()
                .skip(self.entries.len().saturating_sub(capacity))
                .copied(),
        );
        Ok(replacement)
    }
}
fn same_request(a: &Request, b: &Request) -> bool {
    a.operation == b.operation
        && a.expected_configuration == b.expected_configuration
        && a.expected_revision == b.expected_revision
        && a.expected_instance == b.expected_instance
        && a.desired == b.desired
}

#[cfg(test)]
mod tests;
