// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Withdraw a retired DNS host while preserving unrelated live capture.

use super::{Error, Owner, Stage, capture, capture_cause, transaction};
use std::net::{IpAddr, Ipv4Addr};
use warper_core::{BackendId, transport::Request};
use warper_stack::runtime::Publication;

impl Owner {
    /// Run in a retained native worker after the live selector begins retirement.
    /// Keep that address owner retiring until this worker joins; only successful
    /// native withdrawal permits the caller to release its ledger ownership.
    pub fn withdraw_host(
        &mut self,
        publication: Publication,
        address: Ipv4Addr,
        backend: BackendId,
        request: Request,
    ) -> Result<(), Error> {
        if !matches!(self.record.stage, Stage::Enabled | Stage::Captured) || !self.port_issued {
            return Err(Error::InvalidState);
        }
        let wait = transaction::Wait::new(request.clone()).map_err(capture_cause)?;
        self.ready()?;
        tokio::runtime::Handle::try_current().map_err(|_| Error::NoRuntime)?;
        self.verify_capture_device(&wait)?;
        verify_retirement(&publication, address, backend)?;
        if self
            .capture_publication
            .as_ref()
            .is_some_and(|current| !current.same_runtime(&publication))
        {
            return Err(Error::Conflict);
        }
        let index = self.index().ok_or(Error::InvalidState)?;
        let owner = self.record.owner.encode();
        let metric = 0x80000000 | u32::from_be_bytes([owner[56], owner[57], owner[58], owner[59]]);
        let host = capture::Plan {
            prefixes: vec![capture::Prefix {
                network: address,
                length: 32,
            }],
            metric,
        };
        let mut before =
            crate::linux::change_monitor::Monitor::subscribe().map_err(Error::CaptureMonitor)?;
        let Some(plan) = self.record.capture.clone() else {
            if self.record.stage != Stage::Enabled || self.capture_publication.is_some() {
                return Err(Error::InvalidState);
            }
            host.inspect_absence(request)?;
            before.check_pending().map_err(Error::CaptureChanged)?;
            return verify_retirement(&publication, address, backend);
        };
        if self.capture_publication.is_none() || plan.metric != metric {
            return Err(Error::InvalidState);
        }
        self.capture_changes()?
            .check_pending()
            .map_err(Error::CaptureChanged)?;
        plan.inspect(index, request.clone(), true)?;
        before.check_pending().map_err(Error::CaptureChanged)?;
        if let Some(entry) = publication
            .entries()
            .iter()
            .find(|entry| entry.network == IpAddr::V4(address) && entry.prefix_len == 32)
        {
            if entry.backend != backend {
                return Err(Error::InvalidCapturePolicy);
            }
            if plan
                .prefixes
                .iter()
                .any(|prefix| prefix.network == address && prefix.length == 32)
            {
                return verify_retirement(&publication, address, backend);
            }
        }
        let (remaining, removed) = plan.without_host(address)?;
        if !removed {
            host.inspect_absence(request)?;
            before.check_pending().map_err(Error::CaptureChanged)?;
            self.capture_changes()?
                .check_pending()
                .map_err(Error::CaptureChanged)?;
            return verify_retirement(&publication, address, backend);
        }
        self.verify_capture_device(&wait)?;
        verify_retirement(&publication, address, backend)?;
        before.check_pending().map_err(Error::CaptureChanged)?;
        let mut intent = self.record.clone();
        // The complete old batch remains durable until the deleted key is
        // proven absent. A crash cannot erase uncertain removal ownership.
        intent.stage = Stage::RoutesRetiring;
        self.save(intent)?;
        let result = (|| {
            capture::remove(&host, index, request.clone(), &wait, || {
                self.context.revalidate().map_err(Error::Context)?;
                self.verify_capture_device(&wait)?;
                verify_retirement(&publication, address, backend)
            })?;
            drop(before);
            self.capture_monitor = Some(
                crate::linux::change_monitor::Monitor::subscribe()
                    .map_err(Error::CaptureMonitor)?,
            );
            host.inspect_absence(request.clone())?;
            if let Some(remaining) = &remaining {
                remaining.inspect(index, request, true)?;
            }
            self.verify_capture_device(&wait)?;
            verify_retirement(&publication, address, backend)?;
            self.capture_changes()?
                .check_pending()
                .map_err(Error::CaptureChanged)?;
            let mut committed = self.record.clone();
            committed.stage = if remaining.is_some() {
                Stage::Captured
            } else {
                Stage::Enabled
            };
            committed.capture = remaining;
            self.save(committed)?;
            self.capture_changes()?
                .check_pending()
                .map_err(Error::CaptureChanged)?;
            if self.record.capture.is_none() {
                self.capture_publication = None;
                self.capture_monitor = None;
            }
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

fn verify_retirement(
    publication: &Publication,
    address: Ipv4Addr,
    backend: BackendId,
) -> Result<(), Error> {
    publication
        .verify_retirement(address.into(), backend)
        .map_err(|_| Error::CaptureHostActive)
}
