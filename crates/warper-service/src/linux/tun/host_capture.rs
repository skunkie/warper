// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Extend durable native capture only after publishing the live handler.

use super::{Error, Owner, Stage, capture, capture_cause, transaction};
use std::net::{IpAddr, Ipv4Addr};
use warper_core::{BackendId, transport::Request};
use warper_stack::runtime::Publication;

impl Owner {
    /// Publish one live IPv4 mapping in a retained native worker. The caller
    /// must retain its DNS reservation and exclude physical transport endpoints.
    /// Success proves native capture, not ledger commitment or DNS output.
    pub fn publish_host(
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
        verify_mapping(&publication, address, backend)?;
        if self
            .capture_publication
            .as_ref()
            .is_some_and(|current| !current.same_runtime(&publication))
        {
            return Err(Error::Conflict);
        }
        let owner = self.record.owner.encode();
        let metric = 0x80000000 | u32::from_be_bytes([owner[56], owner[57], owner[58], owner[59]]);
        let (plan, added) =
            capture::Plan::extend_host(self.record.capture.as_ref(), address, metric)?;
        let index = self.index().ok_or(Error::InvalidState)?;
        let mut before =
            crate::linux::change_monitor::Monitor::subscribe().map_err(Error::CaptureMonitor)?;
        if self.record.capture.is_some() {
            self.capture_changes()?
                .check_pending()
                .map_err(Error::CaptureChanged)?;
            // Inspect the complete committed baseline before accepting another
            // key. Missing or changed earlier routes cannot become new intent.
            self.record
                .capture
                .as_ref()
                .ok_or(Error::InvalidState)?
                .inspect(index, request.clone(), true)?;
        }
        if !added {
            before.check_pending().map_err(Error::CaptureChanged)?;
            self.capture_changes()?
                .check_pending()
                .map_err(Error::CaptureChanged)?;
            self.verify_capture_device(&wait)?;
            return verify_mapping(&publication, address, backend);
        }
        let host = capture::Prefix {
            network: address,
            length: 32,
        };
        capture::Plan {
            prefixes: vec![host],
            metric,
        }
        .inspect(index, request.clone(), false)?;
        before.check_pending().map_err(Error::CaptureChanged)?;
        self.verify_capture_device(&wait)?;
        verify_mapping(&publication, address, backend)?;
        let mut intent = self.record.clone();
        intent.stage = Stage::Routing;
        intent.capture = Some(plan.clone());
        self.capture_publication = Some(publication);
        self.save(intent)?;
        let result = (|| {
            self.context.revalidate().map_err(Error::Context)?;
            self.verify_capture_device(&wait)?;
            verify_mapping(
                self.capture_publication
                    .as_ref()
                    .ok_or(Error::InvalidState)?,
                address,
                backend,
            )?;
            before.check_pending().map_err(Error::CaptureChanged)?;
            capture::add(host, metric, index, &wait)?;
            drop(before);
            self.capture_monitor = Some(
                crate::linux::change_monitor::Monitor::subscribe()
                    .map_err(Error::CaptureMonitor)?,
            );
            plan.inspect(index, request, true)?;
            self.verify_capture_device(&wait)?;
            verify_mapping(
                self.capture_publication
                    .as_ref()
                    .ok_or(Error::InvalidState)?,
                address,
                backend,
            )?;
            self.capture_changes()?
                .check_pending()
                .map_err(Error::CaptureChanged)?;
            let mut committed = self.record.clone();
            committed.stage = Stage::Captured;
            self.save(committed)?;
            self.capture_changes()?
                .check_pending()
                .map_err(Error::CaptureChanged)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

fn verify_mapping(
    publication: &Publication,
    address: Ipv4Addr,
    backend: BackendId,
) -> Result<(), Error> {
    if publication.selected_backend(IpAddr::V4(address)) != Ok(backend) {
        return Err(Error::InvalidCapturePolicy);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use warper_core::routing::{Entry, Policy};
    use warper_stack::{Seed, host::Limits, runtime::Runtime};

    #[tokio::test]
    async fn mapping_checks_reject_another_backend_unselected_or_stopped_runtime() {
        let address = Ipv4Addr::new(192, 0, 2, 9);
        let policy = Arc::new(
            Policy::new(
                &[Entry {
                    network: address.into(),
                    prefix_len: 32,
                    backend: BackendId(7),
                }],
                1,
            )
            .unwrap(),
        );
        let (runtime, channels) =
            Runtime::new(Limits::default(), policy, 1, Seed::generate().unwrap()).unwrap();
        assert_eq!(
            verify_mapping(&channels.publication, address, BackendId(7)),
            Ok(())
        );
        assert_eq!(
            verify_mapping(&channels.publication, address, BackendId(8)),
            Err(Error::InvalidCapturePolicy)
        );
        assert_eq!(
            verify_mapping(
                &channels.publication,
                Ipv4Addr::new(192, 0, 2, 10),
                BackendId(7)
            ),
            Err(Error::InvalidCapturePolicy)
        );
        drop(runtime);
        assert_eq!(
            verify_mapping(&channels.publication, address, BackendId(7)),
            Err(Error::InvalidCapturePolicy)
        );
    }
}
