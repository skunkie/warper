// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Discard only unchanged unpublished connection intent under service ownership.

use super::*;

pub struct PendingInspection {
    directory: Stat,
    instance: [u8; 16],
    committed: Option<(Snapshot, Pin)>,
    pending: File,
    metadata: Stat,
    bytes: Vec<u8>,
}
impl PendingInspection {
    pub fn committed(&self) -> Option<Snapshot> {
        self.committed.as_ref().map(|(record, _)| *record)
    }
    pub fn pending_len(&self) -> usize {
        self.bytes.len()
    }
}
impl fmt::Debug for PendingInspection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConnectionPendingInspection(<redacted>)")
    }
}
impl ConnectionStore {
    /// Root persistence boundary. The service must separately authorize the
    /// administrative request and bound retained in-process inspection tokens.
    pub fn inspect_pending(
        &self,
        lease: &RuntimeLease,
    ) -> Result<Option<PendingInspection>, Error> {
        self.verify(lease)?;
        let Some((pending, bytes, metadata)) = self.pending_snapshot()? else {
            return Ok(None);
        };
        let committed = self.observed_load()?;
        Ok(Some(PendingInspection {
            directory: fstat(&self.state.directory).map_err(os_error)?,
            instance: self.instance,
            committed,
            pending,
            metadata,
            bytes,
        }))
    }
    pub fn discard_pending(
        &mut self,
        lease: &RuntimeLease,
        inspection: PendingInspection,
    ) -> Result<(), Error> {
        self.discard_with_sync(lease, inspection, Self::sync)
    }
    pub(super) fn discard_with_sync(
        &mut self,
        lease: &RuntimeLease,
        inspection: PendingInspection,
        commit_sync: impl FnOnce(&Self) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.verify(lease)?;
        if inspection.instance != self.instance {
            return Err(Error::Conflict);
        }
        require_same(
            &inspection.directory,
            &fstat(&self.state.directory).map_err(os_error)?,
        )
        .map_err(|_| Error::UnsafeState)?;
        let current = self.observed_load()?;
        match (&inspection.committed, &current) {
            (None, None) => {}
            (Some((before, pin)), Some((after, new))) if before == after => {
                if !unchanged(&pin.metadata, &fstat(&pin.fd).map_err(os_error)?)
                    || !unchanged(&pin.metadata, &new.metadata)
                {
                    return Err(Error::UnsafeState);
                }
            }
            _ => return Err(Error::Conflict),
        }
        if !unchanged(
            &inspection.metadata,
            &fstat(&inspection.pending).map_err(os_error)?,
        ) {
            return Err(Error::UnsafeState);
        }
        let Some((_file, bytes, metadata)) = self.pending_snapshot()? else {
            return Err(Error::UnsafeState);
        };
        if !unchanged(&inspection.metadata, &metadata) || inspection.bytes != bytes {
            return Err(Error::UnsafeState);
        }
        unlinkat(&self.state.directory, PENDING, AtFlags::empty()).map_err(os_error)?;
        self.uncertain.set(true);
        commit_sync(self).map_err(|error| match error {
            Error::Io(kind) => Error::CommitUncertain(kind),
            other => other,
        })?;
        self.uncertain.set(false);
        Ok(())
    }
    fn pending_snapshot(&self) -> Result<Option<(File, Vec<u8>, Stat)>, Error> {
        let pin = match openat2(
            &self.state.directory,
            PENDING,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            resolution(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(os_error(error)),
        };
        let metadata = fstat(&pin).map_err(os_error)?;
        if !(0..=RECORD_LEN as i64).contains(&metadata.st_size) {
            return Err(Error::UnsafeState);
        }
        check_file(&metadata, self.state.owner, metadata.st_size as u64)?;
        let fd = openat2(
            &self.state.directory,
            PENDING,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
            resolution(),
        )
        .map_err(os_error)?;
        if !unchanged(&metadata, &fstat(&fd).map_err(os_error)?) {
            return Err(Error::UnsafeState);
        }
        let mut file = File::from(fd);
        let mut bytes = Vec::with_capacity(RECORD_LEN + 1);
        (&mut file)
            .take((RECORD_LEN + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| Error::Io(e.kind()))?;
        if bytes.len() as u64 != metadata.st_size as u64
            || !unchanged(&metadata, &fstat(&file).map_err(os_error)?)
            || !unchanged(
                &metadata,
                &named(&self.state.directory, PENDING).map_err(Error::Runtime)?,
            )
        {
            return Err(Error::UnsafeState);
        }
        Ok(Some((file, bytes, metadata)))
    }
}
