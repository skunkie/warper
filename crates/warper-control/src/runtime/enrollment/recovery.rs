// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Explicit administrative discard of unchanged unpublished owner intent.

use super::*;

/// A bounded pinned snapshot, not a serializable recovery authorization.
/// Dropping it preserves all filesystem state. Never grants a pending owner.
pub struct PendingInspection {
    directory: Stat,
    committed: Enrollment,
    owner_pin: Option<OwnedFd>,
    owner_metadata: Option<Stat>,
    pending: File,
    pending_metadata: Stat,
    bytes: Vec<u8>,
}
impl PendingInspection {
    pub fn committed(&self) -> Enrollment {
        self.committed
    }
    pub fn pending_len(&self) -> usize {
        self.bytes.len()
    }
}
impl fmt::Debug for PendingInspection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PendingInspection(<redacted>)")
    }
}

impl OwnerStore {
    /// Require a fresh live administrative peer before inspecting any record.
    pub fn inspect_pending(
        &self,
        lease: &RuntimeLease,
        peer: &UnixStream,
    ) -> Result<Option<PendingInspection>, Error> {
        authorize(lease, peer)?;
        self.inspect()
    }

    /// Discard only the unchanged inspected intent; preserve committed policy.
    /// A failed final directory sync reports CommitUncertain after unlink.
    pub fn discard_pending(
        &mut self,
        lease: &RuntimeLease,
        peer: &UnixStream,
        inspection: PendingInspection,
    ) -> Result<Enrollment, Error> {
        authorize(lease, peer)?;
        self.discard(lease, inspection, Self::sync)
    }

    fn inspect(&self) -> Result<Option<PendingInspection>, Error> {
        self.verify()?;
        let Some((pending, bytes, pending_metadata)) = self.pending_snapshot()? else {
            return Ok(None);
        };
        let (committed, owner_pin) = self.load()?;
        let owner_metadata = owner_pin
            .as_ref()
            .map(fstat)
            .transpose()
            .map_err(os_error)?;
        Ok(Some(PendingInspection {
            directory: fstat(&self.directory).map_err(os_error)?,
            committed,
            owner_pin,
            owner_metadata,
            pending,
            pending_metadata,
            bytes,
        }))
    }

    fn discard(
        &self,
        lease: &RuntimeLease,
        inspection: PendingInspection,
        commit_sync: impl FnOnce(&Self) -> Result<(), Error>,
    ) -> Result<Enrollment, Error> {
        lease.revalidate().map_err(Error::Runtime)?;
        self.verify()?;
        require_same(
            &inspection.directory,
            &fstat(&self.directory).map_err(os_error)?,
        )
        .map_err(|_| Error::UnsafeState)?;
        let (committed, owner_pin) = self.load()?;
        if committed != inspection.committed {
            return Err(Error::RevisionConflict);
        }
        match (
            &inspection.owner_pin,
            &inspection.owner_metadata,
            &owner_pin,
        ) {
            (Some(old), Some(before), Some(current)) => {
                if !unchanged(before, &fstat(old).map_err(os_error)?)
                    || !unchanged(before, &fstat(current).map_err(os_error)?)
                {
                    return Err(Error::UnsafeState);
                }
            }
            (None, None, None) => {}
            _ => return Err(Error::UnsafeState),
        }
        if !unchanged(
            &inspection.pending_metadata,
            &fstat(&inspection.pending).map_err(os_error)?,
        ) {
            return Err(Error::UnsafeState);
        }
        let Some((_current, bytes, metadata)) = self.pending_snapshot()? else {
            return Err(Error::UnsafeState);
        };
        if !unchanged(&inspection.pending_metadata, &metadata) || inspection.bytes != bytes {
            return Err(Error::UnsafeState);
        }
        // Root is trusted. Enrollment and recovery must be serialized by the
        // service; an administrator racing this final check remains outside it.
        unlinkat(&self.directory, PENDING, AtFlags::empty()).map_err(os_error)?;
        commit_sync(self).map_err(|error| match error {
            Error::Io(kind) => Error::CommitUncertain(kind),
            other => other,
        })?;
        Ok(committed)
    }

    fn pending_snapshot(&self) -> Result<Option<(File, Vec<u8>, Stat)>, Error> {
        let pin = match openat2(
            &self.directory,
            PENDING,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            resolution(),
        ) {
            Ok(pin) => pin,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(os_error(error)),
        };
        let metadata = fstat(&pin).map_err(os_error)?;
        if metadata.st_size < 0 || metadata.st_size as u64 > RECORD_LEN as u64 {
            return Err(Error::UnsafeState);
        }
        check_file(&metadata, self.owner, metadata.st_size as u64)?;
        let fd = openat2(
            &self.directory,
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
                &named(&self.directory, PENDING).map_err(Error::Runtime)?,
            )
        {
            return Err(Error::UnsafeState);
        }
        Ok(Some((file, bytes, metadata)))
    }
}
fn authorize(lease: &RuntimeLease, peer: &UnixStream) -> Result<(), Error> {
    lease.revalidate().map_err(Error::Runtime)?;
    crate::unix::authenticate_client(peer, &OwnerPolicy { owner: None }, Access::Administer)
        .map_err(Error::Peer)?;
    Ok(())
}
fn unchanged(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_mode == b.st_mode
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_nlink == b.st_nlink
        && a.st_size == b.st_size
        && a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
        && a.st_ctime == b.st_ctime
        && a.st_ctime_nsec == b.st_ctime_nsec
}

#[cfg(test)]
mod tests;
