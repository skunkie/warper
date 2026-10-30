// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Unix account lookup behind the backend-independent configuration interface.

use nix::unistd::{Uid, User, geteuid};
use warper_core::configuration::paths::{Account, Error, IdentityProvider};

/// Uses reentrant OS account lookup, without consulting HOME or sudo variables.
///
/// This synchronous adapter may block inside the system account database (NSS
/// on Linux). Call it on the ordinary-user client's blocking worker, never on
/// an asynchronous networking executor. The OS lookup is not cancellable;
/// bounding client concurrency must not imply that a timed-out worker stopped.
/// Installed-service startup must not use invoking-user configuration discovery.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnixIdentity;

impl IdentityProvider for UnixIdentity {
    fn effective_uid(&self) -> u32 {
        geteuid().as_raw()
    }

    fn account_by_uid(&self, uid: u32) -> Result<Account, Error> {
        let result = User::from_uid(Uid::from_raw(uid)).map(|user| {
            user.map(|user| Account {
                uid: user.uid.as_raw(),
                name: user.name,
                home: user.dir,
            })
        });
        required_account(result)
    }
}

fn required_account(result: nix::Result<Option<Account>>) -> Result<Account, Error> {
    result
        .map_err(|_| Error::IdentityLookup)?
        .ok_or(Error::IdentityLookup)
}

#[cfg(test)]
mod tests {
    use nix::errno::Errno;

    use super::*;

    #[test]
    fn lookup_preserves_records_and_fails_closed_on_missing_or_failed_lookup() {
        let account = Account {
            uid: 1234,
            name: "sample".into(),
            home: "/home/sample".into(),
        };
        assert_eq!(required_account(Ok(Some(account.clone()))), Ok(account));
        assert_eq!(required_account(Ok(None)), Err(Error::IdentityLookup));
        for error in [Errno::EIO, Errno::ERANGE, Errno::EINTR] {
            assert_eq!(required_account(Err(error)), Err(Error::IdentityLookup));
        }
    }
}
