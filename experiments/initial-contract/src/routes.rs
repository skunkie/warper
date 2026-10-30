// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Serialized route transaction protocol with explicit uncertain outcomes.

use std::{fmt, future::Future, net::IpAddr};

use tokio::time::{Instant, timeout_at};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationId(pub u64);

pub use warper_core::BackendId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Route {
    pub address: IpAddr,
    pub prefix_len: u8,
    pub backend: BackendId,
}

impl Route {
    fn valid(self) -> bool {
        match self.address {
            IpAddr::V4(address) if self.prefix_len <= 32 => {
                let host_bits = 32 - self.prefix_len;
                host_bits == 0 || u32::from(address) & (u32::MAX >> self.prefix_len) == 0
            }
            IpAddr::V6(address) if self.prefix_len <= 128 => {
                let host_bits = 128 - self.prefix_len;
                host_bits == 0 || u128::from(address) & (u128::MAX >> self.prefix_len) == 0
            }
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Absent,
    Prepared,
    MappingPublished,
    KernelAcknowledged,
    Committed,
    Retiring,
    RecoveryRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidPrefix,
    InvalidTransition,
    WrongOperation,
    Timeout,
    Conflict,
    Cancelled,
    ResourceLimit,
    RecoveryRequired,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "route contract: {self:?}")
    }
}

impl std::error::Error for Error {}

/// Acknowledgement of the requested mutation, not acceptance into a queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ack {
    Applied,
    Rejected,
    Uncertain,
}

/// Reconciliation must compare the full platform identity and ownership mark.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observed {
    Absent,
    Owned,
    Foreign,
}

/// Commands are completed serially by the supervisor with a bounded deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    PersistIntent,
    PublishMapping,
    Install,
    PersistOwnership,
    Inspect,
    Remove,
    WithdrawMapping,
    Finish,
}

/// The driver owns journaling and platform calls. Install/remove must compare
/// exact owned interface/prefix identity, and inspect must never infer ownership
/// from address equality. Implementations perform nonblocking bounded I/O.
pub trait Driver: Send {
    fn execute(
        &mut self,
        operation: OperationId,
        route: Route,
        command: Command,
    ) -> impl Future<Output = Ack> + Send;
    fn inspect(
        &mut self,
        operation: OperationId,
        route: Route,
    ) -> impl Future<Output = Observed> + Send;
}

/// One prefix operation. The service retains this even after its caller leaves.
///
/// Platform I/O stays outside this value. A flow reference can arrive after
/// mapping publication, including while installation is awaiting an ACK.
#[derive(Debug)]
pub struct Transaction {
    operation: OperationId,
    route: Route,
    state: State,
    command: Command,
    flows: usize,
    cancelled: bool,
    owned: bool,
    published: bool,
}

impl Transaction {
    pub fn new(operation: OperationId, route: Route) -> Result<Self, Error> {
        if !route.valid() {
            return Err(Error::InvalidPrefix);
        }
        Ok(Self {
            operation,
            route,
            state: State::Absent,
            command: Command::PersistIntent,
            flows: 0,
            cancelled: false,
            owned: false,
            published: false,
        })
    }

    /// Report completion only for the exact outstanding command and operation.
    /// Failed persistence/publication cannot authorize an external mutation.
    pub fn complete(
        &mut self,
        operation: OperationId,
        command: Command,
        ack: Ack,
    ) -> Result<Command, Error> {
        if operation != self.operation {
            return Err(Error::WrongOperation);
        }
        if command != self.command || matches!(command, Command::Inspect | Command::Finish) {
            return Err(Error::InvalidTransition);
        }
        if ack != Ack::Applied {
            if (command == Command::Install && ack == Ack::Uncertain) || command == Command::Remove
            {
                self.state = State::RecoveryRequired;
                self.command = Command::Inspect;
            } else if command == Command::WithdrawMapping {
                self.state = State::RecoveryRequired;
                // Do not pretend that a failed handler withdrawal completed.
            } else {
                if command == Command::PublishMapping && ack == Ack::Uncertain {
                    self.published = true;
                }
                self.cancelled = true;
                self.retire();
            }
            return Ok(self.command);
        }
        match command {
            Command::PersistIntent => {
                self.state = State::Prepared;
                if self.cancelled {
                    self.retire();
                } else {
                    self.command = Command::PublishMapping;
                }
            }
            Command::PublishMapping => {
                self.published = true;
                self.state = State::MappingPublished;
                if self.cancelled {
                    self.retire();
                } else {
                    self.command = Command::Install;
                }
            }
            Command::Install => {
                self.owned = true;
                self.state = State::KernelAcknowledged;
                if self.cancelled {
                    self.retire();
                } else {
                    self.command = Command::PersistOwnership;
                }
            }
            Command::PersistOwnership => {
                if self.cancelled {
                    self.retire();
                } else {
                    self.state = State::Committed;
                    self.command = Command::Finish;
                }
            }
            Command::Remove => {
                self.owned = false;
                self.command = Command::WithdrawMapping;
            }
            Command::WithdrawMapping => {
                self.published = false;
                self.state = State::Absent;
                self.command = Command::Finish;
            }
            Command::Inspect | Command::Finish => return Err(Error::InvalidTransition),
        }
        Ok(self.command)
    }

    /// Execute one retained operation. A timeout cannot prove a kernel mutation
    /// failed; its outcome is reconciled before cleanup or further publication.
    pub async fn advance_driver(
        &mut self,
        driver: &mut impl Driver,
        deadline: Instant,
    ) -> Result<Command, Error> {
        let command = self.command;
        if command == Command::Finish {
            return Ok(command);
        }
        if deadline <= Instant::now() {
            return Err(Error::Timeout);
        }
        if command == Command::Inspect {
            let observed = timeout_at(deadline, driver.inspect(self.operation, self.route))
                .await
                .map_err(|_| Error::RecoveryRequired)?;
            return self.reconcile(self.operation, observed);
        }
        let ack = timeout_at(
            deadline,
            driver.execute(self.operation, self.route, command),
        )
        .await
        .unwrap_or(Ack::Uncertain);
        self.complete(self.operation, command, ack)
    }

    pub fn reconcile(
        &mut self,
        operation: OperationId,
        observed: Observed,
    ) -> Result<Command, Error> {
        if operation != self.operation {
            return Err(Error::WrongOperation);
        }
        if self.command != Command::Inspect {
            return Err(Error::InvalidTransition);
        }
        self.cancelled = true;
        match observed {
            Observed::Foreign => {
                // Preserve a changed/foreign route and the diagnostic mapping.
                self.state = State::RecoveryRequired;
                return Err(Error::Conflict);
            }
            Observed::Owned => self.owned = true,
            Observed::Absent => self.owned = false,
        }
        self.retire();
        Ok(self.command)
    }

    /// Caller cancellation never abandons an outstanding kernel operation.
    pub fn cancel(&mut self) {
        self.cancelled = true;
        if self.command == Command::Finish {
            self.retire();
        }
    }

    pub fn acquire_flow(&mut self) -> Result<(), Error> {
        if !self.published
            || self.cancelled
            || !matches!(
                self.state,
                State::MappingPublished | State::KernelAcknowledged | State::Committed
            )
        {
            return Err(Error::Cancelled);
        }
        self.flows = self.flows.checked_add(1).ok_or(Error::ResourceLimit)?;
        Ok(())
    }

    pub fn release_flow(&mut self) -> Result<Command, Error> {
        self.flows = self.flows.checked_sub(1).ok_or(Error::InvalidTransition)?;
        if self.cancelled && self.command == Command::Finish {
            self.retire();
        }
        Ok(self.command)
    }

    pub fn state(&self) -> State {
        self.state
    }
    pub fn command(&self) -> Command {
        self.command
    }
    pub fn route(&self) -> Route {
        self.route
    }
    pub fn can_release_answer(&self) -> bool {
        self.state == State::Committed && !self.cancelled
    }

    fn retire(&mut self) {
        self.state = State::Retiring;
        self.command = if self.flows != 0 {
            Command::Finish
        } else if self.owned {
            Command::Remove
        } else if self.published {
            Command::WithdrawMapping
        } else {
            self.state = State::Absent;
            Command::Finish
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transaction() -> Transaction {
        Transaction::new(
            OperationId(1),
            Route {
                address: "192.0.2.1".parse().unwrap(),
                prefix_len: 32,
                backend: BackendId(1),
            },
        )
        .unwrap()
    }

    fn applied(transaction: &mut Transaction) -> Command {
        transaction
            .complete(OperationId(1), transaction.command(), Ack::Applied)
            .unwrap()
    }

    #[test]
    fn prefixes_are_validated_before_any_mutation() {
        for (address, prefix_len, valid) in [
            ("192.0.2.0", 24, true),
            ("192.0.2.1", 24, false),
            ("0.0.0.0", 0, true),
            ("192.0.2.1", 0, false),
            ("192.0.2.1", 33, false),
            ("2001:db8::", 64, true),
            ("2001:db8::1", 64, false),
            ("::", 0, true),
            ("2001:db8::1", 129, false),
            ("2001:db8::1", 128, true),
        ] {
            let result = Transaction::new(
                OperationId(1),
                Route {
                    address: address.parse().unwrap(),
                    prefix_len,
                    backend: BackendId(1),
                },
            );
            assert_eq!(result.is_ok(), valid, "{address}/{prefix_len}");
            if let Err(error) = result {
                assert_eq!(error, Error::InvalidPrefix);
            }
        }
    }

    struct FakeDriver {
        observed: Observed,
        commands: Vec<Command>,
        uncertain_install: bool,
    }

    impl Driver for FakeDriver {
        async fn execute(
            &mut self,
            _operation: OperationId,
            _route: Route,
            command: Command,
        ) -> Ack {
            self.commands.push(command);
            match command {
                Command::Install => {
                    self.observed = Observed::Owned;
                    if self.uncertain_install {
                        // Kernel mutation happened but the acknowledgement is lost.
                        std::future::pending().await
                    } else {
                        Ack::Applied
                    }
                }
                Command::Remove => {
                    if self.observed == Observed::Foreign {
                        return Ack::Rejected;
                    }
                    self.observed = Observed::Absent;
                    Ack::Applied
                }
                _ => Ack::Applied,
            }
        }

        async fn inspect(&mut self, _operation: OperationId, _route: Route) -> Observed {
            self.observed
        }
    }

    #[tokio::test(start_paused = true)]
    async fn expired_deadline_rejects_a_driver_command_before_mutation() {
        let mut transaction = transaction();
        let mut driver = FakeDriver {
            observed: Observed::Absent,
            commands: Vec::new(),
            uncertain_install: false,
        };
        assert_eq!(
            transaction
                .advance_driver(&mut driver, Instant::now())
                .await,
            Err(Error::Timeout)
        );
        assert!(driver.commands.is_empty());
        assert_eq!(transaction.state(), State::Absent);
        assert_eq!(transaction.command(), Command::PersistIntent);
    }

    #[tokio::test(start_paused = true)]
    async fn driver_timeout_reconciles_actual_mutation_before_rollback() {
        let mut transaction = transaction();
        let mut driver = FakeDriver {
            observed: Observed::Absent,
            commands: Vec::new(),
            uncertain_install: true,
        };
        for _ in 0..3 {
            transaction
                .advance_driver(
                    &mut driver,
                    Instant::now() + std::time::Duration::from_secs(1),
                )
                .await
                .unwrap();
            assert!(!transaction.can_release_answer());
        }
        assert_eq!(driver.observed, Observed::Owned);
        assert_eq!(transaction.command(), Command::Inspect);
        while transaction.command() != Command::Finish {
            transaction
                .advance_driver(
                    &mut driver,
                    Instant::now() + std::time::Duration::from_secs(1),
                )
                .await
                .unwrap();
        }
        assert_eq!(driver.observed, Observed::Absent);
        assert_eq!(
            driver.commands,
            [
                Command::PersistIntent,
                Command::PublishMapping,
                Command::Install,
                Command::Remove,
                Command::WithdrawMapping
            ]
        );
    }

    #[test]
    fn cancellation_at_every_ack_boundary_prevents_late_commit() {
        for completed in 0..4 {
            let mut transaction = transaction();
            for _ in 0..completed {
                applied(&mut transaction);
            }
            transaction.cancel();
            if transaction.command() != Command::Finish {
                applied(&mut transaction);
            }
            assert!(!transaction.can_release_answer());
            while transaction.command() != Command::Finish {
                applied(&mut transaction);
            }
            assert_eq!(transaction.state(), State::Absent, "boundary {completed}");
        }
    }

    #[test]
    fn delayed_ack_and_durable_ownership_gate_publication() {
        let mut transaction = transaction();
        assert!(!transaction.can_release_answer());
        assert_eq!(applied(&mut transaction), Command::PublishMapping);
        assert_eq!(applied(&mut transaction), Command::Install);
        assert!(
            !transaction.can_release_answer(),
            "queued install is not an acknowledgement"
        );
        assert_eq!(
            transaction.complete(OperationId(2), Command::Install, Ack::Applied),
            Err(Error::WrongOperation)
        );
        assert_eq!(applied(&mut transaction), Command::PersistOwnership);
        assert!(
            !transaction.can_release_answer(),
            "ACK still needs durable ownership"
        );
        assert_eq!(applied(&mut transaction), Command::Finish);
        assert!(transaction.can_release_answer());
    }

    #[test]
    fn uncertain_ack_requires_inspection_and_preserves_foreign_state() {
        for observed in [Observed::Absent, Observed::Owned, Observed::Foreign] {
            let mut transaction = transaction();
            applied(&mut transaction);
            applied(&mut transaction);
            assert_eq!(
                transaction.complete(OperationId(1), Command::Install, Ack::Uncertain),
                Ok(Command::Inspect)
            );
            assert!(!transaction.can_release_answer());
            let expected = match observed {
                Observed::Absent => Ok(Command::WithdrawMapping),
                Observed::Owned => Ok(Command::Remove),
                Observed::Foreign => Err(Error::Conflict),
            };
            assert_eq!(transaction.reconcile(OperationId(1), observed), expected);
            assert!(!transaction.can_release_answer());
        }
    }

    #[test]
    fn cancelled_install_keeps_admitted_flow_until_release() {
        let mut transaction = transaction();
        applied(&mut transaction);
        applied(&mut transaction);
        transaction.acquire_flow().unwrap();
        transaction.cancel();
        assert_eq!(transaction.command(), Command::Install);
        assert_eq!(applied(&mut transaction), Command::Finish);
        assert_eq!(transaction.state(), State::Retiring);
        assert!(!transaction.can_release_answer());
        assert_eq!(transaction.acquire_flow(), Err(Error::Cancelled));
        assert_eq!(transaction.release_flow(), Ok(Command::Remove));
        assert_eq!(applied(&mut transaction), Command::WithdrawMapping);
        assert_eq!(applied(&mut transaction), Command::Finish);
        assert_eq!(transaction.state(), State::Absent);
        assert_eq!(transaction.release_flow(), Err(Error::InvalidTransition));
    }

    #[test]
    fn partial_rollback_retains_failed_removal_for_recovery() {
        let mut transactions = [transaction(), transaction()];
        for transaction in &mut transactions {
            for _ in 0..4 {
                applied(transaction);
            }
            transaction.cancel();
            assert_eq!(transaction.command(), Command::Remove);
        }
        applied(&mut transactions[0]);
        applied(&mut transactions[0]);
        assert_eq!(
            transactions[1].complete(OperationId(1), Command::Remove, Ack::Rejected),
            Ok(Command::Inspect)
        );
        assert_eq!(transactions[0].state(), State::Absent);
        assert_eq!(transactions[1].state(), State::RecoveryRequired);
        assert_eq!(
            transactions[1].reconcile(OperationId(1), Observed::Owned),
            Ok(Command::Remove)
        );
        applied(&mut transactions[1]);
        applied(&mut transactions[1]);
        assert_eq!(transactions[1].state(), State::Absent);
    }

    #[test]
    fn persistence_and_publication_failures_never_install_a_route() {
        for completed in 0..4 {
            let mut transaction = transaction();
            for _ in 0..completed {
                applied(&mut transaction);
            }
            let command = transaction.command();
            transaction
                .complete(OperationId(1), command, Ack::Rejected)
                .unwrap();
            assert!(!transaction.can_release_answer());
            assert_ne!(transaction.command(), Command::Install);
            assert_ne!(transaction.command(), Command::PersistOwnership);
            while transaction.command() != Command::Finish {
                applied(&mut transaction);
            }
            assert_eq!(transaction.state(), State::Absent);
        }
    }
}
