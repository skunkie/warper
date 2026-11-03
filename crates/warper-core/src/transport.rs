// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Production transport contracts promoted from executable networking slices.
//! No implementation or third-party packet-stack type crosses this boundary.

use crate::BackendId;
use std::{fmt, future::Future, io, net::SocketAddr, pin::Pin};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::watch,
    time::{Instant, sleep_until},
};

pub mod datagram;

pub trait TcpIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TcpIo for T {}
pub type TcpStream = Box<dyn TcpIo>;
pub type OpenTcp<'a> = Pin<Box<dyn Future<Output = Result<TcpStream, Error>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub id: u64,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub backend: BackendId,
}
pub struct CapturedTcp {
    pub metadata: Metadata,
    pub stream: TcpStream,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capabilities {
    pub ipv4: bool,
    pub ipv6: bool,
    pub tcp: bool,
    pub udp: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rejection {
    General,
    PolicyDenied,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandUnsupported,
    AddressUnsupported,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnsupportedCapability,
    UnsupportedIntegration,
    InvalidDestination,
    Cancelled,
    Timeout,
    ResourceLimit,
    Authentication,
    Protocol,
    Rejected(Rejection),
    Io(io::ErrorKind),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedCapability => {
                "UnsupportedCapability: selected backend cannot perform this operation"
            }
            Self::UnsupportedIntegration => {
                "UnsupportedIntegration: selected backend transport path is unavailable"
            }
            Self::InvalidDestination => "InvalidConfig: invalid captured destination",
            Self::Cancelled => "Cancelled: backend setup cancelled",
            Self::Timeout => "Timeout: backend setup deadline expired",
            Self::ResourceLimit => "ResourceLimit: backend admission exhausted",
            Self::Authentication => "Authentication: backend authentication failed",
            Self::Protocol => "Protocol: backend negotiation failed",
            Self::Rejected(_) => "BackendRejected: selected backend denied the connection",
            Self::Io(_) => "BackendIo: selected backend transport failed",
        })
    }
}
impl std::error::Error for Error {}

pub trait Backend: Send + Sync {
    fn id(&self) -> BackendId;
    fn capabilities(&self) -> Capabilities;
    fn open_tcp(&self, destination: SocketAddr, request: Request) -> OpenTcp<'_>;
}

/// Constructed by the service with verified physical-path protection. A backend
/// must not substitute a direct connector after any selected-transport failure.
pub trait EndpointConnector: Send + Sync {
    fn connect_tcp(&self, endpoint: SocketAddr, request: Request) -> OpenTcp<'_>;
}

#[derive(Clone)]
pub struct Request {
    pub deadline: Instant,
    pub cancellation: watch::Receiver<bool>,
}
impl Request {
    /// Dropping this future drops setup resources. No owned dial is detached.
    pub async fn run<T>(
        mut self,
        operation: impl Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        let deadline = self.deadline;
        let mut operation = std::pin::pin!(operation);
        let bounded = std::future::poll_fn(|context| {
            // Check every poll, including ready I/O resumed before the timer
            // driver observes its next tick.
            if Instant::now() >= deadline {
                std::task::Poll::Ready(Err(Error::Timeout))
            } else {
                operation.as_mut().poll(context)
            }
        });
        tokio::select! {biased;
            _=self.cancellation.wait_for(|cancelled|*cancelled)=>Err(Error::Cancelled),
            ()=sleep_until(deadline)=>Err(Error::Timeout),
            result=bounded=>result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::pending, time::Duration};

    #[tokio::test]
    async fn real_clock_expired_request_never_polls_ready_io() {
        let (_owner, cancellation) = watch::channel(false);
        for _ in 0..16 {
            let polled = std::cell::Cell::new(false);
            let request = Request {
                deadline: Instant::now(),
                cancellation: cancellation.clone(),
            };
            let result = request
                .run(async {
                    polled.set(true);
                    Ok(())
                })
                .await;
            assert_eq!(result, Err(Error::Timeout));
            assert!(
                !polled.get(),
                "expired requests must not start an I/O attempt"
            );
        }
    }

    #[test]
    fn expired_request_does_not_resume_io_before_the_timer_driver_runs() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let _entered = runtime.enter();
        let (_owner, cancellation) = watch::channel(false);
        let deadline = Instant::now() + Duration::from_millis(100);
        let polls = std::cell::Cell::new(0);
        let operation = std::future::poll_fn(|_| {
            let count = polls.get() + 1;
            polls.set(count);
            if count == 1 {
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(Ok(()))
            }
        });
        let request = Request {
            deadline,
            cancellation,
        };
        let mut future = std::pin::pin!(request.run(operation));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(future.as_mut().poll(&mut context).is_pending());
        // Synchronous manual polling intentionally leaves the Tokio timer
        // driver idle while wall time passes its registered deadline.
        std::thread::sleep(
            deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
        );
        assert_eq!(
            future.as_mut().poll(&mut context),
            std::task::Poll::Ready(Err(Error::Timeout))
        );
        assert_eq!(
            polls.get(),
            1,
            "expired I/O must not be polled a second time"
        );
    }
    #[tokio::test(start_paused = true)]
    async fn request_total_deadline_and_owner_loss_cancel_owned_work() {
        let (owner, cancellation) = watch::channel(false);
        let request = Request {
            deadline: Instant::now() + Duration::from_secs(1),
            cancellation,
        };
        assert_eq!(
            request.run(pending::<Result<(), Error>>()).await,
            Err(Error::Timeout)
        );
        let cancellation = owner.subscribe();
        drop(owner);
        let request = Request {
            deadline: Instant::now() + Duration::from_secs(1),
            cancellation,
        };
        assert_eq!(
            request.run(pending::<Result<(), Error>>()).await,
            Err(Error::Cancelled)
        );
    }
    #[tokio::test(start_paused = true)]
    async fn expired_or_cancelled_setup_never_polls_an_io_operation() {
        let polled = std::cell::Cell::new(false);
        let (_owner, cancellation) = watch::channel(false);
        let request = Request {
            deadline: Instant::now(),
            cancellation,
        };
        assert_eq!(
            request
                .run(async {
                    polled.set(true);
                    Ok(())
                })
                .await,
            Err(Error::Timeout)
        );
        assert!(!polled.get());
        let (_owner, cancellation) = watch::channel(true);
        let request = Request {
            deadline: Instant::now() + Duration::from_secs(1),
            cancellation,
        };
        assert_eq!(
            request
                .run(async {
                    polled.set(true);
                    Ok(())
                })
                .await,
            Err(Error::Cancelled)
        );
        assert!(!polled.get());
    }
}
