// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Production TCP contracts promoted from the executable initial slice.
//! No implementation or third-party packet-stack type crosses this boundary.

use crate::BackendId;
use std::{fmt, future::Future, io, net::SocketAddr, pin::Pin};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::watch,
    time::{Instant, sleep_until},
};

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
        tokio::select! {biased;
            _=self.cancellation.wait_for(|cancelled|*cancelled)=>Err(Error::Cancelled),
            ()=sleep_until(self.deadline)=>Err(Error::Timeout),
            result=operation=>result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::pending, time::Duration};
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
