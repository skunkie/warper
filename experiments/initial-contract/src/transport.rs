// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Stack-independent TCP boundary and deadline/cancellation ownership.

use std::{fmt, future::Future, io, net::SocketAddr, pin::Pin};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::watch,
    time::{Instant, timeout_at},
};

use crate::routes::BackendId;

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

#[derive(Debug)]
pub enum Error {
    UnsupportedCapability,
    Cancelled,
    Timeout,
    ResourceLimit,
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Do not print peer/configuration data from an arbitrary I/O error.
        match self {
            Self::Io(error) => write!(formatter, "backend I/O: {:?}", error.kind()),
            error => write!(formatter, "backend: {error:?}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

pub trait Backend: Send + Sync {
    fn id(&self) -> BackendId;
    fn capabilities(&self) -> Capabilities;
    /// Implementations must check capabilities before performing transport I/O
    /// and bind all setup to `Request::run`. No caller retries application data.
    fn open_tcp(&self, destination: SocketAddr, request: Request) -> OpenTcp<'_>;
}

pub struct Request {
    pub deadline: Instant,
    pub cancellation: watch::Receiver<bool>,
}

impl Request {
    /// Dropping this future drops owned setup I/O; no detached dial survives.
    /// A lost cancellation owner is cancellation, never an infinite wait.
    pub async fn run<T>(
        mut self,
        operation: impl Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        if *self.cancellation.borrow() {
            return Err(Error::Cancelled);
        }
        if self.deadline <= Instant::now() {
            return Err(Error::Timeout);
        }
        tokio::select! {
            biased;
            _ = self.cancellation.wait_for(|cancelled| *cancelled) => Err(Error::Cancelled),
            result = timeout_at(self.deadline, operation) => result.map_err(|_| Error::Timeout)?,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{future::pending, time::Duration};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn setup_deadline_and_owner_loss_cancel_owned_work() {
        let (owner, cancellation) = watch::channel(false);
        let request = Request {
            deadline: Instant::now() + Duration::from_secs(1),
            cancellation,
        };
        assert!(matches!(
            request.run(pending::<Result<(), Error>>()).await,
            Err(Error::Timeout)
        ));
        let cancellation = owner.subscribe();
        drop(owner);
        let request = Request {
            deadline: Instant::now() + Duration::from_secs(1),
            cancellation,
        };
        assert!(matches!(
            request.run(pending::<Result<(), Error>>()).await,
            Err(Error::Cancelled)
        ));
    }

    #[tokio::test]
    async fn boxed_stream_preserves_request_fin_and_response_after_fin() {
        let (client, mut peer) = tokio::io::duplex(64);
        let mut client: TcpStream = Box::new(client);
        let worker = tokio::spawn(async move {
            let mut input = Vec::new();
            peer.read_to_end(&mut input).await.unwrap();
            assert_eq!(input, b"request");
            peer.write_all(b"response").await.unwrap();
            peer.shutdown().await.unwrap();
        });
        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"response");
        worker.await.unwrap();
    }
}
