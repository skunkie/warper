// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Server-side TCP framing with retained offsets and original operation limits.

use std::{fmt, io, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use warper_core::transport::{Error as RequestError, Request};

use super::{Limits, Packet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidState,
    InvalidRequest,
    InvalidLength,
    ResourceLimit,
    Closed,
    UnexpectedEof,
    WaitCancelled,
    WaitDeadline,
    Operation(RequestError),
    Packet(super::Error),
    Io(io::ErrorKind),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidState => {
                "Conflict: DNS stream already owns an operation or has no result to join"
            }
            Self::InvalidRequest => "InvalidConfig: invalid DNS stream operation",
            Self::InvalidLength => "DnsProtocol: invalid DNS TCP frame length",
            Self::ResourceLimit => "ResourceLimit: DNS TCP frame admission exhausted",
            Self::Closed => "Cancelled: DNS TCP connection ended",
            Self::UnexpectedEof => "DnsProtocol: DNS TCP frame ended early",
            Self::WaitCancelled => "Cancelled: DNS TCP observation ended",
            Self::WaitDeadline => "Timeout: DNS TCP observation ended",
            Self::Operation(RequestError::Cancelled) => "Cancelled: DNS TCP operation ended",
            Self::Operation(RequestError::Timeout) => "Timeout: DNS TCP operation ended",
            Self::Operation(_) => "WorkerFailed: DNS TCP operation failed",
            Self::Packet(_) => "DnsProtocol: DNS TCP packet validation failed",
            Self::Io(_) => "NativeIo: DNS TCP stream failed",
        })
    }
}
impl std::error::Error for Error {}

pub enum Completion {
    Query(Box<Packet>),
    End,
    /// Stream acceptance only. This is never a native delivery receipt.
    Written,
}

enum Work {
    Read {
        prefix: [u8; 2],
        prefix_read: usize,
        body: Vec<u8>,
        body_read: usize,
    },
    Write {
        bytes: Vec<u8>,
        written: usize,
    },
}

#[must_use = "retain the connection through accepted I/O and supervised cleanup"]
pub struct Connection<S> {
    stream: S,
    limits: Limits,
    operation: Option<Request>,
    work: Option<Work>,
    terminal: Option<Error>,
}
impl<S: AsyncRead + AsyncWrite + Unpin> Connection<S> {
    pub fn new(stream: S, limits: Limits) -> Self {
        Self {
            stream,
            limits,
            operation: None,
            work: None,
            terminal: None,
        }
    }

    pub fn begin_read(&mut self, operation: Request) -> Result<(), Error> {
        self.admit(&operation)?;
        self.work = Some(Work::Read {
            prefix: [0; 2],
            prefix_read: 0,
            body: Vec::new(),
            body_read: 0,
        });
        self.operation = Some(operation);
        Ok(())
    }

    pub fn begin_reply(&mut self, packet: &Packet, operation: Request) -> Result<(), Error> {
        self.admit(&operation)?;
        if !packet.is_response() {
            return Err(Error::InvalidRequest);
        }
        let mut bytes = packet.encode().map_err(Error::Packet)?;
        let length = bytes.len();
        if length > self.limits.wire_bytes() {
            return Err(Error::ResourceLimit);
        }
        bytes
            .try_reserve_exact(2)
            .map_err(|_| Error::ResourceLimit)?;
        bytes.resize(length + 2, 0);
        bytes.copy_within(..length, 2);
        bytes[..2].copy_from_slice(&(length as u16).to_be_bytes());
        self.work = Some(Work::Write { bytes, written: 0 });
        self.operation = Some(operation);
        Ok(())
    }

    /// Observation can be dropped and resumed. Terminal original-operation
    /// errors forbid stream reuse because bytes may already have crossed it.
    pub async fn wait(&mut self, observer: Request) -> Result<Completion, Error> {
        if let Some(error) = self.terminal {
            return Err(error);
        }
        let operation = self.operation.clone().ok_or(Error::InvalidState)?;
        let result = observer
            .run(async { Ok(operation.run(async { Ok(self.transfer().await) }).await) })
            .await;
        let result = match result {
            Err(RequestError::Cancelled) => return Err(Error::WaitCancelled),
            Err(RequestError::Timeout) => return Err(Error::WaitDeadline),
            Err(error) => return Err(Error::Operation(error)),
            Ok(Err(error)) => Err(Error::Operation(error)),
            Ok(Ok(result)) => result,
        };
        self.operation = None;
        self.work = None;
        match result {
            Ok(Completion::End) => {
                self.terminal = Some(Error::Closed);
                Ok(Completion::End)
            }
            Ok(completion) => Ok(completion),
            Err(error) => {
                self.terminal = Some(error);
                Err(error)
            }
        }
    }

    fn admit(&self, operation: &Request) -> Result<(), Error> {
        if let Some(error) = self.terminal {
            return Err(error);
        }
        if self.work.is_some() {
            return Err(Error::InvalidState);
        }
        if *operation.cancellation.borrow() || operation.cancellation.has_changed().is_err() {
            return Err(Error::Operation(RequestError::Cancelled));
        }
        let now = Instant::now();
        if operation.deadline <= now {
            return Err(Error::Operation(RequestError::Timeout));
        }
        if operation.deadline.duration_since(now) > Duration::from_secs(30) {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }

    async fn transfer(&mut self) -> Result<Completion, Error> {
        match self.work.as_mut().ok_or(Error::InvalidState)? {
            Work::Read {
                prefix,
                prefix_read,
                body,
                body_read,
            } => {
                while *prefix_read < prefix.len() {
                    let read = self
                        .stream
                        .read(&mut prefix[*prefix_read..])
                        .await
                        .map_err(|error| Error::Io(error.kind()))?;
                    if read == 0 {
                        return if *prefix_read == 0 {
                            Ok(Completion::End)
                        } else {
                            Err(Error::UnexpectedEof)
                        };
                    }
                    *prefix_read += read;
                }
                let length = usize::from(u16::from_be_bytes(*prefix));
                if length < 12 {
                    return Err(Error::InvalidLength);
                }
                if length > self.limits.wire_bytes() {
                    return Err(Error::ResourceLimit);
                }
                if body.is_empty() {
                    body.try_reserve_exact(length)
                        .map_err(|_| Error::ResourceLimit)?;
                    body.resize(length, 0);
                }
                while *body_read < body.len() {
                    let read = self
                        .stream
                        .read(&mut body[*body_read..])
                        .await
                        .map_err(|error| Error::Io(error.kind()))?;
                    if read == 0 {
                        return Err(Error::UnexpectedEof);
                    }
                    *body_read += read;
                }
                Packet::request(body, self.limits)
                    .map(|packet| Completion::Query(Box::new(packet)))
                    .map_err(Error::Packet)
            }
            Work::Write { bytes, written } => {
                while *written < bytes.len() {
                    let count = self
                        .stream
                        .write(&bytes[*written..])
                        .await
                        .map_err(|error| Error::Io(error.kind()))?;
                    if count == 0 {
                        return Err(Error::Io(io::ErrorKind::WriteZero));
                    }
                    *written += count;
                }
                Ok(Completion::Written)
            }
        }
    }
}

#[cfg(test)]
mod tests;
