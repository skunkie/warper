// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Joined packet directions. Native route and flow lifetimes belong to the supervisor.

use std::{fmt, future::Future, sync::Arc, time::Duration};
use tokio::{sync::watch, time::Instant};
use warper_core::transport::Request;
use warper_stack::runtime::{self, Egress, Ingress};

use super::tun::{BUFFER_BYTES, PacketError, PacketPort};

const READ_WAIT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidDeadline,
    CancellationOwnerLost,
    Input(runtime::Error),
    OutputClosed,
    Native(PacketError),
}
impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDeadline => {
                formatter.write_str("InvalidConfig: invalid packet write deadline")
            }
            Self::CancellationOwnerLost => {
                formatter.write_str("Cancelled: packet supervisor disappeared")
            }
            Self::Input(error) => error.fmt(formatter),
            Self::OutputClosed => formatter.write_str("NativeIo: host packet output closed"),
            Self::Native(error) => error.fmt(formatter),
        }
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Report {
    pub captured_packets: u64,
    pub captured_bytes: u64,
    pub ingress_drops: u64,
    pub sent_packets: u64,
    pub sent_bytes: u64,
    pub discarded_output: u64,
    /// Bucket zero is below one microsecond; each following bound doubles.
    /// The final bucket includes all remaining durations.
    pub write_waits: [u64; 32],
}
#[derive(Debug)]
pub struct Failure {
    pub cause: Error,
    pub secondary: [Option<Error>; 2],
    pub report: Box<Report>,
}
impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.cause.fmt(formatter)
    }
}
impl std::error::Error for Failure {}

pub struct Pump {
    port: Arc<PacketPort>,
    ingress: Ingress,
    output: Egress,
    write_timeout: Duration,
}
impl Pump {
    pub fn new(
        port: Arc<PacketPort>,
        ingress: Ingress,
        output: Egress,
        write_timeout: Duration,
    ) -> Result<Self, Error> {
        validate_timeout(write_timeout)?;
        Ok(Self {
            port,
            ingress,
            output,
            write_timeout,
        })
    }

    /// Retain and join this future's owning task. Stop after route withdrawal;
    /// neither cancellation nor dropping packet ownership performs native cleanup.
    pub async fn run(self, cancellation: watch::Receiver<bool>) -> Result<Report, Failure> {
        drive(
            self.port.as_ref(),
            self.ingress,
            self.output,
            self.write_timeout,
            cancellation,
        )
        .await
    }
}
impl fmt::Debug for Pump {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PacketPump(<redacted>)")
    }
}

trait PacketIo: Sync {
    fn recv(
        &self,
        buffer: &mut [u8; BUFFER_BYTES],
        request: Request,
    ) -> impl Future<Output = Result<usize, PacketError>> + Send;
    fn send(
        &self,
        packet: &[u8],
        request: Request,
    ) -> impl Future<Output = Result<(), PacketError>> + Send;
}
impl PacketIo for PacketPort {
    async fn recv(
        &self,
        buffer: &mut [u8; BUFFER_BYTES],
        request: Request,
    ) -> Result<usize, PacketError> {
        self.recv(buffer, request).await
    }
    async fn send(&self, packet: &[u8], request: Request) -> Result<(), PacketError> {
        self.send(packet, request).await
    }
}
trait PacketOutput: Send {
    fn recv(&mut self) -> impl Future<Output = Option<Vec<u8>>> + Send;
}
impl PacketOutput for Egress {
    async fn recv(&mut self) -> Option<Vec<u8>> {
        self.recv().await
    }
}

async fn drive(
    port: &impl PacketIo,
    ingress: Ingress,
    output: impl PacketOutput,
    write_timeout: Duration,
    mut cancellation: watch::Receiver<bool>,
) -> Result<Report, Failure> {
    let (stop, _) = watch::channel(false);
    let mut input_report = Report::default();
    let mut output_report = Report::default();
    enum End {
        Stop(bool),
        Read(Result<(), Error>),
        Write(Result<(), Error>),
    }
    let (cause, secondary) = {
        let reader = read(port, ingress, stop.subscribe(), &mut input_report);
        let writer = write(
            port,
            output,
            write_timeout,
            stop.subscribe(),
            &mut output_report,
        );
        tokio::pin!(reader, writer);
        let first = tokio::select! { biased;
            lost = cancelled(&mut cancellation) => End::Stop(lost),
            result = &mut reader => End::Read(result),
            result = &mut writer => End::Write(result),
        };
        stop.send_replace(true);
        match first {
            End::Stop(lost) => {
                let (read, write) = tokio::join!(reader, writer);
                let primary = if lost {
                    Some(Error::CancellationOwnerLost)
                } else {
                    None
                };
                errors(primary, read.err(), write.err())
            }
            End::Read(result) => errors(result.err(), writer.await.err(), None),
            End::Write(result) => errors(result.err(), reader.await.err(), None),
        }
    };
    input_report.sent_packets = output_report.sent_packets;
    input_report.sent_bytes = output_report.sent_bytes;
    input_report.discarded_output = output_report.discarded_output;
    input_report.write_waits = output_report.write_waits;
    match cause {
        Some(cause) => Err(Failure {
            cause,
            secondary,
            report: Box::new(input_report),
        }),
        None => Ok(input_report),
    }
}
fn errors(
    first: Option<Error>,
    second: Option<Error>,
    third: Option<Error>,
) -> (Option<Error>, [Option<Error>; 2]) {
    let mut errors = [first, second, third].into_iter().flatten();
    (errors.next(), [errors.next(), errors.next()])
}
fn validate_timeout(timeout: Duration) -> Result<(), Error> {
    if timeout.is_zero() || timeout > READ_WAIT {
        Err(Error::InvalidDeadline)
    } else {
        Ok(())
    }
}
async fn read(
    port: &impl PacketIo,
    ingress: Ingress,
    cancellation: watch::Receiver<bool>,
    report: &mut Report,
) -> Result<(), Error> {
    let mut buffer = [0; BUFFER_BYTES];
    let mut batch = 0;
    loop {
        let request = Request {
            deadline: Instant::now() + READ_WAIT,
            cancellation: cancellation.clone(),
        };
        match port.recv(&mut buffer, request).await {
            Ok(length) => {
                // Keep the boundary checked even for internal test adapters.
                if length == 0 || length >= BUFFER_BYTES {
                    return Err(Error::Native(PacketError::InvalidPacket));
                }
                report.captured_packets = report.captured_packets.saturating_add(1);
                report.captured_bytes = report.captured_bytes.saturating_add(length as u64);
                match ingress.try_inject(&buffer[..length]) {
                    Ok(()) => {}
                    Err(runtime::Error::QueueFull) => {
                        report.ingress_drops = report.ingress_drops.saturating_add(1)
                    }
                    Err(error) => return Err(Error::Input(error)),
                }
            }
            Err(PacketError::Deadline) => {}
            Err(PacketError::Cancelled) => return Ok(()),
            Err(error) => return Err(Error::Native(error)),
        }
        batch += 1;
        if batch == 8 {
            batch = 0;
            tokio::task::yield_now().await;
        }
    }
}
async fn write(
    port: &impl PacketIo,
    mut output: impl PacketOutput,
    write_timeout: Duration,
    mut cancellation: watch::Receiver<bool>,
    report: &mut Report,
) -> Result<(), Error> {
    let mut batch = 0;
    loop {
        let packet = tokio::select! { biased;
            _ = cancelled(&mut cancellation) => return Ok(()),
            packet = output.recv() => packet.ok_or(Error::OutputClosed)?,
        };
        let before = Instant::now();
        let request = Request {
            deadline: before + write_timeout,
            cancellation: cancellation.clone(),
        };
        match port.send(&packet, request).await {
            Ok(()) => {
                report.sent_packets = report.sent_packets.saturating_add(1);
                report.sent_bytes = report.sent_bytes.saturating_add(packet.len() as u64);
                let micros = before.elapsed().as_micros();
                let bucket = (128 - micros.leading_zeros()).min(31) as usize;
                report.write_waits[bucket] = report.write_waits[bucket].saturating_add(1);
            }
            Err(PacketError::Cancelled) => {
                report.discarded_output = report.discarded_output.saturating_add(1);
                return Ok(());
            }
            Err(error) => return Err(Error::Native(error)),
        }
        batch += 1;
        if batch == 8 {
            batch = 0;
            tokio::task::yield_now().await;
        }
    }
}

// Return whether the owner disappeared rather than explicitly requesting stop.
async fn cancelled(cancellation: &mut watch::Receiver<bool>) -> bool {
    loop {
        if *cancellation.borrow_and_update() {
            return false;
        }
        if cancellation.changed().await.is_err() {
            return true;
        }
    }
}

#[cfg(test)]
mod tests;
