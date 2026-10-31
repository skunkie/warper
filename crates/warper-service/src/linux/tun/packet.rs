// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! One bounded packet port sharing only the originally owned TUN descriptor.

use super::{Context, MTU};
use std::{
    fmt,
    future::Future,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tun_rs::AsyncDevice;
use warper_core::transport::Request;

pub const BUFFER_BYTES: usize = MTU as usize + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidPacket,
    Busy,
    Cancelled,
    Deadline,
    Closed,
    Oversized,
    PartialWrite,
    Io(io::ErrorKind),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPacket => "InvalidPacket: native packet length is outside the MTU",
            Self::Busy => "ResourceLimit: native packet direction is already in use",
            Self::Cancelled => "Cancelled: native packet operation cancelled",
            Self::Deadline => "Timeout: native packet deadline expired",
            Self::Closed => "NativeIo: native packet device closed",
            Self::Oversized => "InvalidPacket: native packet exceeds the MTU",
            Self::PartialWrite => "NativeUncertain: native packet write was incomplete",
            Self::Io(_) => "NativeIo: native packet operation failed",
        })
    }
}
impl std::error::Error for Error {}

/// No cloning, reconfiguration or raw-descriptor access. The caller retains and
/// joins packet tasks and drops this port before explicit owner retirement.
pub struct PacketPort {
    // The descriptor reference must drop before the final native runtime pin.
    device: Arc<AsyncDevice>,
    receiving: Direction,
    sending: Direction,
    _context: Arc<Context>,
}
impl PacketPort {
    pub(super) fn new(device: Arc<AsyncDevice>, context: Arc<Context>) -> Self {
        Self {
            device,
            receiving: Direction::default(),
            sending: Direction::default(),
            _context: context,
        }
    }
    pub async fn recv(
        &self,
        buffer: &mut [u8; BUFFER_BYTES],
        request: Request,
    ) -> Result<usize, Error> {
        received(
            self.receiving
                .run(request, self.device.recv(buffer))
                .await?,
        )
    }
    pub async fn send(&self, packet: &[u8], request: Request) -> Result<(), Error> {
        validate_length(packet.len())?;
        let written = self.sending.run(request, self.device.send(packet)).await?;
        written_packet(written, packet.len())
    }
}
impl fmt::Debug for PacketPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PacketPort(<redacted>)")
    }
}

#[derive(Default)]
struct Direction(AtomicBool);
impl Direction {
    async fn run(
        &self,
        mut request: Request,
        io: impl Future<Output = io::Result<usize>>,
    ) -> Result<usize, Error> {
        self.0
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Error::Busy)?;
        let _reservation = Reservation(self);
        tokio::select! {biased;
            _=request.cancellation.wait_for(|cancelled|*cancelled)=>Err(Error::Cancelled),
            ()=tokio::time::sleep_until(request.deadline)=>Err(Error::Deadline),
            result=io=>result.map_err(|error|Error::Io(error.kind())),
        }
    }
}
struct Reservation<'a>(&'a Direction);
impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        self.0.0.store(false, Ordering::Release);
    }
}
fn validate_length(length: usize) -> Result<(), Error> {
    if length == 0 || length > MTU as usize {
        Err(Error::InvalidPacket)
    } else {
        Ok(())
    }
}
fn received(length: usize) -> Result<usize, Error> {
    match length {
        0 => Err(Error::Closed),
        length if length > MTU as usize => Err(Error::Oversized),
        length => Ok(length),
    }
}
fn written_packet(actual: usize, expected: usize) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::PartialWrite)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::pending, time::Duration};
    use tokio::{sync::watch, time::Instant};
    fn request(owner: &watch::Sender<bool>) -> Request {
        Request {
            deadline: Instant::now() + Duration::from_secs(1),
            cancellation: owner.subscribe(),
        }
    }
    #[tokio::test(start_paused = true)]
    async fn cancellation_deadline_and_drop_release_direction_without_polling_late_io() {
        let direction = Direction::default();
        let (owner, _) = watch::channel(false);
        assert_eq!(
            direction.run(request(&owner), pending()).await,
            Err(Error::Deadline)
        );
        owner.send_replace(true);
        assert_eq!(
            direction
                .run(request(&owner), async {
                    panic!("cancelled I/O must not be polled")
                })
                .await,
            Err(Error::Cancelled)
        );
        owner.send_replace(false);
        tokio::select! {biased;
            result=direction.run(request(&owner), pending())=>panic!("pending direction completed: {result:?}"),
            result=direction.run(request(&owner), async { Ok(1) })=>assert_eq!(result, Err(Error::Busy)),
        }
        assert_eq!(direction.run(request(&owner), async { Ok(1) }).await, Ok(1));
        assert_eq!(
            direction
                .run(request(&owner), async {
                    Err(io::ErrorKind::BrokenPipe.into())
                })
                .await,
            Err(Error::Io(io::ErrorKind::BrokenPipe))
        );
        assert_eq!(direction.run(request(&owner), async { Ok(1) }).await, Ok(1));
        let closed = request(&owner);
        drop(owner);
        assert_eq!(
            direction.run(closed, pending()).await,
            Err(Error::Cancelled)
        );
    }
    #[test]
    fn packet_boundaries_and_partial_writes_are_explicit_failures() {
        assert_eq!(validate_length(0), Err(Error::InvalidPacket));
        assert_eq!(validate_length(BUFFER_BYTES), Err(Error::InvalidPacket));
        assert_eq!(validate_length(MTU as usize), Ok(()));
        assert_eq!(received(0), Err(Error::Closed));
        assert_eq!(received(BUFFER_BYTES), Err(Error::Oversized));
        assert_eq!(received(MTU as usize), Ok(MTU as usize));
        assert_eq!(written_packet(1279, 1280), Err(Error::PartialWrite));
        assert_eq!(written_packet(1280, 1280), Ok(()));
    }
}
