// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded synchronous native query and mutation transport for retained workers.

use crate::linux::netlink::{self, MAX_DATAGRAM};
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_DUMP_INTR, NLM_F_REQUEST, NetlinkBuffer, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use std::{
    fmt, io,
    time::{Duration, Instant},
};
use warper_core::transport::Request;

const MAX_REQUEST: usize = 128;
const POLL_SLICE: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Delivery {
    NotSent,
    Rejected,
    Uncertain,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cause {
    InvalidInput,
    ResourceLimit,
    Cancelled,
    Timeout,
    Io(io::ErrorKind),
    Kernel(i32),
    Protocol,
    Lost,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    pub delivery: Delivery,
    pub cause: Cause,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SystemConfiguration: native network transaction failed")
    }
}
impl std::error::Error for Failure {}

pub(super) struct Wait {
    request: Request,
}
impl Wait {
    pub(super) fn new(request: Request) -> Result<Self, Cause> {
        if request
            .deadline
            .into_std()
            .saturating_duration_since(Instant::now())
            > Duration::from_secs(30)
        {
            return Err(Cause::InvalidInput);
        }
        let wait = Self { request };
        wait.check()?;
        Ok(wait)
    }
    pub(super) fn check(&self) -> Result<(), Cause> {
        if *self.request.cancellation.borrow() || self.request.cancellation.has_changed().is_err() {
            return Err(Cause::Cancelled);
        }
        if Instant::now() >= self.request.deadline.into_std() {
            return Err(Cause::Timeout);
        }
        Ok(())
    }
    fn poll(&self, socket: &Socket, events: PollFlags) -> Result<(), Cause> {
        self.check()?;
        let span = self
            .request
            .deadline
            .into_std()
            .saturating_duration_since(Instant::now())
            .min(POLL_SLICE);
        let timeout = Timespec::try_from(span).map_err(|_| Cause::InvalidInput)?;
        let mut descriptors = [PollFd::new(socket, events)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(io_cause(error.into())),
        }
        if descriptors[0].revents().contains(PollFlags::NVAL) {
            return Err(Cause::Protocol);
        }
        self.check()
    }
}

pub(super) fn mutate(message: RouteNetlinkMessage, flags: u16, wait: &Wait) -> Result<(), Failure> {
    let mut sent = false;
    let result = (|| {
        wait.check()?;
        let (socket, port) = socket()?;
        let sequence = sequence()?;
        let request = packet(message, NLM_F_REQUEST | NLM_F_ACK | flags, sequence, port)?;
        send(&socket, &request, wait)?;
        sent = true;
        let mut bytes = [0; MAX_DATAGRAM + 1];
        let (length, sender) = receive(&socket, &mut bytes, wait)?;
        decode_ack(&bytes[..length], sender, sequence, port, &request)
    })();
    result.map_err(|cause| Failure {
        delivery: if matches!(cause, Cause::Kernel(_)) {
            Delivery::Rejected
        } else if sent {
            Delivery::Uncertain
        } else {
            Delivery::NotSent
        },
        cause,
    })
}

pub(super) fn socket() -> Result<(Socket, u32), Cause> {
    let mut socket = Socket::new(NETLINK_ROUTE).map_err(io_cause)?;
    socket.set_non_blocking(true).map_err(io_cause)?;
    socket
        .set_rx_buf_sz(MAX_DATAGRAM as i32)
        .map_err(io_cause)?;
    if socket.get_rx_buf_sz().map_err(io_cause)? > 2 * MAX_DATAGRAM {
        return Err(Cause::ResourceLimit);
    }
    socket.set_no_enobufs(false).map_err(io_cause)?;
    socket.set_cap_ack(true).map_err(io_cause)?;
    socket.set_netlink_get_strict_chk(true).map_err(io_cause)?;
    let address = socket.bind_auto().map_err(io_cause)?;
    if address.port_number() == 0 || address.multicast_groups() != 0 {
        return Err(Cause::Protocol);
    }
    Ok((socket, address.port_number()))
}
pub(super) fn sequence() -> Result<u32, Cause> {
    netlink::sequence().map_err(|_| Cause::ResourceLimit)
}
pub(super) fn packet(
    message: RouteNetlinkMessage,
    flags: u16,
    sequence: u32,
    port: u32,
) -> Result<Vec<u8>, Cause> {
    let mut message = NetlinkMessage::from(message);
    message.header.flags = flags;
    message.header.sequence_number = sequence;
    message.header.port_number = port;
    message.finalize();
    if message.buffer_len() > MAX_REQUEST {
        return Err(Cause::ResourceLimit);
    }
    let mut bytes = vec![0; message.buffer_len()];
    message.serialize(&mut bytes);
    Ok(bytes)
}
pub(super) fn send(socket: &Socket, bytes: &[u8], wait: &Wait) -> Result<(), Cause> {
    loop {
        wait.check()?;
        match socket.send_to(bytes, &SocketAddr::new(0, 0), 0) {
            Ok(length) if length == bytes.len() => return Ok(()),
            Ok(_) => return Err(Cause::Protocol),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait.poll(socket, PollFlags::OUT)?
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(io_cause(error)),
        }
    }
}
pub(super) fn receive(
    socket: &Socket,
    buffer: &mut [u8],
    wait: &Wait,
) -> Result<(usize, SocketAddr), Cause> {
    loop {
        wait.check()?;
        let mut slice = &mut buffer[..];
        match socket.recv_from(&mut slice, 0) {
            Ok(result) => return Ok(result),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait.poll(socket, PollFlags::IN)?
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(io_cause(error)),
        }
    }
}
pub(super) fn correlate(
    message: &NetlinkMessage<RouteNetlinkMessage>,
    sequence: u32,
    port: u32,
) -> Result<(), Cause> {
    if message.header.sequence_number != sequence || message.header.port_number != port {
        return Err(Cause::Protocol);
    }
    if message.header.flags & NLM_F_DUMP_INTR != 0 {
        return Err(Cause::Lost);
    }
    Ok(())
}
pub(super) fn validate_sender(sender: SocketAddr) -> Result<(), Cause> {
    if sender.port_number() != 0 || sender.multicast_groups() != 0 {
        return Err(Cause::Protocol);
    }
    Ok(())
}
pub(super) fn decode_ack(
    bytes: &[u8],
    sender: SocketAddr,
    sequence: u32,
    port: u32,
    request: &[u8],
) -> Result<(), Cause> {
    let message = reply(bytes, sender, sequence, port)?;
    match message.payload {
        NetlinkPayload::Error(error) => {
            if error.header.get(..16) != request.get(..16) || request.len() < 16 {
                return Err(Cause::Protocol);
            }
            match error.raw_code() {
                0 => Ok(()),
                code if code < 0 && code != i32::MIN => Err(Cause::Kernel(-code)),
                _ => Err(Cause::Protocol),
            }
        }
        NetlinkPayload::Overrun(_) => Err(Cause::Lost),
        _ => Err(Cause::Protocol),
    }
}
fn reply(
    bytes: &[u8],
    sender: SocketAddr,
    sequence: u32,
    port: u32,
) -> Result<NetlinkMessage<RouteNetlinkMessage>, Cause> {
    validate_sender(sender)?;
    if bytes.len() > MAX_DATAGRAM {
        return Err(Cause::Lost);
    }
    let envelope = NetlinkBuffer::new_checked(bytes).map_err(|_| Cause::Protocol)?;
    if envelope.length() as usize != bytes.len() {
        return Err(Cause::Protocol);
    }
    let message =
        NetlinkMessage::<RouteNetlinkMessage>::deserialize(bytes).map_err(|_| Cause::Protocol)?;
    correlate(&message, sequence, port)?;
    if message.header.flags & netlink_packet_core::NLM_F_MULTIPART != 0 {
        return Err(Cause::Protocol);
    }
    Ok(message)
}

fn io_cause(error: io::Error) -> Cause {
    if error.raw_os_error() == Some(nix::libc::ENOBUFS) {
        Cause::Lost
    } else {
        Cause::Io(error.kind())
    }
}

/// One correlated unicast reply; no multipart query or mutation is accepted.
pub(super) fn query(
    message: RouteNetlinkMessage,
    wait: &Wait,
) -> Result<RouteNetlinkMessage, Failure> {
    let result = (|| {
        wait.check()?;
        let (socket, port) = socket()?;
        let sequence = sequence()?;
        let request = packet(message, NLM_F_REQUEST, sequence, port)?;
        send(&socket, &request, wait)?;
        let mut bytes = [0; MAX_DATAGRAM + 1];
        let (length, sender) = receive(&socket, &mut bytes, wait)?;
        let message = reply(&bytes[..length], sender, sequence, port)?;
        match message.payload {
            NetlinkPayload::InnerMessage(message) => Ok(message),
            NetlinkPayload::Error(error)
                if error.raw_code() < 0 && error.raw_code() != i32::MIN =>
            {
                Err(Cause::Kernel(-error.raw_code()))
            }
            NetlinkPayload::Overrun(_) => Err(Cause::Lost),
            _ => Err(Cause::Protocol),
        }
    })();
    result.map_err(|cause| Failure {
        delivery: Delivery::NotSent,
        cause,
    })
}
