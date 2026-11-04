// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Private bounded socket construction shared by Linux read-only adapters.

use super::QueryError;
use netlink_packet_core::{
    NLM_F_MULTIPART, NLM_F_REQUEST, NetlinkBuffer, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::SocketAddr;
use netlink_sys::{AsyncSocket, TokioSocket, protocols::NETLINK_ROUTE};
use nix::errno::Errno;
use std::{
    future::{Future, poll_fn},
    io,
    sync::atomic::{AtomicU32, Ordering},
    task::Poll,
};
use tokio::time::{Instant, sleep_until};
use warper_core::transport::Request;

pub(super) const MAX_REQUEST: usize = 128;
static NEXT_SEQUENCE: AtomicU32 = AtomicU32::new(1);

pub(super) const MAX_DATAGRAM: usize = 32768;

pub(super) fn sequence() -> Result<u32, QueryError> {
    NEXT_SEQUENCE
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| QueryError::ResourceLimit)
}

pub(super) enum Error {
    Io(io::Error),
    ResourceLimit,
    InvalidSocket,
}

pub(super) fn socket(groups: u32) -> Result<(TokioSocket, u32), Error> {
    let mut socket = TokioSocket::new(NETLINK_ROUTE).map_err(Error::Io)?;
    socket
        .socket_ref()
        .set_rx_buf_sz(MAX_DATAGRAM as i32)
        .map_err(Error::Io)?;
    if socket.socket_ref().get_rx_buf_sz().map_err(Error::Io)? > 2 * MAX_DATAGRAM {
        return Err(Error::ResourceLimit);
    }
    // Never suppress loss notifications on a monitoring or query socket.
    socket
        .socket_ref()
        .set_no_enobufs(false)
        .map_err(Error::Io)?;
    if socket.socket_ref().get_no_enobufs().map_err(Error::Io)? {
        return Err(Error::InvalidSocket);
    }
    socket
        .socket_ref()
        .set_netlink_get_strict_chk(true)
        .map_err(Error::Io)?;
    let address = netlink_sys::SocketAddr::new(0, groups);
    socket.socket_mut().bind(&address).map_err(Error::Io)?;
    let mut address = address;
    socket
        .socket_ref()
        .get_address(&mut address)
        .map_err(Error::Io)?;
    if address.port_number() == 0 || address.multicast_groups() != groups {
        return Err(Error::InvalidSocket);
    }
    Ok((socket, address.port_number()))
}

pub(super) async fn bounded<T>(
    mut request: Request,
    operation: impl Future<Output = Result<T, QueryError>>,
) -> Result<T, QueryError> {
    let deadline = request.deadline;
    let mut operation = std::pin::pin!(operation);
    let checked = poll_fn(|context| {
        // Check each poll even when the timer driver has not run again.
        if Instant::now() >= deadline {
            Poll::Ready(Err(QueryError::Timeout))
        } else {
            operation.as_mut().poll(context)
        }
    });
    tokio::select! { biased;
        _ = request.cancellation.wait_for(|cancelled| *cancelled) => Err(QueryError::Cancelled),
        () = sleep_until(deadline) => Err(QueryError::Timeout),
        result = checked => result,
    }
}

pub(super) async fn exchange(
    message: RouteNetlinkMessage,
) -> Result<RouteNetlinkMessage, QueryError> {
    // Keep the bounded datagram out of nested async caller stack frames.
    // Allocate before socket creation/send and fail without starting I/O if
    // the allocation cannot fit the promised receive-byte reservation.
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(MAX_DATAGRAM + 1)
        .map_err(|_| QueryError::ResourceLimit)?;
    if buffer.capacity() != MAX_DATAGRAM + 1 {
        return Err(QueryError::ResourceLimit);
    }
    buffer.resize(MAX_DATAGRAM + 1, 0);
    let sequence = sequence()?;
    let (socket, port) = socket(0).map_err(|error| match error {
        Error::Io(error) => socket_error(error),
        Error::ResourceLimit => QueryError::ResourceLimit,
        Error::InvalidSocket => QueryError::InvalidReply,
    })?;
    let packet = request_packet(message, sequence, port)?;
    let length = poll_fn(|context| socket.poll_send_to(context, &packet, &SocketAddr::new(0, 0)))
        .await
        .map_err(socket_error)?;
    if length != packet.len() {
        return Err(QueryError::InvalidReply);
    }
    // A fixed slice cannot grow through BufMut. The extra byte makes every
    // oversized/truncated datagram fail closed, even if its prefix is valid.
    let mut remaining = &mut buffer[..];
    let sender = poll_fn(|context| socket.poll_recv_from(context, &mut remaining))
        .await
        .map_err(socket_error)?;
    let length = MAX_DATAGRAM + 1 - remaining.len();
    decode(&buffer[..length], Some(sender), sequence, port)
}

pub(super) fn request_packet(
    message: RouteNetlinkMessage,
    sequence: u32,
    port: u32,
) -> Result<Vec<u8>, QueryError> {
    if !matches!(
        &message,
        RouteNetlinkMessage::GetRoute(_) | RouteNetlinkMessage::GetLink(_)
    ) {
        return Err(QueryError::InvalidInput);
    }
    let mut packet = NetlinkMessage::from(message);
    packet.header.flags = NLM_F_REQUEST;
    packet.header.sequence_number = sequence;
    packet.header.port_number = port;
    packet.finalize();
    if packet.buffer_len() > MAX_REQUEST {
        return Err(QueryError::ResourceLimit);
    }
    let mut bytes = vec![0; packet.buffer_len()];
    packet.serialize(&mut bytes);
    Ok(bytes)
}

pub(super) fn socket_error(error: io::Error) -> QueryError {
    match error.raw_os_error() {
        Some(code) if code == Errno::ENOBUFS as i32 => QueryError::Lost,
        Some(code) => QueryError::Socket(Errno::from_raw(code)),
        None => QueryError::Io(error.kind()),
    }
}

pub(super) fn decode(
    bytes: &[u8],
    sender: Option<SocketAddr>,
    sequence: u32,
    port: u32,
) -> Result<RouteNetlinkMessage, QueryError> {
    if sender.is_none_or(|sender| sender.port_number() != 0 || sender.multicast_groups() != 0) {
        return Err(QueryError::UnexpectedSender);
    }
    if bytes.len() > MAX_DATAGRAM {
        return Err(QueryError::Lost);
    }
    let buffer = NetlinkBuffer::new_checked(bytes).map_err(|_| QueryError::InvalidReply)?;
    // A single-object query reply must contain exactly one complete message. Do not
    // accept a valid prefix while ignoring another message or untrusted tail.
    if buffer.length() as usize != bytes.len() {
        return Err(QueryError::InvalidReply);
    }
    let message = NetlinkMessage::<RouteNetlinkMessage>::deserialize(bytes)
        .map_err(|_| QueryError::InvalidReply)?;
    if message.header.sequence_number != sequence
        || message.header.port_number != port
        || message.header.flags & NLM_F_MULTIPART != 0
    {
        return Err(QueryError::InvalidReply);
    }
    match message.payload {
        NetlinkPayload::InnerMessage(
            message @ (RouteNetlinkMessage::NewRoute(_) | RouteNetlinkMessage::NewLink(_)),
        ) => Ok(message),
        NetlinkPayload::Error(error) => match error.raw_code() {
            code if code < 0 && code != i32::MIN => Err(QueryError::Kernel(-code)),
            _ => Err(QueryError::InvalidReply),
        },
        NetlinkPayload::Overrun(_) => Err(QueryError::Lost),
        _ => Err(QueryError::InvalidReply),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::{link_lookup, route_lookup};
    use std::{mem::size_of_val, num::NonZeroU32, time::Duration};
    use tokio::{sync::watch, time::Instant};

    #[test]
    fn single_object_query_futures_bound_inline_state() {
        let (_owner, cancellation) = watch::channel(false);
        let request = Request {
            deadline: Instant::now() + Duration::from_secs(1),
            cancellation,
        };
        // Construct but do not poll: no socket, interface inspection or kernel
        // operation is needed to check the retained caller stack footprint.
        let route = route_lookup::lookup(
            route_lookup::Query {
                protocol: route_lookup::Protocol::Tcp,
                destination: "192.0.2.53:53".parse().unwrap(),
                source: None,
                interface: None,
            },
            request.clone(),
        );
        let link = link_lookup::lookup(
            link_lookup::Query::Index(NonZeroU32::new(1).unwrap()),
            request,
        );
        for (name, bytes) in [("route", size_of_val(&route)), ("link", size_of_val(&link))] {
            assert!(
                bytes <= 16 * 1024,
                "{name} query retains {bytes} inline bytes; nested protected connection futures must fit default worker stacks"
            );
        }
    }

    #[test]
    fn expired_native_io_does_not_resume_before_timer_driver_runs() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let _entered = runtime.enter();
        let (_owner, cancellation) = watch::channel(false);
        let deadline = Instant::now() + Duration::from_millis(25);
        let polls = std::cell::Cell::new(0);
        let operation = std::future::poll_fn(|_| {
            polls.set(polls.get() + 1);
            if polls.get() == 1 {
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(Ok::<_, QueryError>(()))
            }
        });
        let mut operation = std::pin::pin!(bounded(
            Request {
                deadline,
                cancellation
            },
            operation
        ));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(operation.as_mut().poll(&mut context).is_pending());
        // Keep the timer driver idle while the real monotonic deadline passes.
        std::thread::sleep(
            deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
        );
        assert_eq!(
            operation.as_mut().poll(&mut context),
            std::task::Poll::Ready(Err(QueryError::Timeout))
        );
        assert_eq!(
            polls.get(),
            1,
            "expired native queries must not be polled again"
        );
    }
}
