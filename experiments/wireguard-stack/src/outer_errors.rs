// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded Linux UDP error-queue decoding for one connected fixture socket.

use std::{
    fmt,
    io::{self, IoSliceMut},
    net::{IpAddr, SocketAddr, UdpSocket},
    os::fd::AsRawFd,
    sync::Arc,
};

use anyhow::{Result, ensure};
use nix::{
    errno::Errno,
    sys::socket::{
        ControlMessageOwned, MsgFlags, SockaddrIn, SockaddrIn6, SockaddrStorage, getsockopt,
        recvmsg, setsockopt, sockopt,
    },
};
use rustix::net::sockopt::{self as options, Ipv4PathMtuDiscovery, Ipv6PathMtuDiscovery};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    WrongSocket,
    Truncated,
    MissingControl,
    DuplicateControl,
    UnexpectedControl,
    InvalidRecord,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "outer UDP error feedback: {self:?}")
    }
}

impl std::error::Error for Error {}

pub struct ErrorQueue {
    socket: UdpSocket,
    local: SocketAddr,
    remote: SocketAddr,
    identity: Arc<()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalMtu {
    pub mtu: usize,
}

#[derive(Clone)]
pub(super) struct Record {
    pub ipv6: bool,
    pub errno: u32,
    pub origin: u8,
    pub kind: u8,
    pub code: u8,
    pub mtu: u32,
    pub reporter: Option<IpAddr>,
}

#[derive(Clone)]
pub(super) struct ReceivedError {
    pub identity: Arc<()>,
    pub local: SocketAddr,
    pub record: Record,
    pub destination: Option<SocketAddr>,
    pub flags: MsgFlags,
    pub prefix: [u8; 16],
    pub quoted_len: usize,
}

impl ErrorQueue {
    pub fn enable(socket: &UdpSocket) -> Result<Self> {
        let queue = Self {
            socket: socket.try_clone()?,
            local: socket.local_addr()?,
            remote: socket.peer_addr()?,
            identity: Arc::new(()),
        };
        ensure!(
            queue.local.is_ipv6() == queue.remote.is_ipv6(),
            "outer socket family mismatch"
        );
        if queue.remote.is_ipv6() {
            setsockopt(socket, sockopt::Ipv6RecvErr, &true)?;
            options::set_ipv6_mtu_discover(socket, Ipv6PathMtuDiscovery::DO)?;
            ensure!(
                getsockopt(socket, sockopt::Ipv6RecvErr)?
                    && options::ipv6_mtu_discover(socket)? == Ipv6PathMtuDiscovery::DO,
                "IPv6 error reporting readback failed"
            );
        } else {
            setsockopt(socket, sockopt::Ipv4RecvErr, &true)?;
            options::set_ip_mtu_discover(socket, Ipv4PathMtuDiscovery::DO)?;
            ensure!(
                getsockopt(socket, sockopt::Ipv4RecvErr)?
                    && options::ip_mtu_discover(socket)? == Ipv4PathMtuDiscovery::DO,
                "IPv4 error reporting readback failed"
            );
        }
        Ok(queue)
    }

    pub(super) fn local(&self) -> SocketAddr {
        self.local
    }

    pub(super) fn remote(&self) -> SocketAddr {
        self.remote
    }

    pub(super) fn identity(&self) -> &Arc<()> {
        &self.identity
    }

    pub(super) fn enable_remote_probe(socket: &UdpSocket) -> Result<Self> {
        let queue = Self::enable(socket)?;
        // The fixture repeats a routed measurement without reusing the kernel's
        // cached PMTU. The declared transport budget still guards every send.
        if queue.remote.is_ipv6() {
            options::set_ipv6_mtu_discover(socket, Ipv6PathMtuDiscovery::PROBE)?;
            ensure!(options::ipv6_mtu_discover(socket)? == Ipv6PathMtuDiscovery::PROBE);
        } else {
            options::set_ip_mtu_discover(socket, Ipv4PathMtuDiscovery::PROBE)?;
            ensure!(options::ip_mtu_discover(socket)? == Ipv4PathMtuDiscovery::PROBE);
        }
        Ok(queue)
    }

    pub fn diagnose(&self, primary: anyhow::Error) -> Result<LocalMtu> {
        let Some(error) = primary.downcast_ref::<io::Error>() else {
            return Err(primary);
        };
        if error.raw_os_error() != Some(Errno::EMSGSIZE as i32) {
            return Err(primary);
        }
        match self.read() {
            Ok(Some(report)) => Ok(report),
            Ok(None) => Err(primary.context("kernel MTU error had no queued report")),
            Err(diagnostic) => {
                Err(primary.context(format!("kernel MTU error diagnostic failed: {diagnostic}")))
            }
        }
    }

    pub fn read(&self) -> Result<Option<LocalMtu>> {
        let Some(received) = self.receive()? else {
            return Ok(None);
        };
        Ok(Some(classify(
            &received.record,
            received.destination,
            self.remote,
            received.flags,
        )?))
    }

    pub(super) fn receive(&self) -> Result<Option<ReceivedError>> {
        let socket = &self.socket;
        if socket.local_addr()? != self.local || socket.peer_addr()? != self.remote {
            return Err(Error::WrongSocket.into());
        }
        let mut bytes = [0; 2048];
        let mut iov = [IoSliceMut::new(&mut bytes)];
        let mut ancillary = [0; 256];
        let message = match recvmsg::<SockaddrStorage>(
            socket.as_raw_fd(),
            &mut iov,
            Some(&mut ancillary),
            MsgFlags::MSG_ERRQUEUE | MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(message) => message,
            Err(Errno::EAGAIN) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if message
            .flags
            .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
        {
            return Err(Error::Truncated.into());
        }
        let destination = message.address.and_then(|address| {
            if let Some(ip) = address.as_sockaddr_in() {
                Some(SocketAddr::from(*ip))
            } else {
                address.as_sockaddr_in6().map(|ip| SocketAddr::from(*ip))
            }
        });
        let record = decode_controls(message.cmsgs()?)?;
        let quoted_len = message.bytes;
        let flags = message.flags;
        let mut prefix = [0; 16];
        let retained = quoted_len.min(prefix.len());
        prefix[..retained].copy_from_slice(&bytes[..retained]);
        Ok(Some(ReceivedError {
            identity: Arc::clone(&self.identity),
            local: self.local,
            record,
            destination,
            flags,
            prefix,
            quoted_len,
        }))
    }
}

fn decode_controls(controls: impl Iterator<Item = ControlMessageOwned>) -> Result<Record, Error> {
    let mut record = None;
    for control in controls {
        if record.is_some() {
            return Err(Error::DuplicateControl);
        }
        let (ipv6, error, reporter) = match control {
            ControlMessageOwned::Ipv4RecvErr(error, address) => (
                false,
                error,
                address.and_then(|address| {
                    (address.sin_family == nix::libc::AF_INET as u16 && address.sin_port == 0)
                        .then(|| IpAddr::V4(SockaddrIn::from(address).ip()))
                }),
            ),
            ControlMessageOwned::Ipv6RecvErr(error, address) => (
                true,
                error,
                address.and_then(|address| {
                    (address.sin6_family == nix::libc::AF_INET6 as u16
                        && address.sin6_port == 0
                        && address.sin6_scope_id == 0)
                        .then(|| IpAddr::V6(SockaddrIn6::from(address).ip()))
                }),
            ),
            _ => return Err(Error::UnexpectedControl),
        };
        record = Some(Record {
            ipv6,
            errno: error.ee_errno,
            origin: error.ee_origin,
            kind: error.ee_type,
            code: error.ee_code,
            mtu: error.ee_info,
            reporter,
        });
    }
    record.ok_or(Error::MissingControl)
}

fn classify(
    record: &Record,
    destination: Option<SocketAddr>,
    remote: SocketAddr,
    flags: MsgFlags,
) -> Result<LocalMtu, Error> {
    if flags.intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC) {
        return Err(Error::Truncated);
    }
    if !flags.contains(MsgFlags::MSG_ERRQUEUE)
        || destination != Some(remote)
        || record.ipv6 != remote.is_ipv6()
        || record.errno != Errno::EMSGSIZE as u32
        || record.origin != nix::libc::SO_EE_ORIGIN_LOCAL
        || record.kind != 0
        || record.code != 0
        || record.mtu == 0
        || record.mtu > 65535
    {
        return Err(Error::InvalidRecord);
    }
    Ok(LocalMtu {
        mtu: record.mtu as usize,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_diagnosis_preserves_the_original_send_error() {
        for ipv6 in [false, true] {
            let socket = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            let remote = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            socket.connect(remote.local_addr().unwrap()).unwrap();
            let queue = ErrorQueue::enable(&socket).unwrap();
            let original = io::Error::from_raw_os_error(Errno::EMSGSIZE as i32);
            let error = queue.diagnose(original.into()).unwrap_err();
            assert_eq!(
                error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
                Some(Errno::EMSGSIZE as i32)
            );
            let error = queue
                .diagnose(io::Error::from(io::ErrorKind::PermissionDenied).into())
                .unwrap_err();
            assert_eq!(
                error.downcast_ref::<io::Error>().unwrap().kind(),
                io::ErrorKind::PermissionDenied
            );
            let error = queue.diagnose(Error::WrongSocket.into()).unwrap_err();
            assert_eq!(error.downcast_ref::<Error>(), Some(&Error::WrongSocket));
            socket.connect(crate::loopback_address(ipv6)).unwrap();
            let error = queue
                .diagnose(io::Error::from_raw_os_error(Errno::EMSGSIZE as i32).into())
                .unwrap_err();
            assert_eq!(
                error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
                Some(Errno::EMSGSIZE as i32)
            );
        }
    }

    #[test]
    fn local_records_require_exact_destination_family_origin_and_error() {
        for ipv6 in [false, true] {
            let peer: SocketAddr = if ipv6 { "[::1]:9000" } else { "127.0.0.1:9000" }
                .parse()
                .unwrap();
            let record = || Record {
                ipv6,
                errno: Errno::EMSGSIZE as u32,
                origin: nix::libc::SO_EE_ORIGIN_LOCAL,
                kind: 0,
                code: 0,
                mtu: 1400,
                reporter: None,
            };
            let flags = MsgFlags::MSG_ERRQUEUE;
            assert_eq!(
                classify(&record(), Some(peer), peer, flags),
                Ok(LocalMtu { mtu: 1400 })
            );
            for field in ["family", "errno", "origin", "type", "code", "zero", "large"] {
                let mut invalid = record();
                match field {
                    "family" => invalid.ipv6 = !ipv6,
                    "errno" => invalid.errno = Errno::ECONNREFUSED as u32,
                    "origin" => invalid.origin = if ipv6 { 3 } else { 2 },
                    "type" => invalid.kind = 1,
                    "code" => invalid.code = 1,
                    "zero" => invalid.mtu = 0,
                    "large" => invalid.mtu = 65536,
                    _ => unreachable!(),
                }
                assert_eq!(
                    classify(&invalid, Some(peer), peer, flags),
                    Err(Error::InvalidRecord),
                    "field {field}"
                );
            }
            assert_eq!(
                classify(&record(), None, peer, flags),
                Err(Error::InvalidRecord)
            );
            let mut wrong = peer;
            wrong.set_port(9001);
            assert_eq!(
                classify(&record(), Some(wrong), peer, flags),
                Err(Error::InvalidRecord)
            );
            assert_eq!(
                classify(&record(), Some(peer), peer, MsgFlags::empty()),
                Err(Error::InvalidRecord)
            );
            for flag in [MsgFlags::MSG_TRUNC, MsgFlags::MSG_CTRUNC] {
                assert_eq!(
                    classify(&record(), Some(peer), peer, flags | flag),
                    Err(Error::Truncated)
                );
            }
        }
    }

    #[test]
    fn enabled_socket_reads_empty_queue_without_blocking_and_rejects_peer_changes() {
        for ipv6 in [false, true] {
            let receiver = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            let sender = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            sender.connect(receiver.local_addr().unwrap()).unwrap();
            let unconnected = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            assert!(ErrorQueue::enable(&unconnected).is_err());
            let queue = ErrorQueue::enable(&sender).unwrap();
            assert_eq!(queue.read().unwrap(), None);
            let other = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            sender.connect(other.local_addr().unwrap()).unwrap();
            assert_eq!(
                queue.read().unwrap_err().downcast_ref::<Error>(),
                Some(&Error::WrongSocket)
            );
        }
    }

    #[test]
    fn missing_unknown_or_duplicate_ancillary_controls_are_rejected() {
        let error = || nix::libc::sock_extended_err {
            ee_errno: Errno::EMSGSIZE as u32,
            ee_origin: nix::libc::SO_EE_ORIGIN_LOCAL,
            ee_type: 0,
            ee_code: 0,
            ee_pad: 0,
            ee_info: 1400,
            ee_data: 0,
        };
        assert!(matches!(
            decode_controls(std::iter::empty()),
            Err(Error::MissingControl)
        ));
        assert!(matches!(
            decode_controls([ControlMessageOwned::ScmRights(Vec::new())].into_iter()),
            Err(Error::UnexpectedControl)
        ));
        assert!(matches!(
            decode_controls(
                [
                    ControlMessageOwned::Ipv4RecvErr(error(), None),
                    ControlMessageOwned::Ipv4RecvErr(error(), None)
                ]
                .into_iter()
            ),
            Err(Error::DuplicateControl)
        ));
        assert!(
            decode_controls([ControlMessageOwned::Ipv6RecvErr(error(), None)].into_iter())
                .unwrap()
                .ipv6
        );
    }

    #[test]
    fn ancillary_router_addresses_require_matching_family_and_unscoped_zero_port() {
        let error = nix::libc::sock_extended_err {
            ee_errno: Errno::EMSGSIZE as u32,
            ee_origin: nix::libc::SO_EE_ORIGIN_ICMP,
            ee_type: 3,
            ee_code: 4,
            ee_pad: 0,
            ee_info: 1400,
            ee_data: 0,
        };
        let address: std::net::SocketAddrV4 = "198.18.0.1:0".parse().unwrap();
        let mut raw: nix::libc::sockaddr_in = SockaddrIn::from(address).into();
        let record =
            decode_controls([ControlMessageOwned::Ipv4RecvErr(error, Some(raw))].into_iter())
                .unwrap();
        assert_eq!(record.reporter, Some(IpAddr::V4(*address.ip())));
        raw.sin_port = 1;
        assert!(
            decode_controls([ControlMessageOwned::Ipv4RecvErr(error, Some(raw))].into_iter())
                .unwrap()
                .reporter
                .is_none()
        );
        raw.sin_port = 0;
        raw.sin_family = nix::libc::AF_UNSPEC as u16;
        assert!(
            decode_controls([ControlMessageOwned::Ipv4RecvErr(error, Some(raw))].into_iter())
                .unwrap()
                .reporter
                .is_none()
        );
        let address: std::net::SocketAddrV6 = "[fd77:1::1]:0".parse().unwrap();
        let raw: nix::libc::sockaddr_in6 = SockaddrIn6::from(address).into();
        let record =
            decode_controls([ControlMessageOwned::Ipv6RecvErr(error, Some(raw))].into_iter())
                .unwrap();
        assert_eq!(record.reporter, Some(IpAddr::V6(*address.ip())));
        for case in 0..3 {
            let mut invalid = raw;
            match case {
                0 => invalid.sin6_scope_id = 1,
                1 => invalid.sin6_port = 1,
                2 => invalid.sin6_family = nix::libc::AF_UNSPEC as u16,
                _ => unreachable!(),
            }
            assert!(
                decode_controls(
                    [ControlMessageOwned::Ipv6RecvErr(error, Some(invalid))].into_iter()
                )
                .unwrap()
                .reporter
                .is_none()
            );
        }
    }

    #[test]
    fn error_reader_retains_its_socket_until_the_reader_is_dropped() {
        for ipv6 in [false, true] {
            let receiver = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            let sender = UdpSocket::bind(crate::loopback_address(ipv6)).unwrap();
            sender.connect(receiver.local_addr().unwrap()).unwrap();
            let address = sender.local_addr().unwrap();
            let queue = ErrorQueue::enable(&sender).unwrap();
            drop(sender);
            assert!(
                UdpSocket::bind(address).is_err(),
                "reserved socket must survive its original descriptor"
            );
            drop(queue);
            UdpSocket::bind(address).unwrap();
        }
    }
}
