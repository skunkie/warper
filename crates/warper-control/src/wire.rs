// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded versioned local-control frames. Authenticate peers before use.
//! Any framing failure poisons the stream; callers must close it, not retry I/O.

use std::{fmt, io};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::watch,
    time::{Instant, sleep_until},
};

pub const MAX_CONFIG: usize = 1024 * 1024;
pub const MAX_BODY: usize = MAX_CONFIG + 8;
const HEADER_LEN: usize = 20;
const VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Kind {
    Hello = 1,
    Status = 2,
    Connect = 3,
    Disconnect = 4,
    Enroll = 5,
    InspectRecovery = 6,
    InstallConfig = 7,
    OperationStatus = 8,
    HelloReply = 0x8001,
    StatusReply = 0x8002,
    Accepted = 0x8003,
    EnrollmentReply = 0x8005,
    RecoveryReply = 0x8006,
    ConfigReply = 0x8007,
    OperationReply = 0x8008,
    ErrorReply = 0xffff,
}
impl Kind {
    pub fn is_request(self) -> bool {
        (self as u16) < 0x8000
    }

    fn parse(value: u16) -> Result<Self, Error> {
        Ok(match value {
            1 => Self::Hello,
            2 => Self::Status,
            3 => Self::Connect,
            4 => Self::Disconnect,
            5 => Self::Enroll,
            6 => Self::InspectRecovery,
            7 => Self::InstallConfig,
            8 => Self::OperationStatus,
            0x8001 => Self::HelloReply,
            0x8002 => Self::StatusReply,
            0x8003 => Self::Accepted,
            0x8005 => Self::EnrollmentReply,
            0x8006 => Self::RecoveryReply,
            0x8007 => Self::ConfigReply,
            0x8008 => Self::OperationReply,
            0xffff => Self::ErrorReply,
            _ => return Err(Error::UnknownKind),
        })
    }

    fn check_length(self, length: usize) -> Result<(), Error> {
        let valid = match self {
            Self::Hello | Self::Status | Self::InspectRecovery => length == 0,
            Self::Connect | Self::Disconnect => length == 24,
            Self::Enroll | Self::HelloReply | Self::Accepted | Self::OperationStatus => {
                length == 16
            }
            Self::InstallConfig => (9..=MAX_BODY).contains(&length),
            Self::StatusReply => length == 18,
            Self::EnrollmentReply | Self::ConfigReply => length == 8,
            Self::RecoveryReply | Self::ErrorReply => length == 2,
            Self::OperationReply => length == 19,
        };
        if valid {
            Ok(())
        } else {
            Err(Error::InvalidLength)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Code {
    None = 0,
    Unsupported = 1,
    PermissionDenied = 2,
    Malformed = 3,
    Busy = 4,
    Conflict = 5,
    RecoveryRequired = 6,
    Timeout = 7,
    Failed = 8,
}
impl Code {
    pub fn parse(value: u16) -> Result<Self, Error> {
        Ok(match value {
            0 => Self::None,
            1 => Self::Unsupported,
            2 => Self::PermissionDenied,
            3 => Self::Malformed,
            4 => Self::Busy,
            5 => Self::Conflict,
            6 => Self::RecoveryRequired,
            7 => Self::Timeout,
            8 => Self::Failed,
            _ => return Err(Error::Malformed),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidMagic,
    IncompatibleVersion,
    UnknownKind,
    InvalidLength,
    InvalidRequestId,
    Malformed,
    Cancelled,
    Deadline,
    Io(io::ErrorKind),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidMagic => "Protocol: invalid control header",
            Self::IncompatibleVersion => "Protocol: incompatible control API version",
            Self::UnknownKind => "Protocol: unsupported control message kind",
            Self::InvalidLength => "ResourceLimit: invalid control message length",
            Self::InvalidRequestId => "Protocol: request ID must be nonzero",
            Self::Malformed => "Protocol: malformed control message",
            Self::Cancelled => "Cancelled: control frame cancelled",
            Self::Deadline => "Timeout: control frame deadline expired",
            Self::Io(_) => "Protocol: control stream I/O failed",
        })
    }
}
impl std::error::Error for Error {}

pub struct Frame {
    kind: Kind,
    request_id: u64,
    body: Vec<u8>,
}
impl Frame {
    pub fn new(kind: Kind, request_id: u64, body: Vec<u8>) -> Result<Self, Error> {
        if request_id == 0 {
            return Err(Error::InvalidRequestId);
        }
        kind.check_length(body.len())?;
        check_body(kind, &body)?;
        Ok(Self {
            kind,
            request_id,
            body,
        })
    }
    pub fn kind(&self) -> Kind {
        self.kind
    }
    pub fn request_id(&self) -> u64 {
        self.request_id
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    pub async fn read<R: AsyncRead + Unpin>(
        reader: &mut R,
        deadline: Instant,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<Self, Error> {
        Self::read_limited(reader, deadline, cancel, HEADER_LEN + MAX_BODY).await
    }

    /// Enforce the configured encoded-message budget before body allocation.
    pub async fn read_limited<R: AsyncRead + Unpin>(
        reader: &mut R,
        deadline: Instant,
        cancel: &mut watch::Receiver<bool>,
        max_encoded: usize,
    ) -> Result<Self, Error> {
        if max_encoded < HEADER_LEN {
            return Err(Error::InvalidLength);
        }
        tokio::select! { biased;
            ()=cancelled(cancel)=>Err(Error::Cancelled),
            ()=sleep_until(deadline)=>Err(Error::Deadline),
            result=Self::read_inner(reader, max_encoded)=>result,
        }
    }
    pub async fn write<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        deadline: Instant,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<(), Error> {
        self.write_limited(writer, deadline, cancel, HEADER_LEN + MAX_BODY)
            .await
    }

    /// Reject an over-budget frame before writing even its header.
    pub async fn write_limited<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        deadline: Instant,
        cancel: &mut watch::Receiver<bool>,
        max_encoded: usize,
    ) -> Result<(), Error> {
        if HEADER_LEN + self.body.len() > max_encoded {
            return Err(Error::InvalidLength);
        }
        tokio::select! { biased;
            ()=cancelled(cancel)=>Err(Error::Cancelled),
            ()=sleep_until(deadline)=>Err(Error::Deadline),
            result=self.write_inner(writer)=>result,
        }
    }

    async fn read_inner<R: AsyncRead + Unpin>(
        reader: &mut R,
        max_encoded: usize,
    ) -> Result<Self, Error> {
        let mut header = [0; HEADER_LEN];
        reader.read_exact(&mut header).await.map_err(io_error)?;
        let (kind, request_id, length) = parse_header(&header)?;
        if HEADER_LEN + length > max_encoded {
            return Err(Error::InvalidLength);
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).await.map_err(io_error)?;
        Self::new(kind, request_id, body)
    }
    async fn write_inner<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<(), Error> {
        let header = encode_header(self.kind, self.request_id, self.body.len())?;
        writer.write_all(&header).await.map_err(io_error)?;
        writer.write_all(&self.body).await.map_err(io_error)?;
        writer.flush().await.map_err(io_error)
    }
}
impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Frame(<redacted>)")
    }
}

fn encode_header(kind: Kind, request_id: u64, length: usize) -> Result<[u8; HEADER_LEN], Error> {
    let length = u32::try_from(length).map_err(|_| Error::InvalidLength)?;
    let mut bytes = [0; HEADER_LEN];
    bytes[..4].copy_from_slice(b"WRPC");
    bytes[4..6].copy_from_slice(&VERSION.to_be_bytes());
    bytes[6..8].copy_from_slice(&(kind as u16).to_be_bytes());
    bytes[8..12].copy_from_slice(&length.to_be_bytes());
    bytes[12..].copy_from_slice(&request_id.to_be_bytes());
    Ok(bytes)
}
fn parse_header(bytes: &[u8; HEADER_LEN]) -> Result<(Kind, u64, usize), Error> {
    if &bytes[..4] != b"WRPC" {
        return Err(Error::InvalidMagic);
    }
    if bytes[4..6] != VERSION.to_be_bytes() {
        return Err(Error::IncompatibleVersion);
    }
    let kind = Kind::parse(u16::from_be_bytes([bytes[6], bytes[7]]))?;
    let length =
        u32::from_be_bytes(bytes[8..12].try_into().map_err(|_| Error::InvalidLength)?) as usize;
    kind.check_length(length)?;
    let request_id = u64::from_be_bytes(
        bytes[12..]
            .try_into()
            .map_err(|_| Error::InvalidRequestId)?,
    );
    if request_id == 0 {
        return Err(Error::InvalidRequestId);
    }
    Ok((kind, request_id, length))
}
fn check_body(kind: Kind, body: &[u8]) -> Result<(), Error> {
    let nonzero = |bytes: &[u8]| bytes.iter().any(|v| *v != 0);
    let valid = match kind {
        Kind::HelloReply
        | Kind::Accepted
        | Kind::OperationStatus
        | Kind::EnrollmentReply
        | Kind::ConfigReply => nonzero(body),
        Kind::Connect | Kind::Disconnect => nonzero(&body[..16]),
        Kind::Enroll => {
            let present = u32::from_be_bytes(body[8..12].try_into().map_err(|_| Error::Malformed)?);
            let uid = u32::from_be_bytes(body[12..].try_into().map_err(|_| Error::Malformed)?);
            matches!((present, uid), (0, 0)) || (present == 1 && uid != u32::MAX)
        }
        Kind::StatusReply => body[0] <= 5 && body[17] <= 1,
        Kind::RecoveryReply => u16::from_be_bytes([body[0], body[1]]) & !7 == 0,
        Kind::OperationReply => {
            let code = Code::parse(u16::from_be_bytes([body[17], body[18]]))?;
            nonzero(&body[..16]) && body[16] <= 4 && ((body[16] == 3) == (code != Code::None))
        }
        Kind::ErrorReply => Code::parse(u16::from_be_bytes([body[0], body[1]]))? != Code::None,
        _ => true,
    };
    if valid { Ok(()) } else { Err(Error::Malformed) }
}
async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow() {
            return;
        }
        if cancel.changed().await.is_err() {
            return;
        }
    }
}
fn io_error(error: io::Error) -> Error {
    Error::Io(error.kind())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn canonical_header_and_redaction_are_stable() {
        let frame = Frame::new(Kind::Hello, 42, vec![]).unwrap();
        assert_eq!(
            encode_header(frame.kind, frame.request_id, 0).unwrap(),
            [
                87, 82, 80, 67, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42
            ]
        );
        assert_eq!(format!("{frame:?}"), "Frame(<redacted>)");
        assert!(Kind::Status.is_request());
        assert!(!Kind::StatusReply.is_request());
        assert!(matches!(
            Frame::new(Kind::Hello, 0, vec![]),
            Err(Error::InvalidRequestId)
        ));
    }

    #[test]
    fn kind_lengths_and_semantic_boundaries_reject_invalid_payloads() {
        struct Case {
            id: &'static str,
            body: Vec<u8>,
            kind: Kind,
            expected: Error,
        }
        let cases = [
            Case {
                id: "empty configuration",
                body: vec![],
                kind: Kind::InstallConfig,
                expected: Error::InvalidLength,
            },
            Case {
                id: "oversized configuration",
                body: vec![0; MAX_BODY + 1],
                kind: Kind::InstallConfig,
                expected: Error::InvalidLength,
            },
            Case {
                id: "extra hello data",
                body: vec![1],
                kind: Kind::Hello,
                expected: Error::InvalidLength,
            },
            Case {
                id: "zero operation",
                body: vec![0; 24],
                kind: Kind::Connect,
                expected: Error::Malformed,
            },
            Case {
                id: "claimed owner presence",
                body: vec![255; 16],
                kind: Kind::Enroll,
                expected: Error::Malformed,
            },
            Case {
                id: "unknown status",
                body: vec![255; 18],
                kind: Kind::StatusReply,
                expected: Error::Malformed,
            },
            Case {
                id: "unknown recovery flags",
                body: vec![0, 8],
                kind: Kind::RecoveryReply,
                expected: Error::Malformed,
            },
            Case {
                id: "success error reply",
                body: vec![0, 0],
                kind: Kind::ErrorReply,
                expected: Error::Malformed,
            },
            Case {
                id: "unknown error code",
                body: vec![0, 9],
                kind: Kind::ErrorReply,
                expected: Error::Malformed,
            },
        ];
        for case in cases {
            assert!(
                matches!(Frame::new(case.kind,1,case.body),Err(error) if error==case.expected),
                "{}",
                case.id
            );
        }
        let mut failed = vec![1; 19];
        failed[16] = 3;
        failed[17..].copy_from_slice(&0u16.to_be_bytes());
        assert!(matches!(
            Frame::new(Kind::OperationReply, 1, failed),
            Err(Error::Malformed)
        ));
        let mut reserved = vec![0; 16];
        reserved[8..12].copy_from_slice(&1u32.to_be_bytes());
        reserved[12..].fill(255);
        assert!(matches!(
            Frame::new(Kind::Enroll, 1, reserved),
            Err(Error::Malformed)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn every_message_kind_round_trips_through_bounded_partial_stream_io() {
        let mut operation = vec![0; 24];
        operation[0] = 1;
        let mut operation_reply = vec![0; 19];
        operation_reply[0] = 1;
        let samples = [
            (Kind::Hello, vec![]),
            (Kind::Status, vec![]),
            (Kind::Connect, operation.clone()),
            (Kind::Disconnect, operation),
            (Kind::Enroll, vec![0; 16]),
            (Kind::InspectRecovery, vec![]),
            (Kind::InstallConfig, vec![b'x'; MAX_BODY]),
            (Kind::OperationStatus, vec![1; 16]),
            (Kind::HelloReply, vec![1; 16]),
            (Kind::StatusReply, vec![0; 18]),
            (Kind::Accepted, vec![1; 16]),
            (Kind::EnrollmentReply, vec![1; 8]),
            (Kind::RecoveryReply, vec![0, 7]),
            (Kind::ConfigReply, vec![1; 8]),
            (Kind::OperationReply, operation_reply),
            (Kind::ErrorReply, vec![0, 1]),
        ];
        for (kind, body) in samples {
            let frame = Frame::new(kind, 7, body).unwrap();
            let (mut reader, mut writer) = tokio::io::duplex(64);
            let (_cancel, cancel) = watch::channel(false);
            let mut a = cancel.clone();
            let mut b = cancel;
            let deadline = Instant::now() + Duration::from_secs(1);
            let (received, sent) = tokio::join!(
                Frame::read(&mut reader, deadline, &mut a),
                frame.write(&mut writer, deadline, &mut b)
            );
            sent.unwrap();
            let received = received.unwrap();
            assert_eq!(received.kind(), kind);
            assert_eq!(received.request_id(), 7);
            assert_eq!(received.body(), frame.body());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn malformed_headers_fail_before_attempting_to_read_or_allocate_the_body() {
        let base = encode_header(Kind::InstallConfig, 1, MAX_BODY).unwrap();
        let mut magic = base;
        magic[0] = 0;
        let mut version = base;
        version[5] = 2;
        let mut kind = base;
        kind[6..8].copy_from_slice(&0xfffeu16.to_be_bytes());
        let mut length = base;
        length[8..12].copy_from_slice(&((MAX_BODY + 1) as u32).to_be_bytes());
        let mut request_id = base;
        request_id[12..].fill(0);
        for (header, expected) in [
            (magic, Error::InvalidMagic),
            (version, Error::IncompatibleVersion),
            (kind, Error::UnknownKind),
            (length, Error::InvalidLength),
            (request_id, Error::InvalidRequestId),
        ] {
            let mut input = header.as_slice();
            let (_sender, mut cancel) = watch::channel(false);
            assert!(
                matches!(Frame::read(&mut input,Instant::now()+Duration::from_secs(1),&mut cancel).await,Err(error) if error==expected)
            );
            assert!(input.is_empty());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn total_deadline_covers_partial_header_body_and_output_without_replay() {
        let (_sender, mut cancel) = watch::channel(false);
        let (mut input, mut peer) = tokio::io::duplex(64);
        peer.write_all(b"WRPC").await.unwrap();
        assert!(matches!(
            Frame::read(
                &mut input,
                Instant::now() + Duration::from_secs(1),
                &mut cancel
            )
            .await,
            Err(Error::Deadline)
        ));
        drop(input);
        drop(peer);
        let (mut input, mut peer) = tokio::io::duplex(64);
        peer.write_all(&encode_header(Kind::Connect, 1, 24).unwrap())
            .await
            .unwrap();
        peer.write_all(&[1; 8]).await.unwrap();
        assert!(matches!(
            Frame::read(
                &mut input,
                Instant::now() + Duration::from_secs(1),
                &mut cancel
            )
            .await,
            Err(Error::Deadline)
        ));
        drop(input);
        drop(peer);
        let (mut writer, mut peer) = tokio::io::duplex(4);
        let frame = Frame::new(Kind::Hello, 1, vec![]).unwrap();
        assert_eq!(
            frame
                .write(
                    &mut writer,
                    Instant::now() + Duration::from_secs(1),
                    &mut cancel
                )
                .await,
            Err(Error::Deadline)
        );
        drop(writer);
        let mut actual = Vec::new();
        peer.read_to_end(&mut actual).await.unwrap();
        assert_eq!(actual, b"WRPC");
    }

    #[tokio::test(start_paused = true)]
    async fn configured_encoded_budget_rejects_before_body_read_or_any_output() {
        let header = encode_header(Kind::InstallConfig, 1, 32).unwrap();
        let mut input = header.as_slice();
        let (_sender, mut cancel) = watch::channel(false);
        let deadline = Instant::now() + Duration::from_secs(1);
        assert!(matches!(
            Frame::read_limited(&mut input, deadline, &mut cancel, 40).await,
            Err(Error::InvalidLength)
        ));
        assert!(input.is_empty());
        let mut input = b"WRPC".as_slice();
        assert!(matches!(
            Frame::read_limited(&mut input, deadline, &mut cancel, 19).await,
            Err(Error::InvalidLength)
        ));
        assert_eq!(input, b"WRPC");
        let frame = Frame::new(Kind::InstallConfig, 1, vec![1; 32]).unwrap();
        let mut output = Vec::new();
        assert_eq!(
            frame
                .write_limited(&mut output, deadline, &mut cancel, 40)
                .await,
            Err(Error::InvalidLength)
        );
        assert!(output.is_empty());
        frame
            .write_limited(&mut output, deadline, &mut cancel, 52)
            .await
            .unwrap();
        assert_eq!(output.len(), 52);
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_interrupts_a_partially_received_frame() {
        let (sender, mut cancel) = watch::channel(false);
        let (mut input, mut peer) = tokio::io::duplex(64);
        peer.write_all(b"WRPC").await.unwrap();
        let (received, ()) = tokio::join!(
            Frame::read(
                &mut input,
                Instant::now() + Duration::from_secs(10),
                &mut cancel
            ),
            async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                sender.send(true).unwrap();
            }
        );
        assert!(matches!(received, Err(Error::Cancelled)));
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_closed_channels_and_eof_keep_distinct_error_categories() {
        let (sender, mut cancel) = watch::channel(true);
        let mut input = b"".as_slice();
        assert!(matches!(
            Frame::read(
                &mut input,
                Instant::now() + Duration::from_secs(1),
                &mut cancel
            )
            .await,
            Err(Error::Cancelled)
        ));
        sender.send(false).unwrap();
        drop(sender);
        assert!(matches!(
            Frame::read(
                &mut input,
                Instant::now() + Duration::from_secs(1),
                &mut cancel
            )
            .await,
            Err(Error::Cancelled)
        ));
        let (_sender, mut cancel) = watch::channel(false);
        assert!(matches!(
            Frame::read(
                &mut input,
                Instant::now() + Duration::from_secs(1),
                &mut cancel
            )
            .await,
            Err(Error::Io(io::ErrorKind::UnexpectedEof))
        ));
        assert!(matches!(
            Frame::read(&mut input, Instant::now(), &mut cancel).await,
            Err(Error::Deadline)
        ));
    }
}
