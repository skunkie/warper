// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Keep third-party DNS types and errors inside the protocol adapter.

use std::{fmt, time::Duration};

use hickory_proto::{
    ProtoError,
    op::{Edns, Header, Message, MessageType, OpCode, Query, ResponseCode},
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
};
use warper_core::dns::Name;

mod address;
mod service;

pub use address::{Address, AddressAnswer, AddressError, AddressLookup, AddressProgress};

pub use service::{
    AddressSection, BindingSet, RelatedAddress, RelatedSet, ServiceAlias, ServiceBinding,
    ServiceError, TimedAlias,
};

const HEADER_BYTES: usize = 12;
const MAX_WIRE_BYTES: usize = u16::MAX as usize;
const MAX_RECORDS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidLimits,
    ResourceLimit,
    Malformed,
    UnsupportedOperation,
    MismatchedResponse,
    Truncated,
    Encoding,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLimits => "invalid DNS packet limits",
            Self::ResourceLimit => "DNS packet admission exhausted",
            Self::Malformed => "malformed DNS packet",
            Self::UnsupportedOperation => "unsupported DNS operation",
            Self::MismatchedResponse => "DNS response does not match the request",
            Self::Truncated => "DNS response requires TCP retry",
            Self::Encoding => "DNS packet encoding failed",
        })
    }
}

impl std::error::Error for Error {}

/// Limits apply before the library allocates question or record vectors.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    wire_bytes: usize,
    records: usize,
}

impl Limits {
    pub fn new(wire_bytes: usize, records: usize) -> Result<Self, Error> {
        if !(HEADER_BYTES..=MAX_WIRE_BYTES).contains(&wire_bytes)
            || !(1..=MAX_RECORDS).contains(&records)
        {
            return Err(Error::InvalidLimits);
        }
        Ok(Self {
            wire_bytes,
            records,
        })
    }

    pub fn wire_bytes(self) -> usize {
        self.wire_bytes
    }

    fn admit(self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > self.wire_bytes {
            return Err(Error::ResourceLimit);
        }
        if bytes.len() < HEADER_BYTES {
            return Err(Error::Malformed);
        }
        let count = |offset| usize::from(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]));
        if count(4) != 1 {
            return Err(Error::Malformed);
        }
        if count(6) + count(8) + count(10) > self.records {
            return Err(Error::ResourceLimit);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Question {
    pub name: Name,
    pub record_type: u16,
    pub class: u16,
}

/// Local replies contain no upstream records and grant no routing permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalReply {
    ServFail,
    Truncated,
    DisabledIpv6,
}

/// Owns a complete, bounded decoded packet. There is no route publication or
/// positive-answer permission here; the endpoint/route gate owns that decision.
pub struct Packet {
    message: Message,
    question: Question,
    limits: Limits,
}

impl Packet {
    pub fn request(bytes: &[u8], limits: Limits) -> Result<Self, Error> {
        let (header, question) = envelope(bytes, limits)?;
        if header.message_type != MessageType::Query || header.truncation {
            return Err(Error::Malformed);
        }
        if header.counts.answers != 0 || header.counts.authorities != 0 {
            return Err(Error::Malformed);
        }
        Self::decode(bytes, question, limits)
    }

    /// Correlate ID, canonical question, class and type before accepting TC or
    /// decoding records. A correlated truncated UDP reply triggers TCP retry
    /// even when its final record was cut short. No partial packet is retained.
    pub fn response(bytes: &[u8], request: &Self, limits: Limits) -> Result<Self, Error> {
        if request.message.message_type != MessageType::Query {
            return Err(Error::MismatchedResponse);
        }
        let (header, question) = envelope(bytes, limits)?;
        if header.message_type != MessageType::Response
            || header.id != request.id()
            || question != request.question
        {
            return Err(Error::MismatchedResponse);
        }
        if header.truncation {
            return Err(Error::Truncated);
        }
        Self::decode(bytes, question, limits)
    }

    /// Construct a dependency query without copying authentication over a
    /// changed question. Each dependency uses its own owned TCP stream.
    pub(super) fn dependency(&self, question: Question) -> Result<Self, Error> {
        self.check_synthesis()?;
        let mut decoder = BinDecoder::new(question.name.wire());
        let name = hickory_proto::rr::Name::read(&mut decoder).map_err(|_| Error::Malformed)?;
        let mut message = Message::new(self.id(), MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = self.message.recursion_desired;
        message.metadata.checking_disabled = self.message.checking_disabled;
        message.edns = self.message.edns.clone();
        let mut query = Query::query(name, question.record_type.into());
        query.query_class = question.class.into();
        message.queries.push(query);
        let packet = Self {
            message,
            question,
            limits: self.limits,
        };
        // Account for a longer dependency name before upstream work starts.
        packet.encode()?;
        Ok(packet)
    }

    pub fn id(&self) -> u16 {
        self.message.id
    }

    pub fn question(&self) -> Question {
        self.question
    }

    pub fn edns_version(&self) -> Option<u8> {
        self.message.edns.as_ref().map(Edns::version)
    }

    /// The virtual UDP endpoint caps payloads at 1232 bytes. EDNS values below
    /// 512 mean 512; absent EDNS retains the original DNS UDP limit.
    pub fn udp_payload_limit(&self) -> usize {
        usize::from(
            self.message
                .edns
                .as_ref()
                .map_or(512, |edns| edns.max_payload().max(512)),
        )
        .min(warper_stack::runtime::udp_dns::MAX_PAYLOAD)
        .min(self.limits.wire_bytes)
    }

    /// Synthesize a small reply from a validated request. Unsupported EDNS
    /// versions take precedence and receive BADVERS with supported version 0.
    /// Transaction authentication and unrelated Additional records cannot be
    /// copied into an unsigned local answer.
    pub fn local_reply(&self, reply: LocalReply) -> Result<Vec<u8>, Error> {
        self.check_synthesis()?;
        if reply == LocalReply::DisabledIpv6
            && (self.question.record_type != 28 || self.question.class != 1)
        {
            return Err(Error::UnsupportedOperation);
        }
        let bad_version = self
            .message
            .edns
            .as_ref()
            .is_some_and(|edns| edns.version() != 0);
        let mut message = Message::new(self.id(), MessageType::Response, OpCode::Query);
        message.metadata.recursion_desired = self.message.recursion_desired;
        message.metadata.checking_disabled = self.message.checking_disabled;
        message.metadata.recursion_available = true;
        message.metadata.response_code = if bad_version {
            ResponseCode::BADVERS
        } else if reply == LocalReply::ServFail {
            ResponseCode::ServFail
        } else {
            ResponseCode::NoError
        };
        message.queries.push(self.message.queries[0].clone());
        if let Some(request_edns) = &self.message.edns {
            let mut edns = Edns::new();
            edns.set_max_payload(
                self.limits
                    .wire_bytes
                    .clamp(512, warper_stack::runtime::udp_dns::MAX_PAYLOAD) as u16,
            );
            edns.set_dnssec_ok(request_edns.flags().dnssec_ok);
            message.edns = Some(edns);
        }
        let packet = Self {
            message,
            question: self.question,
            limits: self.limits,
        };
        let mut wire = packet.encode_limited(self.udp_payload_limit())?;
        // Set intentional TC only after the entire small message fits. Ordinary
        // encoding still rejects a library-truncated serialization.
        if reply == LocalReply::Truncated && !bad_version {
            wire[2] |= 2;
        }
        Ok(wire)
    }

    pub(super) fn check_synthesis(&self) -> Result<(), Error> {
        if self.is_response()
            || self.message.signature.is_some()
            || !self.message.additionals.is_empty()
        {
            return Err(Error::UnsupportedOperation);
        }
        Ok(())
    }

    pub fn response_code(&self) -> u16 {
        self.message.response_code.into()
    }

    pub fn is_response(&self) -> bool {
        self.message.message_type == MessageType::Response
    }
    pub(super) fn limit_bytes(&self) -> usize {
        self.limits.wire_bytes
    }

    /// Check correlation without decoding the incoming query's records again.
    /// Its complete packet must already have passed request validation. The
    /// query may be larger than the response (for example, EDNS padding).
    pub(super) fn correlate_request(&self, bytes: &[u8]) -> Result<(), Error> {
        let (header, question) = envelope(
            bytes,
            Limits {
                wire_bytes: MAX_WIRE_BYTES,
                records: self.limits.records,
            },
        )?;
        if !self.is_response()
            || header.message_type != MessageType::Query
            || header.id != self.id()
            || question != self.question
        {
            return Err(Error::MismatchedResponse);
        }
        if header.truncation || header.counts.answers != 0 || header.counts.authorities != 0 {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// Apply once before output, using time since this packet was received.
    /// Round elapsed time up so encoded cache TTLs never exceed their original
    /// expiry. Returns the largest remaining record TTL: output completion must
    /// retain coverage for at least this duration and the configured grace.
    /// This allocates nothing and never grants route/output permission.
    pub fn age_response(&mut self, elapsed: Duration) -> Result<Duration, Error> {
        if !self.is_response()
            || self.message.signature.is_some()
            || self
                .message
                .additionals
                .iter()
                .any(|record| matches!(u16::from(record.record_type()), 24 | 250))
            || self
                .message
                .answers
                .iter()
                .chain(&self.message.authorities)
                .any(|record| u16::from(record.record_type()) == 250)
        {
            return Err(Error::UnsupportedOperation);
        }
        let seconds = elapsed
            .as_secs()
            .saturating_add(u64::from(elapsed.subsec_nanos() != 0));
        let seconds = u32::try_from(seconds).unwrap_or(u32::MAX);
        let mut maximum = 0;
        for record in self
            .message
            .answers
            .iter_mut()
            .chain(&mut self.message.authorities)
            .chain(&mut self.message.additionals)
        {
            let ttl = if record.ttl & 0x8000_0000 == 0 {
                record.ttl
            } else {
                0
            };
            record.ttl = ttl.saturating_sub(seconds);
            maximum = maximum.max(record.ttl);
        }
        Ok(Duration::from_secs(u64::from(maximum)))
    }

    /// Encoding is for transport and later gated response handoff. It does not
    /// imply that an answer is safe to expose to an application.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.encode_limited(self.limits.wire_bytes)
    }

    /// Enforce an output limit during encoding. Never silently omit records to
    /// fit a smaller UDP budget; the output owner must explicitly arrange TC.
    pub fn encode_limited(&self, wire_bytes: usize) -> Result<Vec<u8>, Error> {
        if !(HEADER_BYTES..=self.limits.wire_bytes).contains(&wire_bytes) {
            return Err(Error::InvalidLimits);
        }
        let mut bytes = Vec::new();
        let mut encoder = BinEncoder::new(&mut bytes);
        encoder.set_max_size(wire_bytes as u16);
        self.message
            .emit(&mut encoder)
            .map_err(|error| match error {
                ProtoError::MaxBufferSizeExceeded(_) | ProtoError::NotAllRecordsWritten { .. } => {
                    Error::ResourceLimit
                }
                _ => Error::Encoding,
            })?;
        // Hickory marks overflowed record sections TC instead of returning an
        // encoding error. Keep an incomplete serialization out of the gate.
        if bytes[2] & 2 != 0 {
            return Err(Error::ResourceLimit);
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8], question: Question, limits: Limits) -> Result<Self, Error> {
        let mut decoder = BinDecoder::new(bytes);
        let message = Message::read(&mut decoder).map_err(|_| Error::Malformed)?;
        if decoder.index() != bytes.len() {
            return Err(Error::Malformed);
        }
        Ok(Self {
            message,
            question,
            limits,
        })
    }
}

impl fmt::Debug for Packet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Packet([redacted])")
    }
}

fn envelope(bytes: &[u8], limits: Limits) -> Result<(Header, Question), Error> {
    limits.admit(bytes)?;
    let mut decoder = BinDecoder::new(bytes);
    let header = Header::read(&mut decoder).map_err(|_| Error::Malformed)?;
    if header.op_code != OpCode::Query {
        return Err(Error::UnsupportedOperation);
    }
    let query = Query::read(&mut decoder).map_err(|_| Error::Malformed)?;
    let question = Question {
        name: Name::from_labels(query.name.iter()).map_err(|_| Error::Malformed)?,
        record_type: query.query_type.into(),
        class: query.query_class.into(),
    };
    Ok((header, question))
}

#[cfg(test)]
mod tests;
