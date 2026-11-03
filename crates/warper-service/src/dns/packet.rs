// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Keep third-party DNS types and errors inside the protocol adapter.

use std::fmt;

use hickory_proto::{
    ProtoError,
    op::{Header, Message, MessageType, OpCode, Query},
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
};
use warper_core::dns::Name;

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

    pub fn id(&self) -> u16 {
        self.message.id
    }

    pub fn question(&self) -> Question {
        self.question
    }

    pub fn response_code(&self) -> u16 {
        self.message.response_code.into()
    }

    pub fn is_response(&self) -> bool {
        self.message.message_type == MessageType::Response
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
