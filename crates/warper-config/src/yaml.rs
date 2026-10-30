// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded YAML decoding, not configuration schema or semantic validation.
//!
//! A decoded value must never be used as approval to start networking or import
//! credentials. Values deliberately have redacted Debug output.

use std::{collections::BTreeMap, fmt};

use yaml_rust2::{
    parser::{Event, Parser, Tag},
    scanner::TScalarStyle,
};

pub const MAX_SOURCE_BYTES: usize = 1_048_576;
pub const MAX_NODES: usize = 65_536;
pub const MAX_DEPTH: usize = 16;

/// Integer and float spelling is preserved for later field-specific conversion.
/// In particular, an overflowing integer never becomes a string or float.
#[derive(Clone, Eq, PartialEq)]
pub enum Value {
    String(String),
    Boolean(bool),
    Integer(String),
    Float(String),
    Sequence(Vec<Value>),
    Mapping(BTreeMap<String, Value>),
}

impl fmt::Debug for Value {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Value(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Category {
    InvalidConfig,
    ResourceLimit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reason {
    SourceLimit,
    NodeLimit,
    DepthLimit,
    InvalidUtf8,
    Syntax,
    DocumentCount,
    ExpectedMapping,
    AnchorsOrAliases,
    UnsupportedTag,
    MismatchedTag,
    Null,
    NonStringKey,
    DuplicateKey,
}

impl Reason {
    pub fn category(self) -> Category {
        match self {
            Self::SourceLimit | Self::NodeLimit | Self::DepthLimit => Category::ResourceLimit,
            _ => Category::InvalidConfig,
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::SourceLimit => "configuration source exceeds 1 MiB",
            Self::NodeLimit => "configuration exceeds the YAML node limit",
            Self::DepthLimit => "configuration exceeds the YAML depth limit",
            Self::InvalidUtf8 => "configuration must be UTF-8",
            Self::Syntax => "invalid YAML syntax",
            Self::DocumentCount => "provide exactly one YAML document",
            Self::ExpectedMapping => "configuration root must be a mapping",
            Self::AnchorsOrAliases => "YAML anchors and aliases are not allowed",
            Self::UnsupportedTag => "custom or unsupported YAML tags are not allowed",
            Self::MismatchedTag => "YAML tag does not match its value",
            Self::Null => "null values are not allowed; omit optional fields instead",
            Self::NonStringKey => "mapping keys must be strings",
            Self::DuplicateKey => "remove the duplicate mapping key",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    pub field: String,
    pub reason: Reason,
}

impl Error {
    fn new(field: &str, reason: Reason) -> Self {
        Self {
            field: field.into(),
            reason,
        }
    }

    pub fn category(&self) -> Category {
        self.reason.category()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:?} at {}: {}",
            self.category(),
            self.field,
            self.reason.message()
        )
    }
}

impl std::error::Error for Error {}

/// Decode one bounded UTF-8 mapping. No environment, files, or OS state are read.
/// Unknown fields, required fields, ranges, and backend semantics are not checked.
pub fn decode(source: &[u8]) -> Result<Value, Error> {
    decode_with_limits(source, MAX_SOURCE_BYTES, MAX_NODES, MAX_DEPTH)
}

fn decode_with_limits(
    source: &[u8],
    source_limit: usize,
    node_limit: usize,
    depth_limit: usize,
) -> Result<Value, Error> {
    if source.len() > source_limit {
        return Err(Error::new("$", Reason::SourceLimit));
    }
    let source = std::str::from_utf8(source).map_err(|_| Error::new("$", Reason::InvalidUtf8))?;
    // The character-stream API does not consume a UTF-8 byte-order mark.
    // Count it against source admission, then remove only the stream prefix.
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
    let mut decoder = Decoder {
        parser: Parser::new_from_str(source),
        nodes_remaining: node_limit,
        depth_limit,
    };
    if decoder.next("$")? != Event::StreamStart || decoder.next("$")? != Event::DocumentStart {
        return Err(Error::new("$", Reason::DocumentCount));
    }
    let event = decoder.next("$")?;
    let value = decoder.value(event, "$", 0)?;
    if !matches!(value, Value::Mapping(_)) {
        return Err(Error::new("$", Reason::ExpectedMapping));
    }
    if decoder.next("$")? != Event::DocumentEnd || decoder.next("$")? != Event::StreamEnd {
        return Err(Error::new("$", Reason::DocumentCount));
    }
    Ok(value)
}

struct Decoder<'a> {
    parser: Parser<std::str::Chars<'a>>,
    nodes_remaining: usize,
    depth_limit: usize,
}

impl Decoder<'_> {
    fn next(&mut self, field: &str) -> Result<Event, Error> {
        // ScanError can contain input text. Do not retain it as an error source.
        self.parser
            .next_token()
            .map(|(event, _)| event)
            .map_err(|_| Error::new(field, Reason::Syntax))
    }

    fn value(&mut self, event: Event, field: &str, depth: usize) -> Result<Value, Error> {
        if depth > self.depth_limit {
            return Err(Error::new(field, Reason::DepthLimit));
        }
        self.nodes_remaining = self
            .nodes_remaining
            .checked_sub(1)
            .ok_or_else(|| Error::new(field, Reason::NodeLimit))?;
        match event {
            Event::Scalar(text, style, anchor, tag) => {
                reject_anchor(anchor, field)?;
                scalar(text, style, tag, field)
            }
            Event::MappingStart(anchor, tag) => {
                reject_anchor(anchor, field)?;
                check_container_tag(tag, "map", field)?;
                let mut entries = BTreeMap::new();
                loop {
                    let event = self.next(field)?;
                    if event == Event::MappingEnd {
                        break;
                    }
                    let key_field = format!("{field}[key]");
                    // Reject complex keys before recursively allocating their values.
                    if !matches!(event, Event::Scalar(..)) {
                        return Err(Error::new(&key_field, Reason::NonStringKey));
                    }
                    let Value::String(key) = self.value(event, &key_field, depth + 1)? else {
                        return Err(Error::new(&key_field, Reason::NonStringKey));
                    };
                    let child = child_field(field, &key);
                    if entries.contains_key(&key) {
                        return Err(Error::new(&child, Reason::DuplicateKey));
                    }
                    let event = self.next(&child)?;
                    let value = self.value(event, &child, depth + 1)?;
                    entries.insert(key, value);
                }
                Ok(Value::Mapping(entries))
            }
            Event::SequenceStart(anchor, tag) => {
                reject_anchor(anchor, field)?;
                check_container_tag(tag, "seq", field)?;
                let mut values = Vec::new();
                loop {
                    let child = format!("{field}[{}]", values.len());
                    let event = self.next(&child)?;
                    if event == Event::SequenceEnd {
                        break;
                    }
                    values.push(self.value(event, &child, depth + 1)?);
                }
                Ok(Value::Sequence(values))
            }
            Event::Alias(_) => Err(Error::new(field, Reason::AnchorsOrAliases)),
            _ => Err(Error::new(field, Reason::Syntax)),
        }
    }
}

fn reject_anchor(anchor: usize, field: &str) -> Result<(), Error> {
    if anchor != 0 {
        return Err(Error::new(field, Reason::AnchorsOrAliases));
    }
    Ok(())
}

fn check_container_tag(tag: Option<Tag>, expected: &str, field: &str) -> Result<(), Error> {
    if let Some(tag) = tag {
        let tag = core_tag(tag, field)?;
        if tag != expected && tag != "non-specific" {
            return Err(Error::new(field, Reason::MismatchedTag));
        }
    }
    Ok(())
}

fn core_tag(tag: Tag, field: &str) -> Result<&'static str, Error> {
    // The parser resolves handles, including overridden !! handles. Comparing
    // the full URI prevents a custom tag from impersonating a core scalar type.
    match format!("{}{}", tag.handle, tag.suffix).as_str() {
        "!" => Ok("non-specific"),
        "tag:yaml.org,2002:str" => Ok("str"),
        "tag:yaml.org,2002:bool" => Ok("bool"),
        "tag:yaml.org,2002:int" => Ok("int"),
        "tag:yaml.org,2002:float" => Ok("float"),
        "tag:yaml.org,2002:map" => Ok("map"),
        "tag:yaml.org,2002:seq" => Ok("seq"),
        "tag:yaml.org,2002:null" => Err(Error::new(field, Reason::Null)),
        _ => Err(Error::new(field, Reason::UnsupportedTag)),
    }
}

fn scalar(
    text: String,
    style: TScalarStyle,
    tag: Option<Tag>,
    field: &str,
) -> Result<Value, Error> {
    if let Some(tag) = tag {
        return match core_tag(tag, field)? {
            "str" | "non-specific" => Ok(Value::String(text)),
            "bool" => boolean(&text)
                .map(Value::Boolean)
                .ok_or_else(|| Error::new(field, Reason::MismatchedTag)),
            "int" if is_integer(&text) => Ok(Value::Integer(text)),
            "float" if is_float(&text) => Ok(Value::Float(text)),
            _ => Err(Error::new(field, Reason::MismatchedTag)),
        };
    }
    if style != TScalarStyle::Plain {
        return Ok(Value::String(text));
    }
    match text.as_str() {
        "" | "~" | "null" | "Null" | "NULL" => Err(Error::new(field, Reason::Null)),
        _ => {
            if let Some(value) = boolean(&text) {
                Ok(Value::Boolean(value))
            } else if is_integer(&text) {
                Ok(Value::Integer(text))
            } else if is_float(&text) {
                Ok(Value::Float(text))
            } else {
                Ok(Value::String(text))
            }
        }
    }
}

fn boolean(text: &str) -> Option<bool> {
    match text {
        "true" | "True" | "TRUE" => Some(true),
        "false" | "False" | "FALSE" => Some(false),
        _ => None,
    }
}

fn is_integer(text: &str) -> bool {
    let (digits, radix) = if let Some(digits) = text.strip_prefix("0x") {
        (digits, 16)
    } else if let Some(digits) = text.strip_prefix("0o") {
        (digits, 8)
    } else {
        (text.strip_prefix(['+', '-']).unwrap_or(text), 10)
    };
    !digits.is_empty() && digits.chars().all(|digit| digit.is_digit(radix))
}

fn is_float(text: &str) -> bool {
    if matches!(
        text,
        ".inf"
            | ".Inf"
            | ".INF"
            | "+.inf"
            | "+.Inf"
            | "+.INF"
            | "-.inf"
            | "-.Inf"
            | "-.INF"
            | ".nan"
            | ".NaN"
            | ".NAN"
    ) {
        return true;
    }
    // The core float grammar also accepts decimal integers (resolved as int
    // first when implicit). Exclude Rust's extra spellings such as NaN/inf.
    text.bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'+' | b'-' | b'.' | b'e' | b'E'))
        && text.parse::<f64>().is_ok()
}

pub(crate) fn child_field(parent: &str, key: &str) -> String {
    // Only schema vocabulary enters diagnostics. Arbitrary mapping keys can
    // themselves contain secrets, terminal escapes, or a forged field path.
    let known = matches!(
        key,
        "tunnel"
            | "protocols"
            | "ipv6"
            | "dns"
            | "timeouts"
            | "limits"
            | "service"
            | "name"
            | "ip"
            | "ipv6_address"
            | "serve_dns"
            | "mtu"
            | "direct_upstreams"
            | "id"
            | "ssh"
            | "socks5"
            | "wireguard"
            | "domains"
            | "ips"
            | "routing_mode"
            | "host"
            | "port"
            | "user"
            | "password"
            | "password_file"
            | "private_key_file"
            | "private_key_passphrase_file"
            | "known_hosts"
            | "pinned_host_key_sha256"
            | "private_key"
            | "peer_public_key"
            | "preshared_key"
            | "endpoint"
            | "address"
            | "extra_addresses"
            | "persistent_keepalive_secs"
            | "inner_mtu"
            | "autoconnect"
            | "connect_ms"
            | "dns_ms"
            | "dns_route_grace_ms"
            | "tcp_idle_ms"
            | "udp_idle_ms"
            | "flow_max_age_ms"
            | "shutdown_ms"
            | "control_ms"
            | "max_tcp_flows"
            | "max_udp_flows"
            | "max_dns_requests"
            | "max_dns_alias_hops"
            | "max_dns_dependency_queries"
            | "max_dns_endpoint_addresses"
            | "max_dns_lease_entries"
            | "max_dns_cache_entries"
            | "max_dns_state_bytes_total"
            | "max_route_entries"
            | "max_pending_route_ops"
            | "max_queued_datagrams_per_flow"
            | "max_buffered_bytes_total"
            | "max_log_entries"
            | "max_log_message_bytes"
            | "max_control_clients"
            | "max_control_message_bytes"
            | "max_control_inflight_requests"
            | "max_control_events_per_client"
            | "max_control_buffered_bytes_total"
            | "max_control_operations"
    );
    if !known {
        format!("{parent}[key]")
    } else if parent == "$" {
        key.into()
    } else {
        format!("{parent}.{key}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping(source: &str) -> BTreeMap<String, Value> {
        let Value::Mapping(values) = decode(source.as_bytes()).unwrap() else {
            panic!("decoder must return a root mapping");
        };
        values
    }

    #[test]
    fn scalar_types_preserve_quotes_numeric_spelling_and_literal_secrets() {
        struct Case {
            id: &'static str,
            sample: &'static str,
            expected: Value,
        }
        let cases = [
            Case {
                id: "boolean",
                sample: "TRUE",
                expected: Value::Boolean(true),
            },
            Case {
                id: "false",
                sample: "False",
                expected: Value::Boolean(false),
            },
            Case {
                id: "quoted boolean",
                sample: "'true'",
                expected: Value::String("true".into()),
            },
            Case {
                id: "integer",
                sample: "42",
                expected: Value::Integer("42".into()),
            },
            Case {
                id: "overflow",
                sample: "18446744073709551616",
                expected: Value::Integer("18446744073709551616".into()),
            },
            Case {
                id: "hex",
                sample: "0xFF",
                expected: Value::Integer("0xFF".into()),
            },
            Case {
                id: "octal",
                sample: "0o17",
                expected: Value::Integer("0o17".into()),
            },
            Case {
                id: "signed",
                sample: "-1",
                expected: Value::Integer("-1".into()),
            },
            Case {
                id: "leading plus",
                sample: "+12",
                expected: Value::Integer("+12".into()),
            },
            Case {
                id: "signed hexadecimal is not core integer syntax",
                sample: "-0xFF",
                expected: Value::String("-0xFF".into()),
            },
            Case {
                id: "binary is not core integer syntax",
                sample: "0b10",
                expected: Value::String("0b10".into()),
            },
            Case {
                id: "float",
                sample: "12.5",
                expected: Value::Float("12.5".into()),
            },
            Case {
                id: "exponent",
                sample: "1e30",
                expected: Value::Float("1e30".into()),
            },
            Case {
                id: "infinity",
                sample: "-.Inf",
                expected: Value::Float("-.Inf".into()),
            },
            Case {
                id: "nan",
                sample: ".NaN",
                expected: Value::Float(".NaN".into()),
            },
            Case {
                id: "non-core nan",
                sample: "NaN",
                expected: Value::String("NaN".into()),
            },
            Case {
                id: "non-core bool",
                sample: "yes",
                expected: Value::String("yes".into()),
            },
            Case {
                id: "empty string",
                sample: "''",
                expected: Value::String(String::new()),
            },
            Case {
                id: "quoted null",
                sample: "'null'",
                expected: Value::String("null".into()),
            },
            Case {
                id: "unicode",
                sample: "пароль",
                expected: Value::String("пароль".into()),
            },
            Case {
                id: "substitutions",
                sample: "'$HOME/`sample`/$(sample)'",
                expected: Value::String("$HOME/`sample`/$(sample)".into()),
            },
            Case {
                id: "explicit string",
                sample: "!!str 42",
                expected: Value::String("42".into()),
            },
            Case {
                id: "explicit bool",
                sample: "!!bool 'true'",
                expected: Value::Boolean(true),
            },
            Case {
                id: "explicit int",
                sample: "!!int '0xFF'",
                expected: Value::Integer("0xFF".into()),
            },
            Case {
                id: "explicit float",
                sample: "!!float 42",
                expected: Value::Float("42".into()),
            },
            Case {
                id: "verbatim string tag",
                sample: "!<tag:yaml.org,2002:str> 42",
                expected: Value::String("42".into()),
            },
            Case {
                id: "non-specific tag suppresses scalar resolution",
                sample: "! null",
                expected: Value::String("null".into()),
            },
        ];
        for case in cases {
            assert_eq!(
                mapping(&format!("password: {}", case.sample))["password"],
                case.expected,
                "{}",
                case.id
            );
        }
        assert_eq!(
            mapping("password: |\n  sample\n")["password"],
            Value::String("sample\n".into())
        );
        assert_eq!(
            mapping("password: >\n  sample\n  value\n")["password"],
            Value::String("sample value\n".into())
        );
    }

    #[test]
    fn rejects_unsupported_yaml_with_redacted_field_diagnostics() {
        struct Case {
            id: &'static str,
            sample: &'static str,
            expected_field: &'static str,
            expected_reason: Reason,
        }
        let cases = [
            Case {
                id: "missing document",
                sample: "# sample",
                expected_field: "$",
                expected_reason: Reason::DocumentCount,
            },
            Case {
                id: "scalar root",
                sample: "sample",
                expected_field: "$",
                expected_reason: Reason::ExpectedMapping,
            },
            Case {
                id: "sequence root",
                sample: "[]",
                expected_field: "$",
                expected_reason: Reason::ExpectedMapping,
            },
            Case {
                id: "multiple documents",
                sample: "{}\n---\n{}",
                expected_field: "$",
                expected_reason: Reason::DocumentCount,
            },
            Case {
                id: "invalid syntax",
                sample: "password: [sample-secret",
                expected_field: "password[1]",
                expected_reason: Reason::Syntax,
            },
            Case {
                id: "duplicate",
                sample: "tunnel: {ip: sample, ip: other}",
                expected_field: "tunnel.ip",
                expected_reason: Reason::DuplicateKey,
            },
            Case {
                id: "sequence duplicate",
                sample: "protocols: [{socks5: {host: sample, host: other}}]",
                expected_field: "protocols[0].socks5.host",
                expected_reason: Reason::DuplicateKey,
            },
            Case {
                id: "escaped duplicate",
                sample: "password: sample\n\"passw\\u006frd\": other",
                expected_field: "password",
                expected_reason: Reason::DuplicateKey,
            },
            Case {
                id: "unknown duplicate",
                sample: "sample-secret: a\nsample-secret: b",
                expected_field: "$[key]",
                expected_reason: Reason::DuplicateKey,
            },
            Case {
                id: "null",
                sample: "password: null",
                expected_field: "password",
                expected_reason: Reason::Null,
            },
            Case {
                id: "capital null",
                sample: "password: NULL",
                expected_field: "password",
                expected_reason: Reason::Null,
            },
            Case {
                id: "title null",
                sample: "password: Null",
                expected_field: "password",
                expected_reason: Reason::Null,
            },
            Case {
                id: "empty value",
                sample: "password:",
                expected_field: "password",
                expected_reason: Reason::Null,
            },
            Case {
                id: "tilde null",
                sample: "password: ~",
                expected_field: "password",
                expected_reason: Reason::Null,
            },
            Case {
                id: "explicit null",
                sample: "password: !!null null",
                expected_field: "password",
                expected_reason: Reason::Null,
            },
            Case {
                id: "scalar anchor",
                sample: "password: &sample sample-secret",
                expected_field: "password",
                expected_reason: Reason::AnchorsOrAliases,
            },
            Case {
                id: "mapping anchor",
                sample: "tunnel: &sample {}",
                expected_field: "tunnel",
                expected_reason: Reason::AnchorsOrAliases,
            },
            Case {
                id: "sequence anchor",
                sample: "protocols: &sample []",
                expected_field: "protocols",
                expected_reason: Reason::AnchorsOrAliases,
            },
            Case {
                id: "undefined alias",
                sample: "password: *sample-secret",
                expected_field: "password",
                expected_reason: Reason::Syntax,
            },
            Case {
                id: "custom scalar tag",
                sample: "password: !sample sample-secret",
                expected_field: "password",
                expected_reason: Reason::UnsupportedTag,
            },
            Case {
                id: "custom mapping tag",
                sample: "tunnel: !sample {}",
                expected_field: "tunnel",
                expected_reason: Reason::UnsupportedTag,
            },
            Case {
                id: "custom sequence tag",
                sample: "protocols: !sample []",
                expected_field: "protocols",
                expected_reason: Reason::UnsupportedTag,
            },
            Case {
                id: "overridden core handle",
                sample: "%TAG !! tag:sample.test,2026:\n---\npassword: !!str sample-secret",
                expected_field: "password",
                expected_reason: Reason::UnsupportedTag,
            },
            Case {
                id: "tagged boolean mismatch",
                sample: "ipv6: !!bool sample-secret",
                expected_field: "ipv6",
                expected_reason: Reason::MismatchedTag,
            },
            Case {
                id: "tagged integer mismatch",
                sample: "tunnel: {mtu: !!int '1.5'}",
                expected_field: "tunnel.mtu",
                expected_reason: Reason::MismatchedTag,
            },
            Case {
                id: "tagged float mismatch",
                sample: "tunnel: {mtu: !!float sample-secret}",
                expected_field: "tunnel.mtu",
                expected_reason: Reason::MismatchedTag,
            },
            Case {
                id: "hexadecimal is not a core float",
                sample: "tunnel: {mtu: !!float 0xFF}",
                expected_field: "tunnel.mtu",
                expected_reason: Reason::MismatchedTag,
            },
            Case {
                id: "tagged container mismatch",
                sample: "tunnel: !!seq {}",
                expected_field: "tunnel",
                expected_reason: Reason::MismatchedTag,
            },
            Case {
                id: "tagged scalar mismatch",
                sample: "tunnel: !!map sample-secret",
                expected_field: "tunnel",
                expected_reason: Reason::MismatchedTag,
            },
            Case {
                id: "integer key",
                sample: "42: sample-secret",
                expected_field: "$[key]",
                expected_reason: Reason::NonStringKey,
            },
            Case {
                id: "complex key",
                sample: "? [sample-secret]\n: value",
                expected_field: "$[key]",
                expected_reason: Reason::NonStringKey,
            },
        ];
        for case in cases {
            let error = decode(case.sample.as_bytes()).unwrap_err();
            assert_eq!(error.field, case.expected_field, "{}", case.id);
            assert_eq!(error.reason, case.expected_reason, "{}", case.id);
            assert_eq!(error.category(), Category::InvalidConfig, "{}", case.id);
            assert!(
                !format!("{error} {error:?}").contains("sample-secret"),
                "{}",
                case.id
            );
        }
    }

    #[test]
    fn bounds_source_nodes_and_depth_at_the_admission_boundary() {
        assert_eq!(decode(&[0xff]).unwrap_err().reason, Reason::InvalidUtf8);
        // Size admission must precede UTF-8 validation.
        assert_eq!(
            decode_with_limits(&[0xff; 2], 1, 10, 10)
                .unwrap_err()
                .reason,
            Reason::SourceLimit
        );
        let mut source = b"password: ".to_vec();
        source.resize(MAX_SOURCE_BYTES, b'a');
        assert!(decode(&source).is_ok());
        source.push(b'a');
        let error = decode(&source).unwrap_err();
        assert_eq!(error.reason, Reason::SourceLimit);
        assert_eq!(error.category(), Category::ResourceLimit);
        assert!(decode_with_limits(b"ip: sample", 10, 3, 1).is_ok());
        assert_eq!(
            decode_with_limits(b"ip: sample", 10, 2, 1)
                .unwrap_err()
                .reason,
            Reason::NodeLimit
        );
        assert_eq!(
            decode_with_limits(b"{}", 2, 0, 1).unwrap_err().reason,
            Reason::NodeLimit
        );
        let source = format!(
            "{}sample{}",
            "{ip: ".repeat(MAX_DEPTH),
            "}".repeat(MAX_DEPTH)
        );
        assert!(decode(source.as_bytes()).is_ok());
        let source = format!("{{ip: {source}}}");
        let error = decode(source.as_bytes()).unwrap_err();
        assert_eq!(error.reason, Reason::DepthLimit);
        assert_eq!(error.category(), Category::ResourceLimit);
        let source = format!("protocols: [{}]", "true,".repeat(MAX_NODES - 3));
        assert!(decode(source.as_bytes()).is_ok());
        let source = format!("protocols: [{}]", "true,".repeat(MAX_NODES - 2));
        assert_eq!(
            decode(source.as_bytes()).unwrap_err().reason,
            Reason::NodeLimit
        );
    }

    #[test]
    fn containers_preserve_order_and_debug_never_exposes_decoded_values() {
        let values =
            mapping("!!map {protocols: !!seq [sample-secret, other], password: sample-secret}");
        assert_eq!(
            values["protocols"],
            Value::Sequence(vec![
                Value::String("sample-secret".into()),
                Value::String("other".into())
            ])
        );
        for value in values.values() {
            assert!(!format!("{value:?}").contains("sample-secret"));
        }
        assert!(matches!(decode(b"{}"), Ok(Value::Mapping(values)) if values.is_empty()));
        assert!(decode(b"! {protocols: ! [{id: first}, {id: second}]}").is_ok());
        assert!(decode("\u{feff}{}".as_bytes()).is_ok());
        // This stage must not silently acquire schema-validation authority.
        assert!(decode(b"unknown: sample").is_ok());
    }
}
