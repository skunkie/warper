// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Strict field access and reusable normalization. No I/O is performed here.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use idna::uts46::{AsciiDenyList, DnsLength, Hyphens, Uts46};
use warper_core::configuration::paths::Paths;

use super::{Error, Reason};
use crate::yaml::{self, Value};

static EMPTY: BTreeMap<String, Value> = BTreeMap::new();

pub(super) struct Object<'a> {
    values: &'a BTreeMap<String, Value>,
    pub path: String,
}

impl<'a> Object<'a> {
    pub fn new(value: &'a Value, path: impl Into<String>, allowed: &[&str]) -> Result<Self, Error> {
        let path = path.into();
        let Value::Mapping(values) = value else {
            return Err(Error::new(path, Reason::WrongType));
        };
        Self::from_mapping(values, path, allowed)
    }

    fn from_mapping(
        values: &'a BTreeMap<String, Value>,
        path: String,
        allowed: &[&str],
    ) -> Result<Self, Error> {
        for key in values.keys() {
            if !allowed.contains(&key.as_str()) {
                return Err(Error::new(
                    yaml::child_field(&path, key),
                    Reason::UnknownField,
                ));
            }
        }
        Ok(Self { values, path })
    }

    pub fn field(&self, name: &str) -> String {
        yaml::child_field(&self.path, name)
    }
    pub fn get(&self, name: &str) -> Option<&'a Value> {
        self.values.get(name)
    }
    pub fn required(&self, name: &str) -> Result<&'a Value, Error> {
        self.get(name)
            .ok_or_else(|| Error::new(self.field(name), Reason::MissingField))
    }
    pub fn child(&self, name: &str, allowed: &[&str]) -> Result<Self, Error> {
        match self.get(name) {
            Some(value) => Self::new(value, self.field(name), allowed),
            None => Self::from_mapping(&EMPTY, self.field(name), allowed),
        }
    }
    pub fn string(&self, name: &str) -> Result<Option<String>, Error> {
        match self.get(name) {
            None => Ok(None),
            Some(Value::String(value)) => Ok(Some(value.clone())),
            Some(_) => Err(Error::new(self.field(name), Reason::WrongType)),
        }
    }
    pub fn required_string(&self, name: &str) -> Result<String, Error> {
        self.string(name)?
            .ok_or_else(|| Error::new(self.field(name), Reason::MissingField))
    }
    pub fn boolean(&self, name: &str, default: bool) -> Result<bool, Error> {
        match self.get(name) {
            None => Ok(default),
            Some(Value::Boolean(value)) => Ok(*value),
            Some(_) => Err(Error::new(self.field(name), Reason::WrongType)),
        }
    }
    pub fn number(&self, name: &str, default: u64, min: u64, max: u64) -> Result<u64, Error> {
        match self.get(name) {
            None => Ok(default),
            Some(Value::Integer(text)) => {
                let result = if let Some(digits) = text.strip_prefix("0x") {
                    u64::from_str_radix(digits, 16)
                } else if let Some(digits) = text.strip_prefix("0o") {
                    u64::from_str_radix(digits, 8)
                } else {
                    text.parse()
                };
                let value = result.map_err(|_| Error::new(self.field(name), Reason::OutOfRange))?;
                if value < min || value > max {
                    return Err(Error::new(self.field(name), Reason::OutOfRange));
                }
                Ok(value)
            }
            Some(_) => Err(Error::new(self.field(name), Reason::WrongType)),
        }
    }
    pub fn sequence(&self, name: &str, required: bool) -> Result<&'a [Value], Error> {
        match self.get(name) {
            None if !required => Ok(&[]),
            None => Err(Error::new(self.field(name), Reason::MissingField)),
            Some(Value::Sequence(values)) => Ok(values),
            Some(_) => Err(Error::new(self.field(name), Reason::WrongType)),
        }
    }
    pub fn strings(&self, name: &str) -> Result<Vec<String>, Error> {
        self.sequence(name, false)?
            .iter()
            .enumerate()
            .map(|(index, value)| match value {
                Value::String(value) => Ok(value.clone()),
                _ => Err(Error::new(
                    format!("{}[{index}]", self.field(name)),
                    Reason::WrongType,
                )),
            })
            .collect()
    }
    pub fn path(&self, name: &str, paths: &Paths) -> Result<Option<std::path::PathBuf>, Error> {
        self.string(name)?
            .map(|sample| {
                paths
                    .resolve_value(&sample)
                    .map_err(|error| Error::new(self.field(name), Reason::Path(error)))
            })
            .transpose()
    }
}

pub(super) fn address(text: &str, field: &str) -> Result<IpAddr, Error> {
    let value: IpAddr = text
        .parse()
        .map_err(|_| Error::new(field, Reason::InvalidAddress))?;
    if value.is_unspecified()
        || value.is_multicast()
        || matches!(value, IpAddr::V4(value) if value.is_broadcast())
    {
        return Err(Error::new(field, Reason::InvalidAddress));
    }
    Ok(value)
}

pub(super) fn local_address(text: &str, field: &str) -> Result<IpAddr, Error> {
    let value = address(text, field)?;
    if value.is_loopback() || matches!(value, IpAddr::V6(value) if value.is_unicast_link_local()) {
        return Err(Error::new(field, Reason::InvalidAddress));
    }
    Ok(value)
}

pub(super) fn addresses(object: &Object<'_>, name: &str) -> Result<Vec<IpAddr>, Error> {
    let mut seen = BTreeSet::new();
    object
        .strings(name)?
        .iter()
        .enumerate()
        .map(|(index, text)| {
            let field = format!("{}[{index}]", object.field(name));
            let value = address(text, &field)?;
            if !seen.insert(value) {
                return Err(Error::new(field, Reason::DuplicateAddress));
            }
            Ok(value)
        })
        .collect()
}

pub(super) fn domain(text: &str, field: &str) -> Result<String, Error> {
    let ascii = Uts46::new()
        .to_ascii(
            text.as_bytes(),
            AsciiDenyList::STD3,
            Hyphens::CheckFirstLast,
            DnsLength::VerifyAllowRootDot,
        )
        .map_err(|_| Error::new(field, Reason::InvalidDomain))?;
    let value = ascii.strip_suffix('.').unwrap_or(&ascii);
    if value.is_empty() || value.parse::<IpAddr>().is_ok() {
        return Err(Error::new(field, Reason::InvalidDomain));
    }
    Ok(value.to_owned())
}
