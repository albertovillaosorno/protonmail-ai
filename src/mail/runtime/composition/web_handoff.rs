// Copyright:
//   - Copyright © 2026 Alberto Villa Osorno.
// SPDX-License-Identifier:
//   - GPL-3.0-only
// Confidential:
//   - false
// License-File:
//   - LICENSE
//
// Boundary-Contract:
// - Owns:
//   - Construction of Proton Mail web-composer handoff URLs.
// - Must-Not:
//   - Send mail, access a mailbox, inspect browser state, or persist message
//     data.
// - Allows:
//   - Encode deliberate composition input into Proton Mail's mailto hash
//     handoff.
// - Split-When:
//   - Browser launching or draft persistence needs independent policy.
// - Merge-When:
//   - Web-composer handoff no longer has an independent runtime concern.
// - Summary:
//   - Builds official WebClients mailto handoff URLs.
// - Description:
//   - Applies RFC 3986 percent encoding at the mailto and outer hash layers.
// - Usage:
//   - Used by the `mail compose-url` CLI command.
// - Defaults:
//   - Produces text only; no browser is opened and no side effect occurs.
//

//! Proton Mail web-composer handoff URL construction.

use std::fmt;
use std::fs::File;
use std::io::Read as _;

const WEB_HANDOFF_PREFIX: &str = "https://mail.proton.me/inbox/#mailto=";
const MAX_BODY_BYTES: usize = 16_384;
const MAX_BODY_READ_BYTES: u64 = 16_385;
const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Validated input for Proton Mail's web-composer handoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComposeInput {
    to: String,
    cc: Option<String>,
    bcc: Option<String>,
    subject: Option<String>,
    body: Option<String>,
}

impl ComposeInput {
    /// Parses CLI flag/value pairs into validated composition input.
    ///
    /// # Errors
    ///
    /// Returns a structured error for missing, duplicated, unknown, or unsafe
    /// input.
    pub fn parse(args: &[String]) -> Result<Self, ComposeInputError> {
        let mut input = Self {
            to: String::new(),
            cc: None,
            bcc: None,
            subject: None,
            body: None,
        };
        let mut index = 0usize;
        while index < args.len() {
            let flag = args.get(index).ok_or(ComposeInputError::MissingValue)?;
            index = index.saturating_add(1);
            let value = args.get(index).ok_or(ComposeInputError::MissingValue)?;
            index = index.saturating_add(1);
            match flag.as_str() {
                "--to" => set_required(&mut input.to, value, "--to")?,
                "--cc" => opt(&mut input.cc, value, "--cc")?,
                "--bcc" => opt(&mut input.bcc, value, "--bcc")?,
                "--subject" => {
                    opt(&mut input.subject, value, "--subject")?;
                }
                "--body" => opt(&mut input.body, value, "--body")?,
                "--body-file" => set_body_file(&mut input.body, value)?,
                _ => return Err(ComposeInputError::UnknownFlag(flag.clone())),
            }
        }
        input.validate()?;
        Ok(input)
    }

    /// Builds the encoded Proton Mail web-composer URL.
    #[must_use]
    pub fn web_url(&self) -> String {
        let mailto = self.mailto_uri();
        format!("{WEB_HANDOFF_PREFIX}{}", percent_encode(&mailto))
    }

    fn validate(&self) -> Result<(), ComposeInputError> {
        if self.to.is_empty() {
            return Err(ComposeInputError::MissingTo);
        }
        validate_recipients(&self.to)?;
        if let Some(value) = self.cc.as_deref() {
            validate_recipients(value)?;
        }
        if let Some(value) = self.bcc.as_deref() {
            validate_recipients(value)?;
        }
        if let Some(value) = self.subject.as_deref() {
            validate_single_line(value)?;
        }
        if let Some(value) = self.body.as_deref() {
            validate_body(value)?;
        }
        Ok(())
    }

    fn mailto_uri(&self) -> String {
        let mut value = String::from("mailto:");
        value.push_str(&percent_encode(&self.to));
        let mut separator = '?';
        for (key, item) in [
            ("subject", self.subject.as_deref()),
            ("cc", self.cc.as_deref()),
            ("bcc", self.bcc.as_deref()),
            ("body", self.body.as_deref()),
        ] {
            if let Some(item) = item {
                value.push(separator);
                value.push_str(key);
                value.push('=');
                value.push_str(&percent_encode(item));
                separator = '&';
            }
        }
        value
    }
}

/// Invalid composition input that cannot be encoded safely.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComposeInputError {
    /// No primary recipient was provided.
    MissingTo,
    /// A flag was provided without its value.
    MissingValue,
    /// A single-value flag was repeated.
    DuplicateFlag(&'static str),
    /// A flag value was explicitly empty.
    EmptyValue(&'static str),
    /// An unsupported CLI flag was provided.
    UnknownFlag(String),
    /// Recipient text contains an ASCII control byte.
    InvalidRecipient,
    /// Subject text contains an ASCII control byte.
    InvalidSubject,
    /// Body text contains a control byte other than tab or line breaks.
    InvalidBody,
    /// The requested UTF-8 body file could not be read.
    BodyFileRead(String),
    /// The message body exceeds the web-handoff size bound.
    BodyTooLarge,
}

type HResult<T> = Result<T, ComposeInputError>;

impl fmt::Display for ComposeInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingTo => f.write_str("--to is required"),
            Self::MissingValue => f.write_str("compose flag value is missing"),
            Self::DuplicateFlag(flag) => {
                write!(f, "duplicate compose flag: {flag}")
            }
            Self::EmptyValue(flag) => {
                write!(f, "compose flag cannot be empty: {flag}")
            }
            Self::UnknownFlag(flag) => {
                write!(f, "unknown compose flag: {flag}")
            }
            Self::InvalidRecipient => f.write_str("recipient contains control"),
            Self::InvalidSubject => f.write_str("subject contains control"),
            Self::InvalidBody => f.write_str("body contains control"),
            Self::BodyFileRead(path) => {
                write!(f, "cannot read body file: {path}")
            }
            Self::BodyTooLarge => f.write_str("body exceeds 16384 bytes"),
        }
    }
}

fn set_required(
    target: &mut String,
    value: &str,
    flag: &'static str,
) -> Result<(), ComposeInputError> {
    if !target.is_empty() {
        return Err(ComposeInputError::DuplicateFlag(flag));
    }
    if value.is_empty() {
        return Err(ComposeInputError::EmptyValue(flag));
    }
    *target = String::from(value);
    Ok(())
}

fn opt(dst: &mut Option<String>, val: &str, key: &'static str) -> HResult<()> {
    if dst.is_some() {
        return Err(ComposeInputError::DuplicateFlag(key));
    }
    if val.is_empty() {
        return Err(ComposeInputError::EmptyValue(key));
    }
    *dst = Some(String::from(val));
    Ok(())
}

fn set_body_file(target: &mut Option<String>, path: &str) -> HResult<()> {
    if target.is_some() {
        return Err(ComposeInputError::DuplicateFlag("--body/--body-file"));
    }
    if path.is_empty() {
        return Err(ComposeInputError::EmptyValue("--body-file"));
    }
    let body = read_body_file(path)?;
    *target = Some(body);
    Ok(())
}

fn read_body_file(path: &str) -> HResult<String> {
    let file = File::open(path).map_err(|_error| body_file_error(path))?;
    let mut body = String::new();
    file.take(MAX_BODY_READ_BYTES)
        .read_to_string(&mut body)
        .map_err(|_error| body_file_error(path))?;
    if body.len() > MAX_BODY_BYTES {
        return Err(ComposeInputError::BodyTooLarge);
    }
    Ok(body)
}

fn body_file_error(path: &str) -> ComposeInputError {
    ComposeInputError::BodyFileRead(String::from(path))
}

fn validate_recipients(value: &str) -> Result<(), ComposeInputError> {
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(ComposeInputError::InvalidRecipient);
    }
    Ok(())
}

fn validate_single_line(value: &str) -> Result<(), ComposeInputError> {
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(ComposeInputError::InvalidSubject);
    }
    Ok(())
}

fn validate_body(value: &str) -> Result<(), ComposeInputError> {
    if value.len() > MAX_BODY_BYTES {
        return Err(ComposeInputError::BodyTooLarge);
    }
    let invalid = value.bytes().any(is_unsupported_body_byte);
    if invalid {
        return Err(ComposeInputError::InvalidBody);
    }
    Ok(())
}

const fn is_unsupported_body_byte(byte: u8) -> bool {
    byte.is_ascii_control() && !matches!(byte, b'\r' | b'\n' | b'\t')
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if is_unreserved(byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4u32)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0F)]));
        }
    }
    encoded
}

const fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}
