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
use std::mem::take;
use std::path::{Component, Path};

use nix::fcntl::{OFlag, open, openat};
use nix::sys::stat::Mode;
use zeroize::Zeroizing;

const WEB_HANDOFF_PREFIX: &str = "https://mail.proton.me/inbox/#mailto=";
const MAX_RECIPIENT_FIELD_BYTES: usize = 8_192;
const MAX_SUBJECT_BYTES: usize = 2_048;
const MAX_BODY_BYTES: usize = 16_384;
const MAX_BODY_READ_BYTES: u64 = 16_385;
const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Validated input for Proton Mail's web-composer handoff.
#[derive(Clone, Eq, PartialEq)]
pub struct ComposeInput {
    to: Zeroizing<String>,
    cc: Option<Zeroizing<String>>,
    bcc: Option<Zeroizing<String>>,
    subject: Option<Zeroizing<String>>,
    body: Option<Zeroizing<String>>,
}

impl fmt::Debug for ComposeInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ComposeInput(<redacted>)")
    }
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
            to: Zeroizing::new(String::new()),
            cc: None,
            bcc: None,
            subject: None,
            body: None,
        };
        // Delay any filesystem access until the command can actually produce
        // a valid compose URL. Rejected flag sets must not inspect body files.
        let mut body_file: Option<&str> = None;
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
                "--body" => {
                    if body_file.is_some() {
                        return Err(ComposeInputError::DuplicateFlag("--body"));
                    }
                    opt(&mut input.body, value, "--body")?;
                }
                "--body-file" => {
                    if input.body.is_some() || body_file.is_some() {
                        // jig-ignore-next-line: rustfmt fixed error variant.
                        return Err(ComposeInputError::DuplicateFlag("--body/--body-file"));
                    }
                    if value.is_empty() {
                        // jig-ignore-next-line: rustfmt fixed error variant.
                        return Err(ComposeInputError::EmptyValue("--body-file"));
                    }
                    body_file = Some(value);
                }
                // jig-ignore-next-line: rustfmt canonical redacted flag branch.
                _ => return Err(ComposeInputError::UnknownFlag(Zeroizing::new(flag.clone()))),
            }
        }
        input.validate()?;
        if let Some(path) = body_file {
            let body = read_body_file(path)?;
            validate_body(&body)?;
            input.body = Some(body);
        }
        Ok(input)
    }

    /// Builds the encoded Proton Mail web-composer URL.
    #[must_use]
    pub fn web_url(&self) -> Zeroizing<String> {
        let mailto = self.mailto_uri();
        let encoded = percent_encode(&mailto);
        let mut url = Zeroizing::new(String::with_capacity(
            WEB_HANDOFF_PREFIX.len().saturating_add(encoded.len()),
        ));
        url.push_str(WEB_HANDOFF_PREFIX);
        url.push_str(&encoded);
        url
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

    fn mailto_uri(&self) -> Zeroizing<String> {
        let fields = [
            ("subject", self.subject.as_deref()),
            ("cc", self.cc.as_deref()),
            ("bcc", self.bcc.as_deref()),
            ("body", self.body.as_deref()),
        ];
        // A guarded String still releases old plaintext allocations on
        // growth. Reserve every escaped field and delimiter before writing.
        let mut capacity = "mailto:"
            .len()
            .saturating_add(percent_encoded_len(&self.to));
        for (key, item) in fields {
            if let Some(item) = item {
                capacity = capacity
                    .saturating_add(key.len().saturating_add(2))
                    .saturating_add(percent_encoded_len(item));
            }
        }
        let mut value = Zeroizing::new(String::with_capacity(capacity));
        value.push_str("mailto:");
        value.push_str(&percent_encode(&self.to));
        let mut separator = '?';
        for (key, item) in fields {
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
#[derive(Clone, Eq, PartialEq)]
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
    UnknownFlag(Zeroizing<String>),
    /// Recipient text contains an unsafe control or direction marker.
    InvalidRecipient,
    /// Recipient text exceeds the bounded URL handoff size.
    RecipientTooLarge,
    /// Subject text contains an unsafe control or direction marker.
    InvalidSubject,
    /// Subject text exceeds the bounded URL handoff size.
    SubjectTooLarge,
    /// Body text contains a control byte other than tab or line breaks.
    InvalidBody,
    /// The requested UTF-8 body file could not be read.
    BodyFileRead(Zeroizing<String>),
    /// The message body exceeds the web-handoff size bound.
    BodyTooLarge,
}

impl fmt::Debug for ComposeInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingTo => f.write_str("MissingTo"),
            Self::MissingValue => f.write_str("MissingValue"),
            // jig-ignore-next-line: canonical rustfmt static-flag diagnostics.
            Self::DuplicateFlag(flag) => f.debug_tuple("DuplicateFlag").field(flag).finish(),
            // jig-ignore-next-line: canonical rustfmt static-flag diagnostics.
            Self::EmptyValue(flag) => f.debug_tuple("EmptyValue").field(flag).finish(),
            Self::UnknownFlag(_) => f.write_str("UnknownFlag(<redacted>)"),
            Self::InvalidRecipient => f.write_str("InvalidRecipient"),
            Self::RecipientTooLarge => f.write_str("RecipientTooLarge"),
            Self::InvalidSubject => f.write_str("InvalidSubject"),
            Self::SubjectTooLarge => f.write_str("SubjectTooLarge"),
            Self::InvalidBody => f.write_str("InvalidBody"),
            Self::BodyFileRead(_) => f.write_str("BodyFileRead(<redacted>)"),
            Self::BodyTooLarge => f.write_str("BodyTooLarge"),
        }
    }
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
            Self::UnknownFlag(_flag) => f.write_str("unknown compose flag"),
            Self::InvalidRecipient => f.write_str("recipient contains control"),
            // jig-ignore-next-line: rustfmt canonical size diagnostic.
            Self::RecipientTooLarge => f.write_str("recipient exceeds 8192 bytes"),
            Self::InvalidSubject => f.write_str("subject contains control"),
            Self::SubjectTooLarge => f.write_str("subject exceeds 2048 bytes"),
            Self::InvalidBody => f.write_str("body contains control"),
            Self::BodyFileRead(_path) => f.write_str("cannot read body file"),
            Self::BodyTooLarge => f.write_str("body exceeds 16384 bytes"),
        }
    }
}

fn set_required(
    target: &mut Zeroizing<String>,
    value: &str,
    flag: &'static str,
) -> Result<(), ComposeInputError> {
    if !target.is_empty() {
        return Err(ComposeInputError::DuplicateFlag(flag));
    }
    if value.is_empty() {
        return Err(ComposeInputError::EmptyValue(flag));
    }
    *target = Zeroizing::new(String::from(value));
    Ok(())
}

// jig-ignore-next-line: canonical rustfmt private helper signature.
fn opt(dst: &mut Option<Zeroizing<String>>, val: &str, key: &'static str) -> HResult<()> {
    if dst.is_some() {
        return Err(ComposeInputError::DuplicateFlag(key));
    }
    if val.is_empty() {
        return Err(ComposeInputError::EmptyValue(key));
    }
    *dst = Some(Zeroizing::new(String::from(val)));
    Ok(())
}

fn read_body_file(path: &str) -> HResult<Zeroizing<String>> {
    // A caller-selected path may name a FIFO, device, or symlink to unrelated
    // content. Resolve every directory via no-follow descriptor-relative
    // opens, then inspect the final held inode before reading any bytes.
    let file = open_body_file_without_links(path)?;
    let metadata = file.metadata().map_err(|_error| body_file_error(path))?;
    if !metadata.is_file() {
        return Err(body_file_error(path));
    }
    // The fixed 16-KiB-plus-one read ceiling fits in one zeroizing Vec.
    // String::read_to_string would grow the String and release older body
    // prefixes without erasure before the final Zeroizing drop.
    // jig-ignore-next-line: canonical bounded body buffer capacity.
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_BODY_BYTES.saturating_add(1)));
    file.take(MAX_BODY_READ_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|_error| body_file_error(path))?;
    if bytes.len() > MAX_BODY_BYTES {
        return Err(ComposeInputError::BodyTooLarge);
    }
    // Reuse the preallocated buffer as a guarded String. Invalid UTF-8
    // retains zeroizing ownership of the rejected input allocation.
    let body = String::from_utf8(take(&mut *bytes)).map_err(|error| {
        let _rejected = Zeroizing::new(error.into_bytes());
        body_file_error(path)
    })?;
    Ok(Zeroizing::new(body))
}

// Traversing by pathname would follow intermediate symlink aliases despite
// O_NOFOLLOW at the file leaf. Hold every ancestor directory descriptor and
// never follow an alias while resolving the explicitly selected body file.
fn open_body_file_without_links(path: &str) -> HResult<File> {
    if path.ends_with('/') || path.ends_with("/.") {
        return Err(body_file_error(path));
    }
    let selected = Path::new(path);
    let leaf = selected.file_name().ok_or_else(|| body_file_error(path))?;
    let parent_flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY;
    let parent_flags = parent_flags | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let start = if selected.is_absolute() {
        Path::new("/")
    } else {
        Path::new(".")
    };
    let initial = open(start, parent_flags, Mode::empty());
    let mut directory = initial.map_err(|_error| body_file_error(path))?;
    if let Some(parent) = selected.parent() {
        for component in parent.components() {
            let name = match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => Path::new(name),
                Component::ParentDir => Path::new(".."),
                Component::Prefix(_) => return Err(body_file_error(path)),
            };
            directory = openat(&directory, name, parent_flags, Mode::empty())
                .map_err(|_error| body_file_error(path))?;
        }
    }
    // Nonblocking open prevents a FIFO from hanging while a writer is absent;
    // the held inode must still be a regular file before reading.
    let file_flags = OFlag::O_RDONLY | OFlag::O_NONBLOCK;
    let file_flags = file_flags | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let fd = openat(&directory, Path::new(leaf), file_flags, Mode::empty())
        .map_err(|_error| body_file_error(path))?;
    Ok(File::from(fd))
}

fn body_file_error(path: &str) -> ComposeInputError {
    ComposeInputError::BodyFileRead(Zeroizing::new(String::from(path)))
}

fn validate_recipients(value: &str) -> Result<(), ComposeInputError> {
    if value.len() > MAX_RECIPIENT_FIELD_BYTES {
        return Err(ComposeInputError::RecipientTooLarge);
    }
    if value.chars().any(invalid_recipient_character) {
        return Err(ComposeInputError::InvalidRecipient);
    }
    Ok(())
}

// A mailto recipient must denote a single unambiguous mailbox token.
const fn invalid_recipient_character(character: char) -> bool {
    character.is_whitespace()
        || character == '\u{fffd}'
        || matches!(character, '<' | '>' | ',' | ';' | ':')
        || invalid_single_line_character(character)
}

fn validate_single_line(value: &str) -> Result<(), ComposeInputError> {
    if value.len() > MAX_SUBJECT_BYTES {
        return Err(ComposeInputError::SubjectTooLarge);
    }
    if value.chars().any(invalid_subject_character) {
        return Err(ComposeInputError::InvalidSubject);
    }
    Ok(())
}

// Human-language subjects use grapheme joiners and variation selectors;
// route-bound recipient addresses retain the stricter single-line gate.
const fn invalid_subject_character(character: char) -> bool {
    invalid_single_line_character(character)
        && !matches!(
            character,
            '\u{180b}'..='\u{180d}' | '\u{200c}'..='\u{200d}'
                | '\u{fe00}'..='\u{fe0f}' | '\u{e0100}'..='\u{e01ef}'
        )
}

// Unicode noncharacters have no stable display semantics in an outgoing
// header; unlike message bodies, recipient and subject fields must be clear.
#[expect(
    clippy::as_conversions,
    reason = "lossless char to scalar conversion inside stable const validator"
)]
const fn is_header_noncharacter(character: char) -> bool {
    let codepoint = character as u32;
    matches!(codepoint, 0xfdd0..=0xfdef) || codepoint & 0xfffe == 0xfffe
}

// A visually hidden selector, bidirectional override, or Unicode newline
// can make the apparent recipient/subject differ from the encoded header.
// Preserve ordinary printable Unicode; the body is intentionally multiline.
const fn invalid_single_line_character(character: char) -> bool {
    character.is_control()
        || is_header_noncharacter(character)
        || matches!(
            character,
            '\u{00ad}' | '\u{034f}' | '\u{061c}' | '\u{0600}'..='\u{0605}'
                | '\u{06dd}' | '\u{070f}' | '\u{0890}'..='\u{0891}' | '\u{08e2}'
                | '\u{115f}'..='\u{1160}'
                | '\u{17b4}'..='\u{17b5}' | '\u{1bca0}'..='\u{1bca3}'
                | '\u{180b}'..='\u{180f}' | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}'
                // jig-ignore-next-line: canonical rustfmt Unicode scalar range.
                | '\u{2800}' | '\u{3164}' | '\u{fe00}'..='\u{fe0f}' | '\u{feff}' | '\u{ffa0}'
                | '\u{fff9}'..='\u{fffb}' | '\u{110bd}' | '\u{110cd}'
                | '\u{13430}'..='\u{1343f}' | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0001}' | '\u{e0020}'..='\u{e007f}'
                | '\u{e0100}'..='\u{e01ef}'
        )
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

fn percent_encode(value: &str) -> Zeroizing<String> {
    // Escapes can triple the UTF-8 byte count. Reserve once so private
    // partially encoded prefixes never survive in freed String allocations.
    // jig-ignore-next-line: canonical exact escaped output capacity.
    let mut encoded = Zeroizing::new(String::with_capacity(percent_encoded_len(value)));
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

fn percent_encoded_len(value: &str) -> usize {
    value.bytes().fold(0usize, |size, byte| {
        size.saturating_add(if is_unreserved(byte) { 1 } else { 3 })
    })
}

const fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}
