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
//   - Provider-neutral attachment filename, destination, and inline-size
//     safety.
// - Must-Not:
//   - Access providers, attachment bytes, output roots, or the filesystem.
// - Allows:
//   - Sanitize untrusted filename metadata and normalize relative destinations.
// - Split-When:
//   - Filesystem output acquires an independent lifecycle or storage policy.
// - Merge-When:
//   - Attachment transport schemas fully own these provider-neutral rules.
// - Summary:
//   - Defines pure attachment output safety primitives.
// - Description:
//   - Prevents filename traversal and enforces the frozen inline-size ceiling.
// - Usage:
//   - Adapters and runtimes validate attachment output before filesystem
//     access.
// - Defaults:
//   - No filesystem access and no provider-specific behavior.
//

//! Provider-neutral attachment output safety primitives.

use core::fmt::{Debug, Formatter, Result as FmtResult};
use std::path::{Component, Path, PathBuf};

use crate::contract_v1::MAX_INLINE_ATTACHMENT_BYTES;

/// Maximum UTF-8 byte length retained for sanitized attachment filename
/// metadata.
pub const MAX_ATTACHMENT_FILENAME_BYTES: usize = 255;
const FALLBACK_ATTACHMENT_FILENAME: &str = "attachment";
const MAX_RELATIVE_PATH_BYTES: usize = 4_096;
const MAX_RELATIVE_PATH_COMPONENTS: usize = 64;

/// A single sanitized attachment filename leaf.
#[derive(Clone, Eq, PartialEq)]
pub struct SanitizedAttachmentFilename(String);

impl SanitizedAttachmentFilename {
    /// Sanitizes untrusted provider filename metadata into one portable leaf.
    ///
    /// Path separators, ASCII controls, and characters reserved by common
    /// desktop filesystems become `_`. Leading dots and Windows device names
    /// are neutralized, trailing spaces/dots are removed, and the result is
    /// truncated on UTF-8 boundaries to [`MAX_ATTACHMENT_FILENAME_BYTES`].
    #[must_use]
    pub fn new(untrusted: &str) -> Self {
        // jig-ignore-next-line: canonical rustfmt line.
        let mut safe = String::with_capacity(untrusted.len().min(MAX_ATTACHMENT_FILENAME_BYTES));
        for character in untrusted.chars() {
            let mapped = if unsafe_filename_character(character) {
                '_'
            } else {
                character
            };
            // jig-ignore-next-line: canonical rustfmt line.
            if safe.len().saturating_add(mapped.len_utf8()) > MAX_ATTACHMENT_FILENAME_BYTES {
                break;
            }
            safe.push(mapped);
        }

        while safe.ends_with([' ', '.']) {
            safe.pop();
        }
        if safe.is_empty() {
            safe.push_str(FALLBACK_ATTACHMENT_FILENAME);
        }
        // jig-ignore-next-line: canonical rustfmt line.
        let leading_dots = safe.bytes().take_while(|byte| *byte == b'.').count();
        if leading_dots != 0 {
            let replacement = "_".repeat(leading_dots);
            safe.replace_range(..leading_dots, &replacement);
        }
        if windows_reserved_filename(&safe) {
            // jig-ignore-next-line: canonical rustfmt line.
            let maximum_original = MAX_ATTACHMENT_FILENAME_BYTES.saturating_sub(1);
            truncate_utf8(&mut safe, maximum_original);
            safe.insert(0, '_');
        }
        Self(safe)
    }

    /// Returns the sanitized leaf for output or public metadata.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for SanitizedAttachmentFilename {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("SanitizedAttachmentFilename(<redacted>)")
    }
}

/// A normalized caller-supplied path strictly relative to an output root.
#[derive(Clone, Eq, PartialEq)]
pub struct AttachmentRelativePath(PathBuf);

impl AttachmentRelativePath {
    /// Validates and normalizes a portable relative attachment destination.
    ///
    /// # Errors
    ///
    /// Rejects empty/absolute destinations, traversal, nonportable Windows
    /// path punctuation, NUL/control, hidden Unicode formatting, device
    /// components, trailing dots/spaces, and drive/stream colon syntax.
    /// Destinations must also fit 4,096 total bytes, 64 path components,
    /// and 255 bytes per path component.
    pub fn new(untrusted: &str) -> Result<Self, AttachmentPathError> {
        if untrusted.is_empty() {
            return Err(AttachmentPathError::Empty);
        }
        if untrusted.len() > MAX_RELATIVE_PATH_BYTES {
            return Err(AttachmentPathError::UnsupportedSyntax);
        }
        if untrusted.chars().any(|character| {
            matches!(character, '\\' | ':' | '?' | '*' | '"' | '<' | '>' | '|')
                || character.is_control()
                || unsafe_filename_format(character)
        }) {
            return Err(AttachmentPathError::UnsupportedSyntax);
        }

        let path = Path::new(untrusted);
        if path.is_absolute() {
            return Err(AttachmentPathError::Absolute);
        }

        let mut normalized = PathBuf::new();
        let mut depth = 0usize;
        for component in path.components() {
            match component {
                Component::Normal(value) => {
                    depth = depth.saturating_add(1);
                    if depth > MAX_RELATIVE_PATH_COMPONENTS
                        || value.len() > MAX_ATTACHMENT_FILENAME_BYTES
                    {
                        return Err(AttachmentPathError::UnsupportedSyntax);
                    }
                    let text = value
                        .to_str()
                        .ok_or(AttachmentPathError::UnsupportedSyntax)?;
                    let has_nonportable_suffix = text.ends_with([' ', '.']);
                    let reserved = windows_reserved_filename(text);
                    if has_nonportable_suffix || reserved {
                        return Err(AttachmentPathError::UnsupportedSyntax);
                    }
                    normalized.push(value);
                }
                Component::CurDir => {}
                // jig-ignore-next-line: canonical rustfmt line.
                Component::ParentDir => return Err(AttachmentPathError::ParentTraversal),
                Component::RootDir | Component::Prefix(_) => {
                    return Err(AttachmentPathError::Absolute);
                }
            }
        }
        if normalized.as_os_str().is_empty() {
            return Err(AttachmentPathError::Empty);
        }
        Ok(Self(normalized))
    }

    /// Returns the normalized path for a later contained filesystem boundary.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl Debug for AttachmentRelativePath {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("AttachmentRelativePath(<redacted>)")
    }
}

/// Why an attachment destination was rejected before filesystem access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentPathError {
    /// No usable relative path remains after normalization.
    Empty,
    /// The destination is absolute or carries a platform root/prefix.
    Absolute,
    /// The destination attempts to traverse to a parent component.
    ParentTraversal,
    /// The destination contains non-portable or control syntax.
    UnsupportedSyntax,
}

/// Reports whether an attachment may be returned inline under the v1 bound.
#[must_use]
pub fn attachment_fits_inline(byte_length: u64) -> bool {
    byte_length <= u64::from(MAX_INLINE_ATTACHMENT_BYTES)
}

const fn unsafe_filename_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '/' | '\\' | '<' | '>' | ':' | '"' | '|' | '?' | '*'
        )
        || unsafe_filename_format(character)
}

// Unicode formatting characters can disguise file extensions or path leaves.
const fn unsafe_filename_format(character: char) -> bool {
    matches!(
        character,
        '\u{00ad}' | '\u{034f}' | '\u{061c}'
            | '\u{115f}' | '\u{1160}' | '\u{180b}'..='\u{180e}'
            | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}' | '\u{2800}' | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}' | '\u{feff}' | '\u{ffa0}'
            | '\u{e0001}' | '\u{e0020}'..='\u{e007f}'
            | '\u{e0100}'..='\u{e01ef}'
    )
}

fn windows_reserved_filename(filename: &str) -> bool {
    let stem = filename
        .split_once('.')
        .map_or(filename, |(before_extension, _extension)| before_extension)
        .trim_end_matches([' ', '.']);
    let uppercase = stem.to_ascii_uppercase();
    matches!(uppercase.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || reserved_numbered_device(&uppercase, "COM")
        || reserved_numbered_device(&uppercase, "LPT")
}

fn reserved_numbered_device(stem: &str, prefix: &str) -> bool {
    stem.strip_prefix(prefix).is_some_and(|suffix| {
        matches!(
            suffix,
            // jig-ignore-next-line: rustfmt canonical device-suffix literals.
            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "\u{b9}" | "\u{b2}" | "\u{b3}"
        )
    })
}

fn truncate_utf8(value: &mut String, maximum_bytes: usize) {
    if value.len() <= maximum_bytes {
        return;
    }
    let mut boundary = maximum_bytes;
    while !value.is_char_boundary(boundary) {
        boundary = boundary.saturating_sub(1);
    }
    value.truncate(boundary);
}
