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
    /// Rejects empty/absolute destinations, parent traversal, backslashes,
    /// NUL/control characters, and colon syntax that could become a Windows
    /// drive or alternate-data-stream path on another supported platform.
    pub fn new(untrusted: &str) -> Result<Self, AttachmentPathError> {
        if untrusted.is_empty() {
            return Err(AttachmentPathError::Empty);
        }
        if untrusted
            .chars()
            // jig-ignore-next-line: canonical rustfmt line.
            .any(|character| character == '\\' || character == ':' || character.is_control())
        {
            return Err(AttachmentPathError::UnsupportedSyntax);
        }

        let path = Path::new(untrusted);
        if path.is_absolute() {
            return Err(AttachmentPathError::Absolute);
        }

        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                Component::Normal(value) => normalized.push(value),
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
    stem.strip_prefix(prefix)
        // jig-ignore-next-line: canonical rustfmt line.
        .is_some_and(|suffix| matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"))
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
