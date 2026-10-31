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
use std::path::{Component, Path};
use zeroize::{Zeroize as _, Zeroizing};

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

#[expect(
    clippy::missing_trait_methods,
    reason = "Drop is the explicit scrub-on-drop contract"
)]
impl Drop for SanitizedAttachmentFilename {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl SanitizedAttachmentFilename {
    /// Sanitizes untrusted provider filename metadata into one portable leaf.
    ///
    /// Path separators, ASCII controls, and characters reserved by common
    /// desktop filesystems become `_`. Leading dots and Windows device names
    /// are neutralized, trailing spaces/dots are removed, and the result is
    /// truncated on UTF-8 boundaries to [`MAX_ATTACHMENT_FILENAME_BYTES`].
    #[must_use]
    pub fn new(untrusted: &str) -> Self {
        // The reserved-device prefix may insert one extra byte after a short
        // provider filename. Reserve it now: even a scrub-on-drop String
        // would otherwise release its old private filename on reallocation.
        let capacity = untrusted
            .len()
            .min(MAX_ATTACHMENT_FILENAME_BYTES)
            .saturating_add(1);
        let mut safe = String::with_capacity(capacity);
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
            // The byte removed for the prefix can expose an earlier trailing
            // dot or space, even though the original leaf was already trimmed.
            while safe.ends_with([' ', '.']) {
                safe.pop();
            }
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
pub struct AttachmentRelativePath(Zeroizing<String>);

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
        if untrusted.ends_with('/') || untrusted.contains("//") {
            return Err(AttachmentPathError::UnsupportedSyntax);
        }

        // Build the bounded, portable path directly in one guarded allocation.
        // An ordinary PathBuf would retain private caller file names in heap
        // allocations that are neither erased on failure nor on success.
        // jig-ignore-next-line: canonical rustfmt guarded path allocation.
        let mut normalized = Zeroizing::new(String::with_capacity(untrusted.len()));
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
                    if !normalized.is_empty() {
                        normalized.push('/');
                    }
                    normalized.push_str(text);
                }
                Component::CurDir => {}
                // jig-ignore-next-line: canonical rustfmt line.
                Component::ParentDir => return Err(AttachmentPathError::ParentTraversal),
                Component::RootDir | Component::Prefix(_) => {
                    return Err(AttachmentPathError::Absolute);
                }
            }
        }
        if normalized.is_empty() {
            return Err(AttachmentPathError::Empty);
        }
        Ok(Self(normalized))
    }

    /// Returns the normalized path for a later contained filesystem boundary.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        Path::new(&*self.0)
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
        '\u{00a0}' | '\u{00ad}' | '\u{034f}' | '\u{061c}' | '\u{1680}'
            | '\u{600}'..='\u{605}' | '\u{6dd}' | '\u{70f}'
            | '\u{890}'..='\u{891}' | '\u{8e2}'
            | '\u{fff9}'..='\u{fffb}' | '\u{110bd}' | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}' | '\u{1d173}'..='\u{1d17a}'
            | '\u{115f}' | '\u{1160}' | '\u{180b}'..='\u{180f}'
            | '\u{17b4}'..='\u{17b5}' | '\u{1bca0}'..='\u{1bca3}'
            | '\u{2000}'..='\u{200f}' | '\u{2028}'..='\u{202f}'
            | '\u{205f}' | '\u{2060}'..='\u{206f}' | '\u{2800}'
            | '\u{3000}' | '\u{3164}'
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
    // A case-folded String would make an ordinary, unguarded copy of the
    // provider filename stem even when the name is not reserved.
    ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
        || reserved_numbered_device(stem, "COM")
        || reserved_numbered_device(stem, "LPT")
}

fn reserved_numbered_device(stem: &str, prefix: &str) -> bool {
    let Some(head) = stem.get(..prefix.len()) else {
        return false;
    };
    head.eq_ignore_ascii_case(prefix)
        && stem.get(prefix.len()..).is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2"
                    | "3"
                    | "4"
                    | "5"
                    | "6"
                    | "7"
                    | "8"
                    | "9"
                    | "\u{b9}"
                    | "\u{b2}"
                    | "\u{b3}"
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
