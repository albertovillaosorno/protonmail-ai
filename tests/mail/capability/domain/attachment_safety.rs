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
//   - Synthetic evidence for provider-neutral attachment output safety.
// - Must-Not:
//   - Touch the filesystem, network, provider state, or real attachment data.
// - Allows:
//   - Exercise filename/path normalization and frozen inline-size limits.
// - Split-When:
//   - Filesystem containment requires process-level acceptance fixtures.
// - Merge-When:
//   - Attachment transport tests fully own these pure safety invariants.
// - Summary:
//   - Proves untrusted attachment names and destinations fail closed safely.
// - Description:
//   - Covers traversal, portability, Unicode, redaction, and byte ceilings.
// - Usage:
//   - Run through the `mail_capability_domain` integration-test target.
// - Defaults:
//   - Synthetic strings and lengths only; no I/O.
//

//! Integration evidence for pure attachment safety primitives.

use mail_capability_domain::MAX_ATTACHMENT_FILENAME_BYTES;
use mail_capability_domain::SanitizedAttachmentFilename;
use mail_capability_domain::attachment_fits_inline;
use mail_capability_domain::contract_v1::MAX_INLINE_ATTACHMENT_BYTES;
use mail_capability_domain::{AttachmentPathError, AttachmentRelativePath};
use std::path::Path;

#[test]
fn filename_sanitization_preserves_unicode_but_removes_path_semantics() {
    let untrusted = "../r\u{e9}sum\u{e9}/2026\\final?.pdf";
    let safe = SanitizedAttachmentFilename::new(untrusted);
    assert_eq!(safe.as_str(), "___r\u{e9}sum\u{e9}_2026_final_.pdf");
    assert!(!safe.as_str().contains('/'));
    assert!(!safe.as_str().contains('\\'));
    assert!(safe.as_str().len() <= MAX_ATTACHMENT_FILENAME_BYTES);
}

#[test]
fn filename_sanitization_handles_empty_hidden_and_reserved_names() {
    assert_eq!(SanitizedAttachmentFilename::new("").as_str(), "attachment");
    assert_eq!(
        SanitizedAttachmentFilename::new("...").as_str(),
        "attachment"
    );
    assert_eq!(SanitizedAttachmentFilename::new(".env").as_str(), "_env");
    assert_eq!(
        SanitizedAttachmentFilename::new("CON.txt").as_str(),
        "_CON.txt"
    );
    assert_eq!(SanitizedAttachmentFilename::new("lpt9").as_str(), "_lpt9");
    assert_eq!(
        SanitizedAttachmentFilename::new("COM0.txt").as_str(),
        "COM0.txt"
    );
}

#[test]
fn reserved_filename_prefixing_preserves_the_byte_ceiling() {
    let long_reserved = format!("CON.{}", "x".repeat(300));
    let safe = SanitizedAttachmentFilename::new(&long_reserved);
    assert!(safe.as_str().starts_with("_CON."));
    assert!(safe.as_str().len() <= MAX_ATTACHMENT_FILENAME_BYTES);
}

#[test]
fn filename_sanitization_truncates_only_on_utf8_boundaries() {
    let input = "\u{1f680}".repeat(100);
    let safe = SanitizedAttachmentFilename::new(&input);
    assert!(safe.as_str().len() <= MAX_ATTACHMENT_FILENAME_BYTES);
    assert!(
        safe.as_str()
            .chars()
            .all(|character| character == '\u{1f680}')
    );
    assert_eq!(safe.as_str().chars().count(), 63);
}

#[test]
fn filename_diagnostics_are_redacted() {
    let secret = "synthetic-private-filename.txt";
    let safe = SanitizedAttachmentFilename::new(secret);
    let debug = format!("{safe:?}");
    assert!(!debug.contains(secret));
    assert_eq!(debug, "SanitizedAttachmentFilename(<redacted>)");
}

#[test]
fn relative_destination_normalizes_current_directory_components() {
    let path = AttachmentRelativePath::new("exports/./mail/attachment.bin")
        .expect("safe relative attachment destination");
    assert_eq!(path.as_path(), Path::new("exports/mail/attachment.bin"));
    assert_eq!(format!("{path:?}"), "AttachmentRelativePath(<redacted>)");
}

#[test]
fn relative_destination_rejects_traversal_absolute_and_portability_hazards() {
    for (input, expected) in [
        ("", AttachmentPathError::Empty),
        (".", AttachmentPathError::Empty),
        ("..", AttachmentPathError::ParentTraversal),
        ("exports/../secret", AttachmentPathError::ParentTraversal),
        ("/tmp/output", AttachmentPathError::Absolute),
        ("C:\\temp\\output", AttachmentPathError::UnsupportedSyntax),
        ("folder\\file", AttachmentPathError::UnsupportedSyntax),
        ("folder:file", AttachmentPathError::UnsupportedSyntax),
        ("folder\0file", AttachmentPathError::UnsupportedSyntax),
        ("folder\nfile", AttachmentPathError::UnsupportedSyntax),
    ] {
        assert_eq!(AttachmentRelativePath::new(input), Err(expected));
    }
}

#[test]
fn inline_attachment_boundary_is_exactly_thirty_two_kibibytes() {
    let limit = u64::from(MAX_INLINE_ATTACHMENT_BYTES);
    assert!(attachment_fits_inline(0));
    assert!(attachment_fits_inline(limit));
    assert!(!attachment_fits_inline(limit + 1));
    assert!(!attachment_fits_inline(u64::MAX));
}
