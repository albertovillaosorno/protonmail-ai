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
fn filename_sanitization_neutralizes_spoofing_format_controls() {
    for (untrusted, expected) in [
        ("photo\u{202e}gpj.exe", "photo_gpj.exe"),
        ("report\u{2028}other.pdf", "report_other.pdf"),
        ("account\u{2029}hidden.txt", "account_hidden.txt"),
        ("word\u{200b}joiner.md", "word_joiner.md"),
        ("file\u{2066}name\u{2069}.pdf", "file_name_.pdf"),
        ("hidden\u{feff}.txt", "hidden_.txt"),
        ("test\u{3164}.txt", "test_.txt"),
        ("filename\u{180f}hidden.pdf", "filename_hidden.pdf"),
        ("khmer\u{17b4}vowel.pdf", "khmer_vowel.pdf"),
        ("shorthand\u{1bca3}control.pdf", "shorthand_control.pdf"),
        ("file\u{00a0}name.pdf", "file_name.pdf"),
        ("report\u{2007}copy.txt", "report_copy.txt"),
        ("hidden\u{202f}space.txt", "hidden_space.txt"),
        ("note\u{3000}draft.pdf", "note_draft.pdf"),
    ] {
        let safe = SanitizedAttachmentFilename::new(untrusted);
        assert_eq!(safe.as_str(), expected);
    }
    let normal = "r\u{e9}sum\u{e9}-\u{65c5}\u{884c}.pdf";
    assert_eq!(
        SanitizedAttachmentFilename::new("my report.pdf").as_str(),
        "my report.pdf"
    );
    assert_eq!(SanitizedAttachmentFilename::new(normal).as_str(), normal);
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
fn attachment_filename_sanitization_neutralizes_superscript_devices() {
    for (input, expected) in [
        ("COM\u{b9}.txt", "_COM\u{b9}.txt"),
        ("com\u{b2}", "_com\u{b2}"),
        ("LPT\u{b3}.pdf", "_LPT\u{b3}.pdf"),
        ("LPT0.txt", "LPT0.txt"),
        ("CONIN$", "_CONIN$"),
        ("conout$.txt", "_conout$.txt"),
    ] {
        assert_eq!(SanitizedAttachmentFilename::new(input).as_str(), expected);
    }
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
        (
            "exports/report.pdf/",
            AttachmentPathError::UnsupportedSyntax,
        ),
        (
            "exports//report.pdf",
            AttachmentPathError::UnsupportedSyntax,
        ),
        (
            "exports///report.pdf",
            AttachmentPathError::UnsupportedSyntax,
        ),
        ("/tmp/output", AttachmentPathError::Absolute),
        ("C:\\temp\\output", AttachmentPathError::UnsupportedSyntax),
        ("folder\\file", AttachmentPathError::UnsupportedSyntax),
        ("folder:file", AttachmentPathError::UnsupportedSyntax),
        (
            "exports/report?.pdf",
            AttachmentPathError::UnsupportedSyntax,
        ),
        (
            "exports/report*.pdf",
            AttachmentPathError::UnsupportedSyntax,
        ),
        (
            r#"exports/"report".pdf"#,
            AttachmentPathError::UnsupportedSyntax,
        ),
        (
            "exports/less<more.pdf",
            AttachmentPathError::UnsupportedSyntax,
        ),
        (
            "exports/less>more.pdf",
            AttachmentPathError::UnsupportedSyntax,
        ),
        (
            "exports/pipe|name.pdf",
            AttachmentPathError::UnsupportedSyntax,
        ),
        ("folder\0file", AttachmentPathError::UnsupportedSyntax),
        ("folder\nfile", AttachmentPathError::UnsupportedSyntax),
    ] {
        assert_eq!(AttachmentRelativePath::new(input), Err(expected));
    }
}

#[test]
fn relative_destination_refuses_windows_aliasing_components() {
    for input in [
        "CON",
        "nul.txt",
        "AUX.log",
        "prn",
        "COM1",
        "LPT9.bin",
        "exports/CON.txt",
        "exports/COM\u{b9}.txt",
        "exports/com\u{b2}.txt",
        "exports/LPT\u{b3}",
        "exports/CONIN$",
        "exports/conout$.txt",
        "exports/com3.pdf",
        "lpt1/archive.pdf",
        "exports/folder./report.txt",
        "exports/folder /report.txt",
        "exports/report.",
        "exports/report ",
        "exports/.. ",
    ] {
        assert_eq!(
            AttachmentRelativePath::new(input),
            Err(AttachmentPathError::UnsupportedSyntax),
            "unsafe portable destination must fail closed"
        );
    }
    for input in [
        "exports/COM0.txt",
        "exports/LPT0.txt",
        "exports/report .txt",
        "exports/hello.txt",
        "exports/memo-2026.pdf",
    ] {
        assert!(AttachmentRelativePath::new(input).is_ok());
    }
}

#[test]
fn relative_destination_rejects_hidden_unicode_path_components() {
    for input in [
        "exports/bill\u{202e}fdp.exe",
        "exports/split\u{2028}line.pdf",
        "exports/hidden\u{200b}segment/report.pdf",
        "exports\u{2066}/report\u{2069}.pdf",
        "exports/\u{3164}/report.pdf",
        "exports/report\u{180f}.pdf",
        "exports/khmer\u{17b5}vowel.pdf",
        "exports/shorthand\u{1bca0}control.pdf",
        "exports/CON\u{00a0}.txt",
        "exports/report\u{2007}.pdf",
        "exports/folder\u{202f}name/report.pdf",
        "exports/report\u{3000}.pdf",
    ] {
        assert_eq!(
            AttachmentRelativePath::new(input),
            Err(AttachmentPathError::UnsupportedSyntax)
        );
    }
    let visible = "exports/r\u{e9}sum\u{e9}-\u{65c5}\u{884c}.pdf";
    assert!(AttachmentRelativePath::new("exports/my report.pdf").is_ok());
    assert_eq!(
        AttachmentRelativePath::new(visible)
            .expect("ordinary Unicode remains portable")
            .as_path(),
        Path::new(visible)
    );
}

#[test]
fn relative_destination_bounds_component_path_and_depth_before_io() {
    let overlong_ascii = format!("exports/{}", "a".repeat(256));
    let overlong_unicode = format!("exports/{}", "\u{e9}".repeat(128));
    let too_deep = format!("{}/report.pdf", "dir/".repeat(65));
    let twenty_folders = vec!["a".repeat(210); 20].join("/");
    let oversized_total = format!("{twenty_folders}/report.pdf");
    let invalid = [overlong_ascii, overlong_unicode, too_deep, oversized_total];
    for candidate in invalid {
        assert_eq!(
            AttachmentRelativePath::new(&candidate),
            Err(AttachmentPathError::UnsupportedSyntax),
        );
    }
    let allowed_ascii = format!("exports/{}", "a".repeat(255));
    assert!(AttachmentRelativePath::new(&allowed_ascii).is_ok());
    let allowed_unicode = format!("exports/{}x", "\u{e9}".repeat(127));
    assert!(AttachmentRelativePath::new(&allowed_unicode).is_ok());
    let allowed_depth = format!("{}report.pdf", "dir/".repeat(63));
    assert!(AttachmentRelativePath::new(&allowed_depth).is_ok());
    let rejected_depth = format!("{}report.pdf", "dir/".repeat(64));
    assert_eq!(
        AttachmentRelativePath::new(&rejected_depth),
        Err(AttachmentPathError::UnsupportedSyntax),
    );
    let prefix = vec!["a".repeat(254); 16].join("/");
    let exact_total = format!("{prefix}/{}", "x".repeat(16));
    assert_eq!(exact_total.len(), 4_096);
    assert!(AttachmentRelativePath::new(&exact_total).is_ok());
    let oversized = format!("{exact_total}x");
    assert_eq!(
        AttachmentRelativePath::new(&oversized),
        Err(AttachmentPathError::UnsupportedSyntax),
    );
}

#[test]
fn inline_attachment_boundary_is_exactly_thirty_two_kibibytes() {
    let limit = u64::from(MAX_INLINE_ATTACHMENT_BYTES);
    assert!(attachment_fits_inline(0));
    assert!(attachment_fits_inline(limit));
    assert!(!attachment_fits_inline(limit + 1));
    assert!(!attachment_fits_inline(u64::MAX));
}
