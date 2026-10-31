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
fn sanitized_filenames_require_scrub_on_drop() {
    #[expect(drop_bounds, reason = "require private filename custody")]
    fn requires_scrub_on_drop<T>()
    where
        T: Drop,
    {
    }
    requires_scrub_on_drop::<SanitizedAttachmentFilename>();
}

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
fn lossy_unicode_replacement_is_not_portable_filename_or_destination() {
    // U+FFFD can be introduced when invalid source bytes are decoded with
    // replacement. Do not write an alias of an unknown original leaf.
    let lossy = "invoice\u{fffd}signed.pdf";
    assert_eq!(
        SanitizedAttachmentFilename::new(lossy).as_str(),
        "invoice_signed.pdf"
    );
    for destination in [String::from(lossy), format!("exports/{lossy}")] {
        assert_eq!(
            AttachmentRelativePath::new(&destination),
            Err(AttachmentPathError::UnsupportedSyntax),
            "lossily decoded filesystem path must fail before I/O"
        );
    }
    // Explicit printable Unicode glyphs retain their original spelling.
    let authentic = "r\u{e9}sum\u{e9}-\u{65c5}\u{884c}.pdf";
    assert_eq!(
        SanitizedAttachmentFilename::new(authentic).as_str(),
        authentic
    );
    assert!(AttachmentRelativePath::new(authentic).is_ok());
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
fn untrusted_attachment_paths_neutralize_all_unicode_format_controls() {
    // Unicode formatting controls and noncharacters are not portable
    // filename content, even outside familiar bidi/ZWJ ranges.
    for point in [
        0x600,
        0x605,
        0x6dd,
        0x70f,
        0x890,
        0x891,
        0x8e2,
        0xfff9,
        0xfffb,
        0x110bd,
        0x110cd,
        0x13430,
        0x1343f,
        0x1d173,
        0x1d17a,
        0xfdd0,
        0xfdef,
        0xfffe,
        0x0001_fffe,
        0x0010_ffff,
    ] {
        let mark = char::from_u32(point).expect("valid Unicode scalar");
        let filename = format!("report{mark}archive.pdf");
        assert_eq!(
            SanitizedAttachmentFilename::new(&filename).as_str(),
            "report_archive.pdf",
            "unsafe format character U+{point:04X} escaped filename guard"
        );
        let destination = format!("exports/{filename}");
        assert_eq!(
            AttachmentRelativePath::new(&destination),
            Err(AttachmentPathError::UnsupportedSyntax),
            "unsafe format character U+{point:04X} escaped output path guard"
        );
    }
    let portable = "exports/r\u{e9}sum\u{e9}-\u{65c5}\u{884c}.pdf";
    assert_eq!(
        AttachmentRelativePath::new(portable)
            .expect("printable Unicode must remain supported")
            .as_path(),
        Path::new(portable)
    );
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
fn mixed_case_device_detection_preserves_ascii_only_folding() {
    for (input, expected) in [
        ("cOn", "_cOn"),
        ("PrN.txt", "_PrN.txt"),
        ("aUx", "_aUx"),
        ("nUl.log", "_nUl.log"),
        ("CoNiN$", "_CoNiN$"),
        ("cOnOuT$.pdf", "_cOnOuT$.pdf"),
        ("cOm1", "_cOm1"),
        ("LpT9.txt", "_LpT9.txt"),
        ("cOm\u{b9}.txt", "_cOm\u{b9}.txt"),
        ("LpT\u{b2}", "_LpT\u{b2}"),
        ("cOm0", "cOm0"),
        ("pRivate-COM1.txt", "pRivate-COM1.txt"),
        ("C\u{00d6}M1", "C\u{00d6}M1"),
        ("\u{1f680}COM1", "\u{1f680}COM1"),
    ] {
        assert_eq!(SanitizedAttachmentFilename::new(input).as_str(), expected);
        assert_eq!(
            AttachmentRelativePath::new(input).is_err(),
            input != expected,
            "relative destination policy must agree on reserved device names"
        );
    }
}

#[test]
fn sanitizer_outputs_only_portable_relative_filename_leaves() {
    // Seeded, bounded adversarial corpus. Every sanitized provider filename
    // must also pass the independent destination validator as one leaf.
    let alphabet = [
        'A',
        'c',
        'o',
        'n',
        '1',
        '9',
        '.',
        ' ',
        '/',
        '\\',
        ':',
        '?',
        '\0',
        '\n',
        '\t',
        '\r',
        '\u{202e}',
        '\u{200b}',
        '\u{00e9}',
        '\u{1f680}',
        '\u{b2}',
        '\u{301}',
        'p',
        'r',
        'N',
        'U',
        'L',
        'm',
        't',
        '0',
        '_',
        '$',
    ];
    let mut seed = 0x6a09_e667_f3bc_c909u64;
    for _case in 0..2_048u16 {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let size = usize::try_from(seed & 0x1ff).expect("bounded corpus size");
        let mut untrusted = String::new();
        for _ in 0..size {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let index = usize::try_from(seed & 31);
            let position = index.expect("bounded symbol index");
            untrusted.push(alphabet[position]);
        }
        let sanitized = SanitizedAttachmentFilename::new(&untrusted);
        let leaf = sanitized.as_str();
        assert!(!leaf.is_empty());
        assert!(leaf.len() <= MAX_ATTACHMENT_FILENAME_BYTES);
        let destination = AttachmentRelativePath::new(leaf);
        assert!(destination.is_ok(), "sanitized leaf must be portable");
        assert_eq!(
            destination.expect("portable leaf").as_path(),
            Path::new(leaf)
        );
    }
}

#[test]
fn reserved_filename_prefixing_preserves_the_byte_ceiling() {
    let long_reserved = format!("CON.{}", "x".repeat(300));
    let safe = SanitizedAttachmentFilename::new(&long_reserved);
    assert!(safe.as_str().starts_with("_CON."));
    assert!(safe.as_str().len() <= MAX_ATTACHMENT_FILENAME_BYTES);
}

#[test]
fn sanitization_discards_private_suffix_without_changing_visible_leaf() {
    for (input, expected) in [
        ("report.txt.  ", "report.txt"),
        ("report.txt   ", "report.txt"),
        ("...", "attachment"),
        ("CON.  ", "_CON"),
        ("COM1.  ", "_COM1"),
    ] {
        assert_eq!(SanitizedAttachmentFilename::new(input).as_str(), expected);
    }
    // The reserved-device prefix reduces the 255-byte input allowance by
    // one. The final four-byte emoji must be scrubbed before truncation.
    let stem = "x".repeat(247);
    let name = format!("CON.{stem}\u{1f680}");
    assert_eq!(name.len(), MAX_ATTACHMENT_FILENAME_BYTES);
    let safe = SanitizedAttachmentFilename::new(&name);
    assert_eq!(safe.as_str(), format!("_CON.{stem}"));
    assert!(safe.as_str().len() <= MAX_ATTACHMENT_FILENAME_BYTES);
}

#[test]
fn reserved_name_prefixing_never_reintroduces_trailing_dots_or_spaces() {
    for device in ["CON.", "LPT1.", "NUL."] {
        for suffix in ['.', ' '] {
            let fill_length = MAX_ATTACHMENT_FILENAME_BYTES - device.len() - 2;
            let fill = "x".repeat(fill_length);
            let input = format!("{device}{fill}{suffix}z");
            assert_eq!(input.len(), MAX_ATTACHMENT_FILENAME_BYTES);
            let sanitized = SanitizedAttachmentFilename::new(&input);
            let name = sanitized.as_str();
            assert!(name.starts_with('_'), "reserved device prefix required");
            assert!(name.len() <= MAX_ATTACHMENT_FILENAME_BYTES);
            assert!(!name.ends_with([' ', '.']), "unsafe trailing name alias");
        }
    }
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
fn normalized_path_preserves_private_names_across_clones() {
    let selected = "./synthetic-private-directory/./synthetic-private-file.txt";
    let path = AttachmentRelativePath::new(selected);
    let path = path.expect("synthetic private path");
    let normalized = Path::new("synthetic-private-directory");
    let normalized = normalized.join("synthetic-private-file.txt");
    assert_eq!(path.as_path(), normalized);
    let copied = path.clone();
    drop(path);
    assert_eq!(copied.as_path(), normalized);
    assert_eq!(format!("{copied:?}"), "AttachmentRelativePath(<redacted>)");
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
            "exports/report.pdf/.",
            AttachmentPathError::UnsupportedSyntax,
        ),
        ("exports/./.", AttachmentPathError::UnsupportedSyntax),
        ("./exports/.", AttachmentPathError::UnsupportedSyntax),
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
