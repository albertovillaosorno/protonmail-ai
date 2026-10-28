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
//   - Private Rust row projection safety independent of browser DOM guards.
// - Must-Not:
//   - Read a Mail account, store content, or depend on live Chromium.
// - Allows:
//   - Exercise synthetic row IDs and bounded content fields.
// - Split-When:
//   - Distinct data projection safety models are needed.
// - Merge-When:
//   - Row validation can share broader mailbox snapshot fixtures.
// - Summary:
//   - Rejects unsafe opaque IDs at the Rust CDP response boundary.
// - Description:
//   - Directly tests private projection before list reconciliation.
// - Usage:
//   - Included under the mailbox_page module for unit testing.
// - Defaults:
//   - No external access or real messages.
//

//! Synthetic private Rust mailbox-row projection tests.

use serde_json::json;

use super::parse_rows;
use crate::driver::BrowserDriverError;

#[test]
fn rust_row_projection_refuses_unsafe_ids_independently_of_list_guard() {
    for id in [
        ".",
        "..",
        "with space",
        "encoded%2fslash",
        "unsafe/slash",
        "control\nnewline",
        "bidi\u{202e}reversed",
        "zero\u{200b}width",
        "hangul\u{115f}filler",
        "compatibility\u{3164}filler",
        "braille\u{2800}blank",
        "variation\u{fe0f}selector",
        "mongolian\u{180f}variation",
        "khmer\u{17b4}vowel",
        "shorthand\u{1bca0}control",
        "tag\u{e0100}selector",
    ] {
        let value = json!([{
            "id": id,
            "subject": "Synthetic subject",
            "addresses": "synthetic@example.test",
            "unread": false
        }]);
        assert_eq!(
            parse_rows(&value),
            Err(BrowserDriverError::MailboxPageIncompatible)
        );
    }
    let safe = json!([{
        "id": "m\u{e9}morandum",
        "subject": "Synthetic subject",
        "addresses": "synthetic@example.test",
        "unread": false
    }]);
    assert!(parse_rows(&safe).is_ok());
}

#[test]
fn rust_row_projection_rejects_control_bearing_visible_text() {
    for (subject, addresses) in [
        ("Synthetic\nsubject", "sender@example.test"),
        ("Synthetic\rsubject", "sender@example.test"),
        ("Synthetic\u{2028}subject", "sender@example.test"),
        ("Normal subject", "sender@example.test\u{0000}"),
        ("Normal subject", "sender@example.test\u{007f}"),
        ("Normal subject", "sender@example.test\u{2029}"),
    ] {
        let value = json!([{
            "id": "safe-row",
            "subject": subject,
            "addresses": addresses,
            "unread": false
        }]);
        assert_eq!(
            parse_rows(&value),
            Err(BrowserDriverError::MailboxPageIncompatible)
        );
    }
    let safe = json!([{
        "id":"safe-row",
        "subject":"Emoji \u{263a} and an ordinary space",
        "addresses":"Sender <sender@example.test>",
        "unread":false
    }]);
    assert!(parse_rows(&safe).is_ok());
}

#[test]
fn rust_row_projection_refuses_hidden_formatting_in_display_text() {
    for mark in [
        '\u{00ad}',
        '\u{034f}',
        '\u{061c}',
        '\u{200b}',
        '\u{200d}',
        '\u{202e}',
        '\u{2066}',
        '\u{2069}',
        '\u{fe0f}',
        '\u{feff}',
        '\u{e0001}',
        '\u{e0100}',
    ] {
        for (subject, addresses) in [
            (
                format!("invoice{mark}approved"),
                String::from("sender@example.test"),
            ),
            (
                String::from("Normal subject"),
                format!("sender{mark}@example.test"),
            ),
        ] {
            let value = json!([{
                "id": "safe-row", "subject": subject, "addresses": addresses,
                "unread": false
            }]);
            assert_eq!(
                parse_rows(&value),
                Err(BrowserDriverError::MailboxPageIncompatible),
                "hidden formatting must not cross row projection"
            );
        }
    }
    let printable = json!([{
        "id": "safe-row", "subject": "Caf\u{e9} \u{1f600}",
        "addresses": "\u{00c9}lodie <sender@example.test>", "unread": false
    }]);
    assert!(parse_rows(&printable).is_ok());
}
