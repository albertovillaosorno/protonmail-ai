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
//   - Synthetic Unicode guard regression coverage for shared display fields.
// - Must-Not:
//   - Contact Proton, inspect mailbox data, or alter the filesystem.
// - Allows:
//   - Prove hidden-format refusal and ordinary grapheme compatibility.
// - Split-When:
//   - Text-safety rules move into a versioned provider-neutral capability.
// - Merge-When:
//   - Shared display guard tests move into the complete read-model suite.
// - Summary:
//   - Keeps all read-only metadata projections on one guarded Unicode policy.
// - Description:
//   - Rejects invisible/bidi characters without rejecting emoji selectors.
// - Usage:
//   - Included as private tests under display_text_safety.rs.
// - Defaults:
//   - All test strings are synthetic Unicode samples.
//

//! Synthetic Unicode display safety regressions.

use super::unsafe_display_character;

#[test]
fn hidden_display_controls_are_not_exported() {
    for character in [
        '\u{0}',
        '\n',
        '\u{7f}',
        '\u{85}',
        '\u{00ad}',
        '\u{034f}',
        '\u{200b}',
        '\u{200e}',
        '\u{2028}',
        '\u{2029}',
        '\u{202e}',
        '\u{2060}',
        '\u{2066}',
        '\u{2069}',
        '\u{feff}',
        '\u{e0020}',
    ] {
        assert!(unsafe_display_character(character), "{character:?}");
    }
}

#[test]
fn real_unicode_graphemes_are_not_rejected() {
    for character in [
        'a',
        '\u{e9}',
        '\u{a0}',
        '\u{200c}',
        '\u{200d}',
        '\u{fe0f}',
        '\u{e0100}',
        '\u{1f469}',
        '\u{1f4bb}',
    ] {
        assert!(!unsafe_display_character(character), "{character:?}");
    }
}
