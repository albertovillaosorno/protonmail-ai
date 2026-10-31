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
//   - One audited hidden-format and control guard for displayed Mail metadata.
// - Must-Not:
//   - Inspect accounts, provider responses, UI state, or user-controlled files.
// - Allows:
//   - Share exact visible-text refusal across read-only metadata projections.
// - Split-When:
//   - Text policy becomes an independently versioned capability contract.
// - Merge-When:
//   - One common read model directly owns all text projection constraints.
// - Summary:
//   - Keeps read-only display fields consistent against Unicode spoof marks.
// - Description:
//   - Refuses controls and invisible formatting while preserving real glyphs.
// - Usage:
//   - Message subject/recipients, visible rows, and catalog names use this.
// - Defaults:
//   - Ordinary Unicode, grapheme joiners, and variation selectors are valid.
//

//! Shared private Unicode text-safety predicate for displayed Mail metadata.

// Metadata may be displayed to a user or reused to select a reply target.
// Hidden selectors and bidi controls must not disguise the displayed value.
// Preserve grapheme joiners and variation selectors used by natural scripts.
#[expect(
    clippy::redundant_pub_crate,
    reason = "sibling read-model modules reuse a guard in this private module"
)]
pub(crate) const fn unsafe_display_character(character: char) -> bool {
    character.is_control()
        || is_noncharacter(character)
        || matches!(
            character,
            '\u{00ad}' | '\u{034f}' | '\u{061c}' | '\u{0600}'..='\u{0605}'
                | '\u{06dd}' | '\u{070f}' | '\u{0890}'..='\u{0891}' | '\u{08e2}'
                | '\u{115f}'..='\u{1160}'
                | '\u{17b4}'..='\u{17b5}' | '\u{180e}'..='\u{180f}'
                // jig-ignore-next-line: rustfmt Unicode guard.
                | '\u{1bca0}'..='\u{1bca3}' | '\u{200b}' | '\u{200e}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}'
                | '\u{fff9}'..='\u{fffb}' | '\u{110bd}' | '\u{110cd}'
                | '\u{13430}'..='\u{1343f}' | '\u{1d173}'..='\u{1d17a}'
                | '\u{2800}' | '\u{3164}' | '\u{feff}' | '\u{ffa0}'
                | '\u{e0001}' | '\u{e0020}'..='\u{e007f}'
        )
}

// Unicode noncharacters have no stable display meaning. Guard all planes
// without rejecting grapheme-joining code points used by real scripts.
#[expect(
    clippy::as_conversions,
    reason = "char to u32 is lossless and required inside a stable const fn"
)]
const fn is_noncharacter(character: char) -> bool {
    let codepoint = character as u32;
    matches!(codepoint, 0xfdd0..=0xfdef) || codepoint & 0xfffe == 0xfffe
}

#[cfg(test)]
#[path = "../../../../tests/mail/web/adapter-outbound/display_text_safety.rs"]
mod tests;
