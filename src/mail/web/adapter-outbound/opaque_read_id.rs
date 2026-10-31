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
//   - Common bounded route-component validation for read-only Mail IDs.
// - Must-Not:
//   - Log, normalize, encode, decode, or persist opaque provider IDs.
// - Allows:
//   - Refuse ambiguous read identifiers before UI or Network projection.
// - Split-When:
//   - Provider-specific identity semantics require a typed separate model.
// - Merge-When:
//   - One audited read adapter owns route-bound identifier validation.
// - Summary:
//   - Rejects bounded read identifiers unsafe as exact URL path components.
// - Description:
//   - Provides one content-free predicate shared by read-only projections.
// - Usage:
//   - Apply before accepting rendered rows, metadata IDs, or cursor IDs.
// - Defaults:
//   - Empty, oversized, control, whitespace, delimiter, or dot segments fail.
//

//! Uniform validation of opaque identities entering read-only Mail routes.

/// Checks an opaque identifier without modifying or logging its contents.
///
/// This is not a provider-identity validator: it only blocks identifiers that
/// are unsafe or ambiguous when later used as exact URL path components.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private child module shares its validator with sibling adapters"
)]
pub(super) fn safe_read_id(id: &str, max_bytes: usize) -> bool {
    !id.is_empty()
        && !matches!(id, "." | "..")
        && id.len() <= max_bytes
        && !id.chars().any(|character| {
            character.is_control()
                || character.is_whitespace()
                // Matrix-parameter separators can change a path segment's
                // identity in HTTP routers and intermediaries even without
                // URL encoding. Do not treat them as exact provider IDs.
                || matches!(character, '/' | '?' | '#' | '%' | ';' | '\\')
                // U+FFFD cannot prove the original exact route identity.
                || character == '\u{fffd}'
                || is_invisible_format(character)
                || is_unicode_noncharacter(character)
        })
}

// Unicode noncharacters are valid scalar values but have no interchange
// meaning. They cannot prove an unambiguous provider URL path identity.
fn is_unicode_noncharacter(character: char) -> bool {
    let codepoint = u32::from(character);
    (0xfdd0..=0xfdef).contains(&codepoint) || codepoint & 0xfffe == 0xfffe
}

/// Refuse hidden formatting and direction controls that obscure exact identity.
const fn is_invisible_format(character: char) -> bool {
    matches!(
        character,
        '\u{00ad}' | '\u{034f}' | '\u{061c}'
            | '\u{600}'..='\u{605}' | '\u{6dd}' | '\u{70f}'
            | '\u{890}'..='\u{891}' | '\u{8e2}'
            | '\u{fff9}'..='\u{fffb}' | '\u{110bd}' | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}' | '\u{1d173}'..='\u{1d17a}'
            | '\u{115f}' | '\u{1160}' | '\u{180b}'..='\u{180f}'
            | '\u{17b4}'..='\u{17b5}' | '\u{1bca0}'..='\u{1bca3}'
            | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}' | '\u{2800}' | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}' | '\u{feff}' | '\u{ffa0}'
            | '\u{e0001}' | '\u{e0020}'..='\u{e007f}'
            | '\u{e0100}'..='\u{e01ef}'
    )
}
