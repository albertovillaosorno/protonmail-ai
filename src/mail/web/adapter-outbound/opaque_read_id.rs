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
                || matches!(character, '/' | '?' | '#' | '%' | '\\')
                || is_invisible_format(character)
        })
}

/// Refuse invisible direction controls that could obscure exact identity.
const fn is_invisible_format(character: char) -> bool {
    matches!(
        character,
        '\u{061c}' | '\u{200b}' | '\u{200c}' | '\u{200d}'
            | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}'
            | '\u{2060}' | '\u{2066}'..='\u{2069}' | '\u{feff}'
    )
}

#[cfg(test)]
mod tests {
    use super::safe_read_id;

    #[test]
    fn rejects_unsafe_components_without_ever_normalizing_ids() {
        for invalid in [
            "",
            ".",
            "..",
            "nested/id",
            "field?query",
            "field#fragment",
            "field\\backslash",
            "field space",
            "field\nnewline",
            "field\tTab",
            "field\u{a0}nbsp",
            "field\u{2003}wide",
            "field\u{85}control",
            "percent%2Fslash",
            "%2e",
            "%2E%2E",
            "prefix%252Fdouble",
            "direction\u{202e}flip",
            "joiner\u{200b}invisible",
            "isolate\u{2066}hidden\u{2069}",
            "mark\u{feff}hidden",
        ] {
            assert!(!safe_read_id(invalid, 512));
        }
        for valid in ["opaque+_~=", "a.b", "...", "\u{2603}"] {
            assert!(safe_read_id(valid, 512));
        }
        assert!(safe_read_id(&"x".repeat(512), 512));
        assert!(!safe_read_id(&"x".repeat(513), 512));
        assert!(!safe_read_id("safe", 3));
    }
}
