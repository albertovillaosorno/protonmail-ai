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
                || matches!(character, '/' | '?' | '#' | '\\')
        })
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
