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
//   - Pure effective-owner and mode-policy regression for output custody.
// - Must-Not:
//   - Read mailbox data, spawn browsers, or mutate real user files.
// - Allows:
//   - Test synthetic UID and mode combinations without privilege changes.
// - Split-When:
//   - Output policy requires a separate reusable domain object.
// - Merge-When:
//   - Attachment output ownership becomes a general filesystem policy.
// - Summary:
//   - Rejects foreign-owned directories even when their mode is private.
// - Description:
//   - Proves private output requires both effective owner and private mode.
// - Usage:
//   - Included from attachment_output for private test-only policy access.
// - Defaults:
//   - Synthetic numbers only; no account, browser, or filesystem access.
//

//! Pure synthetic effective-ownership policy tests.

use super::private_directory_allowed;

#[test]
fn private_output_requires_effective_owner_and_private_mode() {
    assert!(private_directory_allowed(0o700, 1000, 1000));
    assert!(private_directory_allowed(0o700, 0, 0));
    assert!(!private_directory_allowed(0o700, 1001, 1000));
    assert!(!private_directory_allowed(0o700, 0, 1000));
    assert!(!private_directory_allowed(0o770, 1000, 1000));
    // A 0755 directory permits untrusted users to enumerate attachment names
    // even when each final attachment file is independently chmodded 0600.
    for mode in [0o755, 0o750, 0o705, 0o711, 0o740, 0o500, 0o600] {
        assert!(!private_directory_allowed(mode, 1000, 1000));
    }
}
