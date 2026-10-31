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
//   - Synthetic regression evidence for private network request diagnostics.
// - Must-Not:
//   - Use a live browser, provider, credential, account, or message content.
// - Allows:
//   - Format synthetic tracked request records and assert safe redaction.
// - Split-When:
//   - Private diagnostics have independently specified formatting contracts.
// - Merge-When:
//   - Another synthetic test suite covers the same request records.
// - Summary:
//   - Private identifiers and scoped URL hashes cannot enter Debug output.
// - Description:
//   - Proves exact synthetic markers cannot appear in request diagnostics.
// - Usage:
//   - Included as a private test module by its owning source module.
// - Defaults:
//   - No external I/O, credentials, or persistent state.
//

//! Synthetic tracked-request diagnostic redaction tests.

use super::*;

#[test]
fn tracked_private_identifier_cannot_leak_through_debug() {
    let tracked = TrackedAttachmentMetadataRequest {
        state: AttachmentMetadataRequestState::Requested,
        attachment_id: Zeroizing::new("private-entity-id-marker".into()),
    };
    let debug = format!("{tracked:?}");
    assert!(!debug.contains("private-entity-id-marker"));
    assert!(debug.contains("<redacted>"));
}
