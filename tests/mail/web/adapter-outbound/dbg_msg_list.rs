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
fn tracked_list_anchor_is_never_exposed_in_debug() {
    let tracked = TrackedMessageListRequest {
        state: NetworkRequestState::Requested,
        kind: MessageListRequestKind::Continuation,
        limit: 1,
        page: None,
        sort_key: MessageListSortKey::Time,
        descending: true,
        anchor: Some(42),
        anchor_id: Some(Zeroizing::new("private-message-list-anchor".into())),
    };
    let debug = format!("{tracked:?}");
    assert!(!debug.contains("private-message-list-anchor"));
    assert!(debug.contains("<redacted>"));
}
