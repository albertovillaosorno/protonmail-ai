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
fn tracked_event_id_and_private_request_hashes_are_redacted() {
    let event = TrackedEventRequest {
        state: EventRequestState::Requested,
        event_id: Zeroizing::new("private-event-id-marker".into()),
        url_fingerprint: [1_234_567_890_123, 4_567_890_123_456],
    };
    let event_debug = format!("{event:?}");
    assert!(!event_debug.contains("private-event-id-marker"));
    assert!(!event_debug.contains("1234567890123"));
    assert!(!event_debug.contains("4567890123456"));
    assert!(event_debug.contains("<redacted>"));

    let latest = TrackedLatestEventRequest {
        state: EventRequestState::Requested,
        url_fingerprint: [1_234_567_890_123, 4_567_890_123_456],
    };
    let latest_debug = format!("{latest:?}");
    assert!(!latest_debug.contains("1234567890123"));
    assert!(!latest_debug.contains("4567890123456"));
    assert!(latest_debug.contains("<redacted>"));
}
