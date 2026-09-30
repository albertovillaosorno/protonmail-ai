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
//   - Synthetic regression evidence for Proton QR session-fork framing.
// - Must-Not:
//   - Contact Proton, use a real account, or expose generated secrets in logs.
// - Allows:
//   - Decode synthetic payloads to verify framing and entropy length.
// - Split-When:
//   - Network polling or encrypted fork-response fixtures are implemented.
// - Merge-When:
//   - A complete deterministic fork-adapter suite subsumes these checks.
// - Summary:
//   - Proves third-party target handoffs are framed and redacted correctly.
// - Description:
//   - Exercises only local target payload generation with synthetic user codes.
// - Usage:
//   - Run through the workspace test gate.
// - Defaults:
//   - No network, account, browser, or provider session is required.
//

//! Target-side Proton Mail session-fork handoff regression tests.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use mail_auth_fork_adapter::SDK_DEFAULT_CLIENT_ID;
use mail_auth_fork_adapter::{HandoffError, TargetHandoff};

#[test]
fn target_payload_matches_proton_qr_shape() {
    let handoff = TargetHandoff::new("ABCDEFGH").expect("entropy must exist");
    let payload = handoff.payload();
    let fields: Vec<_> = payload.expose().split(':').collect();

    assert_eq!(fields.len(), 4);
    assert_eq!(fields[0], "0");
    assert_eq!(fields[1], "ABCDEFGH");
    assert_eq!(fields[3], SDK_DEFAULT_CLIENT_ID);

    let secret = STANDARD.decode(fields[2]).expect("secret must be base64");
    assert_eq!(secret.len(), 32);
}

#[test]
fn sdk_default_identity_never_claims_a_first_party_client() {
    assert_eq!(SDK_DEFAULT_CLIENT_ID, "Other");
    assert!(!SDK_DEFAULT_CLIENT_ID.contains("mail"));
    assert!(!SDK_DEFAULT_CLIENT_ID.contains("ios"));
    assert!(!SDK_DEFAULT_CLIENT_ID.contains("android"));
}

#[test]
fn invalid_user_codes_fail_before_entropy_is_used() {
    assert!(matches!(
        TargetHandoff::new(""),
        Err(HandoffError::InvalidUserCode)
    ));
    assert!(matches!(
        TargetHandoff::new("bad:code"),
        Err(HandoffError::InvalidUserCode)
    ));
}

#[test]
fn debug_output_redacts_handoff_secret() {
    let handoff = TargetHandoff::new("ABCDEFGH").expect("entropy must exist");
    let payload = handoff.payload();
    let exposed = payload.expose().to_owned();

    assert_eq!(format!("{payload:?}"), "HandoffPayload([REDACTED])");
    assert!(!format!("{handoff:?}").contains(&exposed));
    assert!(format!("{handoff:?}").contains("[REDACTED]"));
}
