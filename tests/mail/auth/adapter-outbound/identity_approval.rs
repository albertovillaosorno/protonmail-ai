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
//   - Synthetic private provider authorization policy rejection evidence.
// - Must-Not:
//   - Enable real provider authorization or use real approval credentials.
// - Allows:
//   - Construct isolated policies to test approved-destination syntax.
// - Split-When:
//   - Provider-approved transport policy gains a separate test suite.
// - Merge-When:
//   - One identity test suite covers all approval and candidate checks.
// - Summary:
//   - Proves unsafe API hosts and open redirect login paths cannot approve.
// - Description:
//   - Uses invented registration metadata and synthetic destination values.
// - Usage:
//   - Run as internal identity-policy unit tests.
// - Defaults:
//   - The real provider-authorization policy remains blocked.
//

//! Synthetic private approval-policy validation, without provider authority.

use super::*;

fn synthetic_approved_policy() -> AuthorizationPolicy {
    let dossier = "docs/architecture/provider-client-registration.mdc";
    AuthorizationPolicy {
        status: ProviderAuthorizationStatus::Approved,
        evidence_reviewed_on: "2026-10-30",
        evidence_reference: dossier,
        app_version: Some("example-third-party-mail@1.0.0"),
        child_client_id: Some("example-third-party-mail"),
        api_base: Some("https://mail.proton.me/api"),
        fork_payload_version: Some(3),
        login_path: Some("/desktop/login?app=mail&pv=3"),
        approval_ref: Some("SYNTHETIC-APPROVAL-NOT-REAL"),
        approved_on: Some("2026-10-30"),
    }
}

#[test]
fn canonical_synthetic_approval_validates_without_enabling_live_auth() {
    let policy = synthetic_approved_policy();
    let identity = policy.approved_identity().expect("synthetic valid fixture");
    assert_eq!(identity.api_base(), "https://mail.proton.me/api");
    assert_eq!(
        identity.desktop_login_path(),
        "/desktop/login?app=mail&pv=3"
    );
    assert_eq!(
        ProviderAuthorizationSnapshot::current().status(),
        ProviderAuthorizationStatus::Blocked
    );
    assert!(
        ProviderAuthorizationSnapshot::current()
            .approved()
            .is_none()
    );
}

#[test]
fn approval_policy_rejects_noncanonical_or_injected_api_origins() {
    for unsafe_api in [
        "https://",
        "https://evil.example/api",
        "https://mail.proton.me@evil.example/api",
        "https://mail.proton.me/api/../other",
        "https://mail.proton.me/api?redirect=1",
        "https://mail.proton.me/api#fragment",
        "https://mail.proton.me:443/api",
    ] {
        let policy = AuthorizationPolicy {
            api_base: Some(unsafe_api),
            ..synthetic_approved_policy()
        };
        assert!(policy.approved_identity().is_none());
        assert_eq!(
            policy.snapshot().status(),
            ProviderAuthorizationStatus::Blocked
        );
    }
}

#[test]
fn approval_policy_rejects_protocol_relative_and_encoded_login_paths() {
    for unsafe_path in [
        "//evil.example/login",
        "/\\evil.example/login",
        "/desktop/login#fragment",
        "/desktop/%2F%2Fevil.example",
        "/desktop/login?app=mail%0d%0aInjected",
    ] {
        let policy = AuthorizationPolicy {
            login_path: Some(unsafe_path),
            ..synthetic_approved_policy()
        };
        assert!(policy.approved_identity().is_none());
        assert_eq!(
            policy.snapshot().status(),
            ProviderAuthorizationStatus::Blocked
        );
    }
}
