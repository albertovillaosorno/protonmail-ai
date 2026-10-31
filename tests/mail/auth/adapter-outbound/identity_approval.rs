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
fn approval_policy_requires_real_gregorian_evidence_dates() {
    for impossible in [
        "2026-00-01",
        "2026-13-01",
        "2026-02-29",
        "2026-02-30",
        "2026-04-31",
        "2026-10-00",
        "2026-99-99",
        "1900-02-29",
        "0000-01-01",
    ] {
        let invalid_approval = AuthorizationPolicy {
            approved_on: Some(impossible),
            ..synthetic_approved_policy()
        };
        assert!(invalid_approval.approved_identity().is_none());

        let invalid_review = AuthorizationPolicy {
            evidence_reviewed_on: impossible,
            ..synthetic_approved_policy()
        };
        assert!(invalid_review.approved_identity().is_none());
    }

    // Gregorian leap years remain valid, including the 400-year rule.
    for leap in ["2024-02-29", "2000-02-29"] {
        let policy = AuthorizationPolicy {
            evidence_reviewed_on: leap,
            approved_on: Some(leap),
            ..synthetic_approved_policy()
        };
        assert!(policy.approved_identity().is_some());
    }
}

#[test]
fn approval_policy_requires_approval_before_or_at_evidence_review() {
    for (review, approval) in [
        ("2026-10-29", "2026-10-30"),
        ("2025-12-31", "2026-01-01"),
        ("2024-02-28", "2024-02-29"),
    ] {
        let policy = AuthorizationPolicy {
            evidence_reviewed_on: review,
            approved_on: Some(approval),
            ..synthetic_approved_policy()
        };
        assert!(policy.approved_identity().is_none());
        assert_eq!(
            policy.snapshot().status(),
            ProviderAuthorizationStatus::Blocked
        );
    }
    for (review, approval) in [
        ("2026-10-30", "2026-10-30"),
        ("2026-10-30", "2026-10-29"),
        ("2026-01-01", "2025-12-31"),
    ] {
        let policy = AuthorizationPolicy {
            evidence_reviewed_on: review,
            approved_on: Some(approval),
            ..synthetic_approved_policy()
        };
        assert!(policy.approved_identity().is_some());
    }
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

#[test]
fn approval_policy_requires_exact_mail_desktop_handoff_and_matching_version() {
    for unsafe_path in [
        "/desktop/login?app=drive&pv=3",
        "/desktop/login?app=mail&pv=1",
        "/desktop/login?app=mail&pv=3&redirect=https://evil.example",
        "/desktop/login?app=mail&pv=3&app=drive",
        "/desktop/../desktop/login?app=mail&pv=3",
        "/desktop/login?pv=3&app=mail",
        "/desktop/login?app=mail&pv=03",
        "/desktop/login?app=mail&pv=3?next=evil",
    ] {
        let policy = AuthorizationPolicy {
            login_path: Some(unsafe_path),
            ..synthetic_approved_policy()
        };
        assert!(
            policy.approved_identity().is_none(),
            "unreviewed alternate login route must not authorize"
        );
        assert_eq!(
            policy.snapshot().status(),
            ProviderAuthorizationStatus::Blocked
        );
    }

    for (version, route) in [
        (1u8, "/desktop/login?app=mail&pv=1"),
        (2u8, "/desktop/login?app=mail&pv=2"),
        (3u8, "/desktop/login?app=mail&pv=3"),
    ] {
        let policy = AuthorizationPolicy {
            fork_payload_version: Some(version),
            login_path: Some(route),
            ..synthetic_approved_policy()
        };
        let identity = policy
            .approved_identity()
            .expect("synthetic matching version");
        assert_eq!(identity.desktop_login_path(), route);
    }
    assert!(
        ProviderAuthorizationSnapshot::current()
            .approved()
            .is_none()
    );
}
