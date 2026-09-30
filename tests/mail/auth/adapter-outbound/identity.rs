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
//   - Regression evidence for third-party Mail identity candidate policy.
// - Must-Not:
//   - Claim provider approval or use a real credential or provider session.
// - Allows:
//   - Exercise known-negative identity and syntax validation offline.
// - Split-When:
//   - Provider registration fixtures require separate approval evidence.
// - Merge-When:
//   - One adapter identity suite fully owns candidate and approval checks.
// - Summary:
//   - Proves SDK defaults and first-party Mail identities fail closed.
// - Description:
//   - Uses synthetic candidate identities and public first-party identifiers.
// - Usage:
//   - Run through the workspace test gate.
// - Defaults:
//   - No candidate is treated as provider-authorized.
//

//! Proton Mail client-identity candidate policy regression tests.

use mail_auth_fork_adapter::ClientIdentityError;
use mail_auth_fork_adapter::ProviderAuthorizationStatus;
use mail_auth_fork_adapter::ProviderProfile;
use mail_auth_fork_adapter::ThirdPartyIdentityCandidate as Candidate;

const CANDIDATE_APP: &str = "thirdparty-example@1.0.0";
const CANDIDATE_APP_V2: &str = "thirdparty-example@1.2.3";
const CANDIDATE_CHILD: &str = "thirdparty-example";
const REGISTRATION_DOSSIER: &str = include_str!(concat!(
    "../../../../docs/architecture/",
    "provider-client-registration.mdc"
));

#[test]
fn blocked_policy_and_registration_dossier_remain_aligned() {
    let authorization = ProviderProfile::authorization();

    assert_eq!(authorization.status(), ProviderAuthorizationStatus::Blocked);
    let blocked = "Status: blocked on provider authorization.";
    assert!(REGISTRATION_DOSSIER.contains(blocked));
    assert!(REGISTRATION_DOSSIER.contains("Evidence reviewed: 2026-09-30."));
    assert_eq!(
        authorization.evidence_reference(),
        "docs/architecture/provider-client-registration.mdc"
    );
}

#[test]
fn current_provider_authorization_is_blocked_and_has_no_identity() {
    let authorization = ProviderProfile::authorization();

    assert_eq!(authorization.status(), ProviderAuthorizationStatus::Blocked);
    assert_eq!(authorization.evidence_reviewed_on(), "2026-09-30");
    assert_eq!(
        authorization.evidence_reference(),
        "docs/architecture/provider-client-registration.mdc"
    );
    assert_eq!(authorization.approved(), None);
    assert_eq!(ProviderProfile::live_identity(), None);
    assert_eq!(ProviderProfile::live_fork_payload_version(), None);
    assert!(!ProviderProfile::live_auth_supported());
}

#[test]
fn versioned_unreserved_candidate_is_only_a_candidate() {
    let candidate = Candidate::try_new(CANDIDATE_APP_V2, CANDIDATE_CHILD)
        .expect("synthetic candidate should pass negative checks");

    assert_eq!(candidate.app_version(), "thirdparty-example@1.2.3");
    assert_eq!(candidate.child_client_id(), "thirdparty-example");
}

#[test]
fn sdk_default_is_never_a_live_candidate() {
    for (app_version, child_id) in [
        ("Other@1.0.0", "thirdparty-example"),
        ("thirdparty-example@1.0.0", "Other"),
    ] {
        assert_eq!(
            Candidate::try_new(app_version, child_id),
            Err(ClientIdentityError::SdkDefault)
        );
    }
}

#[test]
fn known_first_party_mail_ids_are_rejected_case_insensitively() {
    for client_id in [
        "web-mail",
        "windows-mail",
        "macos-mail",
        "linux-mail",
        "ios-mail",
        "android-mail",
        "WEB-MAIL",
        "iOS-mail",
    ] {
        let app_version = format!("{client_id}@1.0.0");
        assert_eq!(
            Candidate::try_new(app_version, CANDIDATE_CHILD),
            Err(ClientIdentityError::FirstPartyMail)
        );
        assert_eq!(
            Candidate::try_new(CANDIDATE_APP, client_id),
            Err(ClientIdentityError::FirstPartyMail)
        );
    }
}

#[test]
fn unversioned_or_framing_unsafe_candidates_fail_closed() {
    assert_eq!(
        Candidate::try_new("thirdparty-example", "safe"),
        Err(ClientIdentityError::MissingVersion)
    );
    for value in [
        "",
        " padded",
        "bad:value",
        "bad value",
        "bad\nvalue",
        "client-\u{1f6ab}",
    ] {
        assert!(matches!(
            Candidate::try_new(CANDIDATE_APP, value),
            Err(ClientIdentityError::InvalidSyntax)
        ));
    }
}
