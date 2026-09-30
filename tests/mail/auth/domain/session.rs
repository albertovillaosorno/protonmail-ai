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
//   - Synthetic regression evidence for authentication session applys.
// - Must-Not:
//   - Use real accounts, credentials, browsers, networks, or secret stores.
// - Allows:
//   - Exercise provider-neutral session events and fail-closed authority rules.
// - Split-When:
//   - Session lifecycle suites require independent fixtures or runtimes.
// - Merge-When:
//   - Another deterministic suite fully covers the authentication state
//     machine.
// - Summary:
//   - Verifies secret-free authentication session lifecycle behavior.
// - Description:
//   - Proves cancellation, expiry, revocation, logout, and store-failure rules.
// - Usage:
//   - Run through the workspace test gate.
// - Defaults:
//   - Synthetic local-only execution with no authority or external systems.
//

//! Authentication session state-machine regression tests.

use mail_auth_domain::{SessionEvent, SessionState, apply};

#[test]
fn aborted_login_never_installs_new_authority() {
    let aborted = SessionEvent::InteractiveLoginAborted;
    let absent = apply(SessionState::Absent, aborted);
    let existing = apply(SessionState::Valid, aborted);

    assert_eq!(absent, SessionState::Absent);
    assert_eq!(existing, SessionState::Valid);
}

#[test]
fn installed_and_provider_accepted_sessions_are_usable() {
    let login = SessionEvent::LoginInstalled;
    let installed = apply(SessionState::Absent, login);
    let refreshed = apply(installed, SessionEvent::ProviderAccepted);

    assert!(installed.authority_available());
    assert!(refreshed.authority_available());
}

#[test]
fn provider_expiry_and_revocation_fail_closed() {
    let expired_event = SessionEvent::ProviderExpired;
    let revoked_event = SessionEvent::ProviderRevoked;
    let expired = apply(SessionState::Valid, expired_event);
    let revoked = apply(SessionState::Valid, revoked_event);

    assert_eq!(expired, SessionState::Expired);
    assert_eq!(revoked, SessionState::Revoked);
    assert!(!expired.authority_available());
    assert!(!revoked.authority_available());
}

#[test]
fn logout_is_idempotent_from_every_state() {
    let states = [
        SessionState::Absent,
        SessionState::AccountMismatch,
        SessionState::Expired,
        SessionState::Revoked,
        SessionState::StoreUnavailable,
        SessionState::Valid,
    ];

    for state in states {
        let once = apply(state, SessionEvent::LocalLogoutCompleted);
        let twice = apply(once, SessionEvent::LocalLogoutCompleted);
        assert_eq!(once, SessionState::Absent);
        assert_eq!(twice, SessionState::Absent);
    }
}

#[test]
fn store_failure_and_account_mismatch_disable_authority() {
    let store_failure = SessionEvent::StoreUnavailable;
    let account_mismatch = SessionEvent::AccountMismatchDetected;
    let unavailable = apply(SessionState::Valid, store_failure);
    let mismatch = apply(SessionState::Valid, account_mismatch);

    assert_eq!(unavailable, SessionState::StoreUnavailable);
    assert_eq!(mismatch, SessionState::AccountMismatch);
    assert!(!unavailable.authority_available());
    assert!(!mismatch.authority_available());
}
