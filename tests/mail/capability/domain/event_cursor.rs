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
//   - Provider-neutral event-cursor scope regression tests.
// - Must-Not:
//   - Encode provider state, credentials, account content, or transport tokens.
// - Allows:
//   - Exercise account, adapter, generation, and diagnostic binding rules.
// - Split-When:
//   - Cursor serialization gains a distinct public transport test suite.
// - Merge-When:
//   - Event cursor and change-envelope contracts become one fixture.
// - Summary:
//   - Proves event cursor state cannot cross its provider-neutral scope.
// - Description:
//   - Synthetic values exercise exact scope equality and redacted diagnostics.
// - Usage:
//   - Run through the mail_capability_domain event-cursor test target.
// - Defaults:
//   - No provider, browser, network, credential, or filesystem interaction.
//

//! Provider-neutral event-cursor binding regression tests.

use mail_capability_domain::EventCursorResumeFailure;
use mail_capability_domain::ScopedEventCursor;
use mail_capability_domain::{EventCursorBindingError, EventCursorScope};

#[test]
fn cursor_scope_and_state_have_drop_time_secret_scrubbing() {
    // Scope accounts and adapter state are private even when their public
    // Debug implementations redact them. Both require explicit Drop custody.
    #[expect(drop_bounds, reason = "require explicit zeroization on drop")]
    fn require_drop<T>()
    where
        T: Drop,
    {
    }
    require_drop::<EventCursorScope>();
    require_drop::<ScopedEventCursor<String>>();

    // jig-ignore-next-line: rustfmt canonical synthetic cursor scope.
    let scope = EventCursorScope::new("private-account", "web", "generation").expect("valid scope");
    let cursor = scope.clone().bind(String::from("private-watermark"));
    assert_eq!(
        cursor.state_for(&scope).map(String::as_str),
        Ok("private-watermark")
    );
}

#[test]
fn exact_scope_releases_opaque_adapter_state() {
    let scope = EventCursorScope::new("account-a", "web", "generation-7")
        .expect("valid synthetic cursor scope");
    let cursor = scope.clone().bind(String::from("provider-event-9"));
    assert_eq!(
        cursor.state_for(&scope).map(String::as_str),
        Ok("provider-event-9")
    );
}

#[test]
fn account_adapter_or_generation_drift_has_stable_resume_class() {
    let original =
        // jig-ignore-next-line: canonical rustfmt line.
        EventCursorScope::new("account-a", "web", "generation-7").expect("valid original scope");
    let cursor = original.bind(String::from("provider-event-9"));
    let cases = [
        (
            EventCursorScope::new("account-b", "web", "generation-7"),
            EventCursorBindingError::AccountMismatch,
            EventCursorResumeFailure::InvalidCursor,
        ),
        (
            EventCursorScope::new("account-a", "direct", "generation-7"),
            EventCursorBindingError::AdapterMismatch,
            EventCursorResumeFailure::InvalidCursor,
        ),
        (
            EventCursorScope::new("account-a", "web", "generation-8"),
            EventCursorBindingError::GenerationMismatch,
            EventCursorResumeFailure::CursorExpired,
        ),
    ];
    for (current, expected_binding, expected_resume) in cases {
        let error = cursor
            .state_for(&current.expect("valid drifted scope"))
            .expect_err("drifted scope must reject cursor");
        assert_eq!(error, expected_binding);
        assert_eq!(error.resume_failure(), expected_resume);
    }
}

#[test]
fn malformed_scope_components_fail_closed() {
    assert_eq!(
        EventCursorBindingError::MalformedScope.resume_failure(),
        EventCursorResumeFailure::InvalidCursor
    );
    for result in [
        EventCursorScope::new("", "web", "generation-7"),
        EventCursorScope::new("account-a", "", "generation-7"),
        EventCursorScope::new("account-a", "web", ""),
        EventCursorScope::new(&"a".repeat(513), "web", "generation-7"),
    ] {
        assert_eq!(result, Err(EventCursorBindingError::MalformedScope));
    }
}

#[test]
fn cursor_account_rejects_ambiguous_identity_without_normalizing_unicode() {
    for bad in [
        "account\n",
        "account\u{00a0}",
        "account\u{034f}",
        "account\u{200b}",
        "account\u{202e}",
        "account\u{2800}",
        "account\u{fe0f}",
        "account\u{e0100}",
    ] {
        assert_eq!(
            EventCursorScope::new(bad, "web", "generation"),
            Err(EventCursorBindingError::MalformedScope)
        );
    }
    let printable = "compte-\u{e9}t\u{e9}-\u{5e33}\u{6236}";
    let scope = EventCursorScope::new(printable, "web", "generation")
        .expect("printable Unicode remains an opaque account identity");
    assert_eq!(scope.binding_components().0, printable);
    let max_account = "\u{e9}".repeat(256);
    assert!(EventCursorScope::new(&max_account, "web", "generation").is_ok());
}

#[test]
fn diagnostics_redact_scope_and_provider_state() {
    let scope = EventCursorScope::new(
        "synthetic-account-secret",
        "synthetic-adapter-secret",
        "synthetic-generation-secret",
    )
    .expect("valid synthetic cursor scope");
    let cursor = scope.bind(String::from("synthetic-provider-secret"));
    let debug = format!("{cursor:?}");
    for secret in [
        "synthetic-account-secret",
        "synthetic-adapter-secret",
        "synthetic-generation-secret",
        "synthetic-provider-secret",
    ] {
        assert!(!debug.contains(secret));
    }
}
