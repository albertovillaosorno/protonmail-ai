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

use mail_capability_domain::{EventCursorBindingError, EventCursorScope};

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
fn account_adapter_or_generation_drift_rejects_resume() {
    let original =
        // jig-ignore-next-line: canonical rustfmt line.
        EventCursorScope::new("account-a", "web", "generation-7").expect("valid original scope");
    let cursor = original.bind(String::from("provider-event-9"));
    for current in [
        EventCursorScope::new("account-b", "web", "generation-7"),
        EventCursorScope::new("account-a", "direct", "generation-7"),
        EventCursorScope::new("account-a", "web", "generation-8"),
    ] {
        assert_eq!(
            cursor.state_for(&current.expect("valid drifted scope")),
            Err(EventCursorBindingError::ScopeMismatch)
        );
    }
}

#[test]
fn malformed_scope_components_fail_closed() {
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
