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
//   - Synthetic shared CDP response provenance and status-order tests.
// - Must-Not:
//   - Contact a provider or retain browser headers, credentials, or bodies.
// - Allows:
//   - Check cached-source hints and promised HTTP status completion.
// - Split-When:
//   - Provider-specific evidence needs a separate lifecycle test suite.
// - Merge-When:
//   - One read-capture suite owns all provider GET provenance checks.
// - Summary:
//   - Ensures shared passive network provenance state fails closed.
// - Description:
//   - Synthesized CDP metadata checks without network or account access.
// - Usage:
//   - Included below response_provenance as a private unit test module.
// - Defaults:
//   - All status and provenance fixtures are offline and synthetic.
//

//! Synthetic shared CDP provenance and extra-status regression coverage.

use super::ExtraStatusEvidence;
use super::direct_extra_status_is_200;
use super::uncached_provider_response;
use serde_json::json;

#[test]
fn extra_status_presence_and_type_bind_completion() {
    let mut waiting = ExtraStatusEvidence::default();
    assert!(waiting.note_response(&json!({"hasExtraInfo": true})));
    assert!(!waiting.ready());
    assert!(waiting.note_200());
    assert!(waiting.ready());
    assert!(!waiting.note_200(), "a second actual status is ambiguous");

    let mut early = ExtraStatusEvidence::default();
    assert!(early.note_200());
    assert!(early.note_response(&json!({"hasExtraInfo":true})));
    assert!(early.ready());

    let mut contradictory = ExtraStatusEvidence::default();
    assert!(contradictory.note_200());
    assert!(!contradictory.note_response(&json!({"hasExtraInfo":false})));
    let mut absent = ExtraStatusEvidence::default();
    assert!(absent.note_response(&json!({})));
    assert!(absent.ready());
    let mut explicitly_absent = ExtraStatusEvidence::default();
    assert!(explicitly_absent.note_response(&json!({"hasExtraInfo":false})));
    assert!(!explicitly_absent.note_200());
    for invalid in [json!(null), json!(1i32), json!("true"), json!([])] {
        let mut evidence = ExtraStatusEvidence::default();
        assert!(!evidence.note_response(&json!({"hasExtraInfo":invalid})));
    }
}

#[test]
fn network_status_accepts_only_exact_integer_200() {
    assert!(direct_extra_status_is_200(&json!({
        "params": {"statusCode": 200u16}
    })));
    for value in [json!(304u16), json!(503u16), json!(null), json!("200")] {
        assert!(!direct_extra_status_is_200(&json!({
            "params": {"statusCode": value}
        })));
    }
    assert!(!direct_extra_status_is_200(&json!({"params": {}})));
    assert!(!direct_extra_status_is_200(&json!({})));
}

#[test]
fn contradictory_source_hints_override_false_flags() {
    let mut response = json!({
        "fromDiskCache": false,
        "fromServiceWorker": false,
        "fromPrefetchCache": false,
        "fromEarlyHints": false
    });
    assert!(uncached_provider_response(&response));
    for (field, value) in [
        ("serviceWorkerResponseSource", json!("network")),
        ("cacheStorageCacheName", json!("cache")),
        (
            "serviceWorkerRouterInfo",
            json!({"actualSourceType":"network"}),
        ),
    ] {
        response[field] = value;
        assert!(!uncached_provider_response(&response));
        response
            .as_object_mut()
            .expect("fixture object")
            .remove(field);
        assert!(uncached_provider_response(&response));
    }
}
