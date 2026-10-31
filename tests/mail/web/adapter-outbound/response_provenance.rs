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
use super::bodyless_cdp_get;
use super::direct_extra_status_is_200;
use super::non_speculative_cdp_get;
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

#[test]
fn insecure_network_security_states_cannot_prove_direct_provider_http() {
    let ordinary = json!({
        "status":200u16, "mimeType":"application/json",
        "fromDiskCache":false, "fromServiceWorker":false
    });
    assert!(uncached_provider_response(&ordinary));
    let mut secure = ordinary.clone();
    secure["securityState"] = json!("secure");
    assert!(uncached_provider_response(&secure));
    for alias in ["SecurityState", "securitySTATE", "securityStateFuture"] {
        let mut ambiguous = secure.clone();
        ambiguous[alias] = json!("insecure");
        assert!(
            !uncached_provider_response(&ambiguous),
            "unreviewed CDP security state alias {alias} must fail closed"
        );
    }
    for invalid in [
        json!("insecure"),
        json!("insecure-broken"),
        json!("neutral"),
        json!("unknown"),
        json!("info"),
        json!("future"),
        json!(null),
        json!(true),
        json!(42i32),
    ] {
        let mut response = ordinary.clone();
        response["securityState"] = invalid.clone();
        assert!(
            !uncached_provider_response(&response),
            "unsafe CDP security state {invalid} must not establish HTTP proof"
        );
    }
}

#[test]
fn unknown_response_source_markers_cannot_prove_direct_http() {
    let ordinary_response = json!({
        "status": 200u16, "mimeType": "application/json",
        "fromDiskCache": false, "fromServiceWorker": false,
        "fromPrefetchCache": false, "fromEarlyHints": false
    });
    assert!(uncached_provider_response(&ordinary_response));
    for (name, marker) in [
        ("fromMemoryCache", json!(true)),
        ("FromDiskCache", json!(true)),
        ("fromUnknownProvider", json!(false)),
        ("serviceWorkerNewSource", json!("network")),
        ("ServiceWorkerRouterInfo", json!(null)),
        ("cacheStorageFuture", json!({})),
        ("CacheStorageCacheName", json!("cache")),
        ("isFromDiskCache", json!(true)),
        ("ISFROMDISKCACHE", json!(false)),
        ("servedFromCache", json!(true)),
        ("wasServedFromCache", json!(false)),
        ("cacheEntrySource", json!("disk")),
        ("prefetchResponseSource", json!("network")),
        ("sourceKind", json!("cache")),
        // Non-prefix extensions still advertise alternate response origins.
        ("isCached", json!(false)),
        ("wasCached", json!(true)),
        ("servedByServiceWorker", json!(false)),
        ("responseSource", json!("network")),
        ("responseCacheStatus", json!("miss")),
        ("hasPrefetchSource", json!(false)),
        ("transportSecurityState", json!("secure")),
    ] {
        let mut response = ordinary_response.clone();
        response[name] = marker;
        assert!(
            !uncached_provider_response(&response),
            "unreviewed source marker {name} must not prove direct HTTP"
        );
    }
    assert!(!uncached_provider_response(&json!(null)));
}

#[test]
fn non_ascii_cdp_response_field_names_cannot_prove_direct_http() {
    // CDP response metadata names are ASCII protocol identifiers. Unicode
    // lookalikes must not hide a cache/source hint from our provenance gate.
    let ordinary = json!({
        "status":200u16, "mimeType":"application/json",
        "fromDiskCache":false, "fromServiceWorker":false
    });
    assert!(uncached_provider_response(&ordinary));
    for (name, value) in [
        ("fromDiskCa\u{0441}he", json!(true)),
        ("securitySt\u{0430}te", json!("insecure")),
        ("\u{5b89}\u{5168}", json!(null)),
    ] {
        let mut response = ordinary.clone();
        response[name] = value;
        assert!(
            !uncached_provider_response(&response),
            "non-ASCII CDP field {name} cannot prove direct HTTP"
        );
    }
}

#[test]
fn only_explicitly_bodyless_cdp_requests_can_prove_read_only_get() {
    for request in [
        json!({"method":"GET","url":"https://mail.proton.me/"}),
        json!({"method":"GET","hasPostData":false}),
    ] {
        assert!(bodyless_cdp_get(&request));
    }
    for request in [
        json!(null),
        json!({"method":"GET","hasPostData":true}),
        json!({"method":"GET","hasPostData":null}),
        json!({"method":"GET","hasPostData":"false"}),
        json!({"method":"GET","postData":"private"}),
        json!({"method":"GET","postData":null}),
        json!({"method":"GET","postDataEntries":[]}),
    ] {
        assert!(!bodyless_cdp_get(&request));
    }
}

#[test]
fn speculative_browser_gets_cannot_establish_active_read_provenance() {
    let ordinary = json!({
        "params":{"request":{"method":"GET","isLinkPreload":false},
            "type":"Fetch","initiator":{"type":"script"}}
    });
    assert!(non_speculative_cdp_get(&ordinary));
    let mut legacy = ordinary.clone();
    legacy["params"]
        .as_object_mut()
        .expect("object")
        .remove("type");
    legacy["params"]
        .as_object_mut()
        .expect("object")
        .remove("initiator");
    legacy["params"]["request"]
        .as_object_mut()
        .expect("object")
        .remove("isLinkPreload");
    assert!(non_speculative_cdp_get(&legacy));
    for (field, value) in [
        ("link", json!(true)),
        ("link", json!(null)),
        ("resource", json!("Prefetch")),
        ("resource", json!("Preflight")),
        ("resource", json!(null)),
        ("initiator", json!({"type":"preload"})),
        ("initiator", json!({"type":"preflight"})),
        ("initiator", json!({"type":null})),
    ] {
        let mut event = ordinary.clone();
        if field == "link" {
            event["params"]["request"]["isLinkPreload"] = value;
        } else if field == "resource" {
            event["params"]["type"] = value;
        } else {
            event["params"]["initiator"] = value;
        }
        assert!(!non_speculative_cdp_get(&event), "unsafe {field}");
    }
}
