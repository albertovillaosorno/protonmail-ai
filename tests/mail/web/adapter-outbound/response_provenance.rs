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
use super::RequestExtraInfoEvidence;
use super::bodyless_cdp_get;
use super::direct_cdp_read_response;
use super::direct_extra_status_is_200;
use super::non_speculative_cdp_get;
use super::uncached_provider_response;
use serde_json::json;

#[test]
fn provisional_and_refined_http2_paths_match_exact_cdp_url() {
    let url = "https://mail.proton.me/api/mail/v4/messages?Page=0";
    let path = "/api/mail/v4/messages?Page=0";
    let request = json!({"method":"GET", "url":url,
        "headers":{":method":"GET", ":scheme":"https",
            ":authority":"mail.proton.me", ":path":path}});
    assert!(bodyless_cdp_get(&request));
    let response = json!({"url":url, "status":200u16,
        "requestHeaders":{":method":"GET", ":scheme":"https",
            ":authority":"mail.proton.me", ":path":path}});
    assert!(uncached_provider_response(&response));

    for other in ["/api/core/v4/users", "/api/mail/v4/messages?Page=1"] {
        let mut swapped_request = request.clone();
        swapped_request["headers"][":path"] = json!(other);
        assert!(!bodyless_cdp_get(&swapped_request));
        let mut swapped_response = response.clone();
        swapped_response["requestHeaders"][":path"] = json!(other);
        assert!(!uncached_provider_response(&swapped_response));
    }
    let mut missing_url = request;
    missing_url
        .as_object_mut()
        .expect("request object")
        .remove("url");
    assert!(!bodyless_cdp_get(&missing_url));
    let mut missing_url_response = response;
    missing_url_response
        .as_object_mut()
        .expect("response object")
        .remove("url");
    assert!(!uncached_provider_response(&missing_url_response));
}

#[test]
fn http2_pseudo_headers_must_prove_the_same_mail_get() {
    let ordinary = json!({"params":{"requestId":"h2-request", "headers":{
        ":authority":"mail.proton.me", ":method":"GET", ":scheme":"https",
        ":path":"/api/mail/v4/messages?Page=0", "Accept":"application/json"
    }}});
    let mut evidence = RequestExtraInfoEvidence::default();
    assert!(evidence.note_event(&ordinary).is_some());
    assert!(!evidence.rejects("h2-request"));

    for (header, value) in [
        (":authority", "foreign.invalid"),
        (":method", "POST"),
        (":scheme", "http"),
        (":path", "/logout"),
        (":path", "/api/mail/v4/messages#fragment"),
    ] {
        let mut contradictory = ordinary.clone();
        contradictory["params"]["headers"][header] = json!(value);
        let mut probe = RequestExtraInfoEvidence::default();
        assert!(probe.note_event(&contradictory).is_some());
        assert!(probe.rejects("h2-request"));
    }
    let mut future = ordinary.clone();
    future["params"]["headers"][":future"] = json!("unknown");
    assert!(evidence.note_event(&future).is_some());
    assert!(evidence.rejects("h2-request"));
}

#[test]
fn insecure_request_extra_client_cannot_prove_mail_page_ownership() {
    let valid = json!({"params":{"requestId":"secure-page",
        "headers":{"Host":"mail.proton.me"},
        "clientSecurityState":{"initiatorIsSecureContext":true,
            "initiatorIPAddressSpace":"Public"}}});
    let mut evidence = RequestExtraInfoEvidence::default();
    assert_eq!(evidence.note_event(&valid), Some("secure-page"));
    assert!(!evidence.rejects("secure-page"));
    for invalid in [json!(false), json!(null), json!("true"), json!(1i32)] {
        let mut extra = valid.clone();
        extra["params"]["requestId"] = json!("insecure-page");
        let client_state = &mut extra["params"]["clientSecurityState"];
        client_state["initiatorIsSecureContext"] = invalid;
        let mut probe = RequestExtraInfoEvidence::default();
        assert_eq!(probe.note_event(&extra), Some("insecure-page"));
        assert!(probe.rejects("insecure-page"));
    }
    let mut malformed = valid;
    malformed["params"]["clientSecurityState"] = json!(null);
    let mut probe = RequestExtraInfoEvidence::default();
    assert_eq!(probe.note_event(&malformed), Some("secure-page"));
    assert!(probe.rejects("secure-page"));
}

#[test]
fn wire_request_extra_info_custody_is_bounded_and_header_only() {
    let mut evidence = RequestExtraInfoEvidence::default();
    let safe = json!({"params":{"requestId":"safe",
        "headers":{"Host":"mail.proton.me", "Content-Length":"0",
            "Sec-Fetch-Mode":"cors"}}});
    assert_eq!(evidence.note_event(&safe), Some("safe"));
    assert!(!evidence.rejects("safe"));

    for (id, header, value) in [
        ("foreign", "Host", "foreign.invalid"),
        ("framed", "Content-Length", "12"),
        ("replayed", "Cache-Control", "only-if-cached"),
        ("method", "X-HTTP-Method-Override", "POST"),
        ("speculative", "Purpose", "prefetch"),
    ] {
        let event = json!({"params":{"requestId":id,
            "headers":{header:value}}});
        assert_eq!(evidence.note_event(&event), Some(id));
        assert!(evidence.rejects(id));
    }
    let later_safe = json!({"params":{"requestId":"foreign",
        "headers":{"Host":"mail.proton.me"}}});
    assert_eq!(evidence.note_event(&later_safe), Some("foreign"));
    assert!(
        evidence.rejects("foreign"),
        "later headers cannot erase rejection"
    );
    for malformed in [
        json!({"params":{"requestId":"missing"}}),
        json!({"params":{"requestId":"string", "headers":"untyped"}}),
        json!({"params":{"requestId":"nonprint\n", "headers":{}}}),
    ] {
        assert_eq!(evidence.note_event(&malformed), None);
    }

    // Only a bounded number of early untrusted request IDs may be retained;
    // neither header maps nor their values become part of capture state.
    let mut bounded = RequestExtraInfoEvidence::default();
    for index in 0..super::MAX_UNSAFE_EXTRA_REQUEST_IDS {
        let event = json!({"params":{"requestId":format!("synthetic-{index}"),
            "headers":{"Host":"foreign.invalid"}}});
        assert!(bounded.note_event(&event).is_some());
    }
    let over_limit = json!({"params":{"requestId":"over-limit",
        "headers":{"Host":"foreign.invalid"}}});
    assert!(bounded.note_event(&over_limit).is_none());
    assert!(!bounded.rejects("over-limit"));
}

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
fn extra_status_http2_pseudo_header_must_confirm_200() {
    let real_http2 = json!({"params":{"statusCode":200u16,
        "headers":{":status":"200", "content-type":"application/json"}}});
    assert!(direct_extra_status_is_200(&real_http2));
    for (pseudo, value) in [
        (":status", "304"),
        (":status", "200 OK"),
        (":method", "GET"),
        (":authority", "mail.proton.me"),
    ] {
        let mut invalid = real_http2.clone();
        invalid["params"]["headers"]
            .as_object_mut()
            .expect("headers map")
            .remove(":status");
        invalid["params"]["headers"][pseudo] = json!(value);
        assert!(!direct_extra_status_is_200(&invalid));
    }
}

#[test]
fn malformed_json_mime_extension_parameters_are_not_http_evidence() {
    for valid in [
        "application/json; profile=standard",
        "application/json; profile=\"multi word\"",
        "application/json; charset=utf-8; profile=\"other\"",
    ] {
        let event = json!({"params":{"statusCode":200u16,
            "headers":{"Content-Type":valid}}});
        assert!(direct_extra_status_is_200(&event));
    }
    for bad in [
        "application/json; profile=two words",
        "application/json; profile=two=words",
        "application/json; profile=\"unterminated",
        "application/json; profile=\"ok\"garbage",
        "application/json; profile=inv\u{e1}lido",
    ] {
        let event = json!({"params":{"statusCode":200u16,
            "headers":{"Content-Type":bad}}});
        assert!(
            !direct_extra_status_is_200(&event),
            "malformed MIME parameter"
        );
        let response = json!({"headers":{"Content-Type":bad}});
        assert!(!uncached_provider_response(&response));
    }
}

#[test]
fn extra_status_wire_content_type_must_confirm_json_response() {
    for valid in [
        "application/json",
        "application/json; charset=utf-8",
        "Application/JSON;Charset=UTF-8",
        r#"application/json; charset="utf-8""#,
    ] {
        let event = json!({"params":{"statusCode":200u16,
            "headers":{"Content-Type":valid}}});
        assert!(direct_extra_status_is_200(&event));
    }
    for invalid in [
        json!("text/html"),
        json!("application/javascript"),
        json!("application/json, text/html"),
        json!("application/json; charset=utf-8, text/html"),
        json!("application/json; charset=iso-8859-1"),
        json!("application/json; charset=utf-8; charset=iso-8859-1"),
        json!("application/json; charset="),
        json!("application/json; invalid-parameter"),
        json!(null),
        json!(["application/json"]),
    ] {
        let event = json!({"params":{"statusCode":200u16,
            "headers":{"Content-Type":invalid}}});
        assert!(!direct_extra_status_is_200(&event));
    }
    let duplicate = json!({"params":{"statusCode":200u16,
        "headers":{"Content-Type":"application/json",
            "content-type":"text/html"}}});
    assert!(!direct_extra_status_is_200(&duplicate));
    assert!(!direct_extra_status_is_200(&json!({"params":{
        "statusCode":200u16, "headers":"not-an-object"}})));
}

#[test]
fn raw_wire_response_headers_must_correlate_with_structured_json_200() {
    let original = json!({"params":{"statusCode":200u16,
        "headers":{"Content-Type":"application/json; charset=utf-8"},
        // jig-ignore-next-line: synthetic raw wire CRLF fixture.
        "headersText":"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nDate: Sat, 31 Oct 2026 09:00:00 GMT\r\n\r\n"}});
    assert!(direct_extra_status_is_200(&original));
    let accepted = json!({"params":{"statusCode":200u16,
        // jig-ignore-next-line: synthetic raw wire CRLF fixture.
        "headersText":"HTTP/1.0 200\r\nContent-Type: application/json\r\n\r\n"}});
    assert!(direct_extra_status_is_200(&accepted));

    for raw in [
        "HTTP/1.1 304 Not Modified\r\nContent-Type: application/json\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
        // jig-ignore-next-line: synthetic ambiguous MIME list fixture.
        "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8, text/html\r\n\r\n",
        // jig-ignore-next-line: synthetic raw wire CRLF fixture.
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Type: text/html\r\n\r\n",
        // jig-ignore-next-line: synthetic raw wire CRLF fixture.
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Type: application/json\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\n\n",
        // jig-ignore-next-line: synthetic raw wire CRLF fixture.
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\nInjected: unknown\r\n\r\n",
    ] {
        let mut changed = original.clone();
        changed["params"]["headersText"] = json!(raw);
        assert!(
            !direct_extra_status_is_200(&changed),
            "raw headers must not override structured proof"
        );
    }
    for invalid in [json!(null), json!([]), json!(0u16), json!("")] {
        let mut changed = original.clone();
        changed["params"]["headersText"] = invalid;
        assert!(!direct_extra_status_is_200(&changed));
    }
    let mut conflicting = original;
    conflicting["params"]["headersText"] =
        json!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n");
    assert!(
        !direct_extra_status_is_200(&conflicting),
        "raw and structured media types must agree"
    );
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
fn speculative_event_and_initiator_aliases_cannot_prove_active_read() {
    let ordinary = json!({
        "params": {"request": {"method": "GET", "isLinkPreload": false},
            "type": "Fetch", "initiator": {"type": "script"}}
    });
    assert!(non_speculative_cdp_get(&ordinary));
    for (kind, name, value) in [
        ("event", "isPrefetch", json!(true)),
        ("event", "wasPreloaded", json!(false)),
        ("event", "prerenderHint", json!(null)),
        ("initiator", "isPrefetch", json!(true)),
        ("initiator", "wasPreloaded", json!(false)),
        ("initiator", "speculativeHint", json!(false)),
    ] {
        let mut event = ordinary.clone();
        if kind == "event" {
            event["params"][name] = value;
        } else {
            event["params"]["initiator"][name] = value;
        }
        assert!(
            !non_speculative_cdp_get(&event),
            "unreviewed speculative {kind} field {name} must fail closed"
        );
    }
}

#[test]
fn unreviewed_request_speculation_markers_cannot_prove_active_mail_get() {
    let ordinary = json!({
        "params": {"request": {"method": "GET", "isLinkPreload": false},
            "type": "Fetch", "initiator": {"type": "script"}}
    });
    assert!(bodyless_cdp_get(&ordinary["params"]["request"]));
    assert!(non_speculative_cdp_get(&ordinary));
    for (name, value) in [
        ("IsLinkPreload", json!(true)),
        ("isPrefetch", json!(true)),
        ("wasPreloaded", json!(false)),
        ("requestPrerender", json!(false)),
        ("preflightRequest", json!(null)),
        ("speculativeHint", json!(false)),
    ] {
        let mut event = ordinary.clone();
        event["params"]["request"][name] = value;
        assert!(bodyless_cdp_get(&event["params"]["request"]));
        assert!(
            !non_speculative_cdp_get(&event),
            "unreviewed speculative Request field {name} cannot prove a read"
        );
    }
}

#[test]
fn explicit_foreign_origin_header_cannot_prove_mail_api_read() {
    let ordinary = json!({
        "params": {"request": {"method": "GET",
            "headers": {"Origin": "https://mail.proton.me"}},
            "type": "Fetch", "initiator": {"type": "script"}}
    });
    assert!(non_speculative_cdp_get(&ordinary));
    for origin in [
        json!("https://account.proton.me"),
        json!("https://mail.proton.me.evil.invalid"),
        json!("http://mail.proton.me"),
        json!("null"),
        json!("https://mail.proton.me:8443"),
    ] {
        let mut event = ordinary.clone();
        event["params"]["request"]["headers"]["Origin"] = origin;
        assert!(
            !non_speculative_cdp_get(&event),
            "explicit foreign Origin must reject passive Mail API read"
        );
    }
}

#[test]
fn cross_site_cdp_request_hint_cannot_prove_active_mail_read() {
    let ordinary = json!({
        "params": {"request": {"method": "GET", "isSameSite": true},
            "type": "Fetch", "initiator": {"type": "script"}}
    });
    assert!(non_speculative_cdp_get(&ordinary));
    let mut absent = ordinary.clone();
    absent["params"]["request"]
        .as_object_mut()
        .expect("synthetic request")
        .remove("isSameSite");
    assert!(non_speculative_cdp_get(&absent));
    for invalid in [json!(false), json!(null), json!("true"), json!(0i32)] {
        let mut event = ordinary.clone();
        event["params"]["request"]["isSameSite"] = invalid;
        assert!(
            !non_speculative_cdp_get(&event),
            "a cross-site or malformed browser site hint is not Mail evidence"
        );
    }
}

#[test]
fn only_if_cached_request_directive_cannot_prove_direct_http() {
    let ordinary = json!({
        "params": {"request": {"method": "GET",
            "headers": {"Cache-Control": "no-cache"}},
            "type": "Fetch", "initiator": {"type": "script"}}
    });
    assert!(non_speculative_cdp_get(&ordinary));
    for directive in [
        "only-if-cached",
        "max-age=0, only-if-cached",
        "ONLY-IF-CACHED",
        "no-cache, ONLY-IF-CACHED, max-age=0",
    ] {
        let mut event = ordinary.clone();
        let headers = &mut event["params"]["request"]["headers"];
        headers["Cache-Control"] = json!(directive);
        assert!(
            !non_speculative_cdp_get(&event),
            "explicit cache-only request cannot prove direct provider HTTP"
        );
        let mut refined = json!({
            "params": {"type": "Fetch", "response": {
                "status": 200u16, "mimeType": "application/json",
                "requestHeaders": {"Cache-Control": "no-cache"}
            }}
        });
        let wire = &mut refined["params"]["response"]["requestHeaders"];
        wire["Cache-Control"] = json!(directive);
        assert!(
            !direct_cdp_read_response(&refined),
            "refined cache-only request cannot prove direct provider HTTP"
        );
    }
}

#[test]
fn duplicated_origin_singleton_headers_cannot_prove_mail_read() {
    let ordinary = json!({
        "params": {"request": {"method": "GET",
            "headers": {"Host": "mail.proton.me"}},
            "type": "Fetch", "initiator": {"type": "script"}}
    });
    assert!(non_speculative_cdp_get(&ordinary));
    for (canonical, duplicate, value) in [
        ("Host", "host", "mail.proton.me"),
        ("Origin", "origin", "https://mail.proton.me"),
        ("Referer", "referer", "https://mail.proton.me/u/0/inbox"),
        ("Sec-Fetch-Mode", "sec-fetch-mode", "cors"),
        ("Sec-Fetch-Site", "sec-fetch-site", "same-origin"),
        ("Sec-Fetch-Dest", "sec-fetch-dest", "empty"),
    ] {
        let mut event = ordinary.clone();
        let headers = &mut event["params"]["request"]["headers"];
        headers[canonical] = json!(value);
        headers[duplicate] = json!(value);
        assert!(
            !non_speculative_cdp_get(&event),
            "duplicate singleton {canonical} cannot establish origin"
        );
        let mut refined = json!({
            "params": {"type": "Fetch", "response": {
                "status": 200u16, "mimeType": "application/json",
                "requestHeaders": {"Accept": "application/json"}
            }}
        });
        let wire = &mut refined["params"]["response"]["requestHeaders"];
        wire[canonical] = json!(value);
        wire[duplicate] = json!(value);
        assert!(
            !direct_cdp_read_response(&refined),
            "duplicate transmitted singleton {canonical} is ambiguous"
        );
    }
}

#[test]
fn proxy_routing_headers_cannot_prove_direct_mail_api_read() {
    let ordinary = json!({
        "params": {"request": {"method": "GET",
            "headers": {"Host": "mail.proton.me"}},
            "type": "Fetch", "initiator": {"type": "script"}}
    });
    assert!(non_speculative_cdp_get(&ordinary));
    for header in [
        "Forwarded",
        "forwarded",
        "X-Forwarded-Host",
        "X-Forwarded-Proto",
        "X-Forwarded-Prefix",
        "X-Forwarded-Port",
        "X-Original-Host",
        "X-Original-URL",
        "X-Original-URI",
        "X-Forwarded-URI",
        "X-Rewrite-URL",
    ] {
        let mut request = ordinary.clone();
        let headers = &mut request["params"]["request"]["headers"];
        headers[header] = json!("host=foreign.invalid");
        assert!(
            !non_speculative_cdp_get(&request),
            "proxy routing metadata {header} contradicts a direct Mail read"
        );
    }
    let mut response = json!({
        "params": {"type": "Fetch", "response": {
            "status": 200u16, "mimeType": "application/json",
            "requestHeaders": {"Host": "mail.proton.me"}
        }}
    });
    assert!(direct_cdp_read_response(&response));
    let headers = &mut response["params"]["response"]["requestHeaders"];
    headers["X-Forwarded-Host"] = json!("foreign.invalid");
    assert!(!direct_cdp_read_response(&response));
    response["params"]["response"]["requestHeaders"]
        .as_object_mut()
        .expect("header map")
        .remove("X-Forwarded-Host");
    let headers = &mut response["params"]["response"]["requestHeaders"];
    headers["X-Forwarded-Prefix"] = json!("/rewritten");
    assert!(!direct_cdp_read_response(&response));
    // Matching values are not enough: forwarding hints can alter routing.
    let mut same_host = ordinary;
    let headers = &mut same_host["params"]["request"]["headers"];
    headers["Forwarded"] = json!("host=mail.proton.me");
    assert!(!non_speculative_cdp_get(&same_host));
}

#[test]
fn mismatched_host_header_cannot_prove_mail_origin_read() {
    let ordinary = json!({
        "params": {"request": {"method": "GET",
            "headers": {"Host": "mail.proton.me"}},
            "type": "Fetch", "initiator": {"type": "script"}}
    });
    assert!(non_speculative_cdp_get(&ordinary));
    for host in ["MAIL.PROTON.ME", "mail.proton.me:443"] {
        let mut event = ordinary.clone();
        event["params"]["request"]["headers"]["Host"] = json!(host);
        assert!(non_speculative_cdp_get(&event));
    }
    let mut absent = ordinary.clone();
    absent["params"]["request"]["headers"] = json!({});
    assert!(non_speculative_cdp_get(&absent));
    for host in [
        "evil.invalid",
        "mail.proton.me.evil.invalid",
        "mail.proton.me:8443",
        "mail.proton.me@evil.invalid",
        "",
    ] {
        let mut event = ordinary.clone();
        event["params"]["request"]["headers"]["Host"] = json!(host);
        assert!(
            !non_speculative_cdp_get(&event),
            "a contradictory HTTP Host must not establish Mail origin"
        );
    }
}

#[test]
fn foreign_referer_header_cannot_prove_active_mail_read() {
    let ordinary = json!({
        "params": {"request": {"method": "GET",
            "headers": {"Referer": "https://mail.proton.me/u/0/inbox"}},
            "type": "Fetch", "initiator": {"type": "script"}}
    });
    assert!(non_speculative_cdp_get(&ordinary));
    let mut omitted = ordinary.clone();
    omitted["params"]["request"]["headers"]
        .as_object_mut()
        .expect("synthetic header map")
        .remove("Referer");
    assert!(non_speculative_cdp_get(&omitted));
    let mut lowercase = ordinary.clone();
    let headers = json!({"referer": "https://mail.proton.me"});
    lowercase["params"]["request"]["headers"] = headers;
    assert!(non_speculative_cdp_get(&lowercase));
    for referer in [
        "https://evil.invalid/frame",
        "https://mail.proton.me.evil.invalid/u/0/inbox",
        "https://mail.proton.me@evil.invalid/u/0/inbox",
        "https://mail.proton.me:8443/u/0/inbox",
        "http://mail.proton.me/u/0/inbox",
        "https://account.proton.me/u/0/inbox",
        "https://mail.proton.me/invalid path",
        "https://mail.proton.me/\u{1f6e1}\u{fe0f}",
    ] {
        let mut event = ordinary.clone();
        event["params"]["request"]["headers"]["Referer"] = json!(referer);
        assert!(
            !non_speculative_cdp_get(&event),
            "foreign or malformed Referer must not prove a Mail API read"
        );
    }
}

#[test]
fn navigation_fetch_metadata_cannot_prove_active_mail_ajax() {
    let ordinary = json!({
        "params": {"request": {"method": "GET",
            "headers": {"Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Dest": "empty", "Sec-Fetch-Site": "same-origin"}},
            "type": "Fetch", "initiator": {"type": "script"}}
    });
    assert!(non_speculative_cdp_get(&ordinary));
    for (name, value) in [
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Mode", "no-cors"),
        ("sec-fetch-mode", "websocket"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Dest", "image"),
        ("sec-fetch-site", "cross-site"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
    ] {
        let mut event = ordinary.clone();
        event["params"]["request"]["headers"][name] = json!(value);
        assert!(
            !non_speculative_cdp_get(&event),
            "navigation metadata {name}={value} cannot prove an AJAX read"
        );
    }
}

#[test]
fn explicitly_speculative_header_hints_cannot_prove_active_mail_fetches() {
    let ordinary = json!({
        "params": {"request": {"method": "GET",
            "headers": {"Accept": "application/json"},
            "isLinkPreload": false},
            "type": "Fetch", "initiator": {"type": "script"}}
    });
    assert!(bodyless_cdp_get(&ordinary["params"]["request"]));
    assert!(non_speculative_cdp_get(&ordinary));
    for (header, value) in [
        ("Purpose", "prefetch"),
        ("purpose", "prefetch"),
        ("Sec-Purpose", "prefetch"),
        ("sec-purpose", "prefetch;prerender"),
        ("SEC-PURPOSE", "future-purpose"),
    ] {
        let mut event = ordinary.clone();
        event["params"]["request"]["headers"][header] = json!(value);
        assert!(bodyless_cdp_get(&event["params"]["request"]));
        assert!(
            !non_speculative_cdp_get(&event),
            "speculative purpose header {header} cannot prove active read"
        );
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
        ("resource", json!("FedCM")),
        ("resource", json!("prefetch")),
        ("resource", json!("futureResource")),
        ("resource", json!(null)),
        ("initiator", json!({"type":"preload"})),
        ("initiator", json!({"type":"preflight"})),
        ("initiator", json!({"type":"FedCM"})),
        ("initiator", json!({"type":"Preload"})),
        ("initiator", json!({"type":"futureInitiator"})),
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
    for (resource, initiator) in [
        ("Fetch", "script"),
        ("XHR", "parser"),
        ("Fetch", "other"),
        ("XHR", "SignedExchange"),
    ] {
        let mut event = ordinary.clone();
        event["params"]["type"] = json!(resource);
        event["params"]["initiator"]["type"] = json!(initiator);
        assert!(non_speculative_cdp_get(&event));
    }
}

#[test]
fn request_document_origin_cannot_be_laundered_as_mail_activity() {
    let ordinary = json!({
        "params": {
            "request": {"method": "GET"},
            "documentURL": "https://mail.proton.me/u/0/inbox"
        }
    });
    assert!(non_speculative_cdp_get(&ordinary));
    for unsafe_document in [
        json!("https://example.invalid/frame"),
        json!("https://mail.proton.me.evil.invalid/u/0/inbox"),
        json!("https://mail.proton.me:8443/u/0/inbox"),
        json!("http://mail.proton.me/u/0/inbox"),
        json!("https://account.proton.me/u/0/inbox"),
        json!("https://mail.proton.me\\@evil.invalid/"),
        json!("https://mail.proton.me/line break"),
        json!("https://mail.proton.me/\u{1f48c}"),
        json!(null),
        json!(42i32),
        json!(format!("https://mail.proton.me/{}", "a".repeat(16 * 1024))),
    ] {
        let mut event = ordinary.clone();
        event["params"]["documentURL"] = unsafe_document.clone();
        assert!(
            !non_speculative_cdp_get(&event),
            "foreign or malformed requesting document {unsafe_document}"
        );
    }
    let mut legacy = ordinary;
    legacy["params"]
        .as_object_mut()
        .expect("synthetic params object")
        .remove("documentURL");
    assert!(non_speculative_cdp_get(&legacy));
}

#[test]
fn refined_wire_request_headers_must_confirm_passive_get_provenance() {
    let ordinary = json!({
        "params": {"type": "Fetch", "response": {
            "status": 200u16, "mimeType": "application/json",
            "requestHeaders": {
                "Host": "mail.proton.me", "Accept": "application/json"
            }
        }}
    });
    assert!(direct_cdp_read_response(&ordinary));
    let mut legacy = ordinary.clone();
    legacy["params"]["response"]
        .as_object_mut()
        .expect("synthetic response")
        .remove("requestHeaders");
    assert!(direct_cdp_read_response(&legacy));
    for (name, value) in [
        ("Host", json!("evil.invalid")),
        ("Origin", json!("https://foreign.invalid")),
        ("Referer", json!("https://foreign.invalid/frame")),
        ("Sec-Fetch-Site", json!("cross-site")),
        ("Purpose", json!("prefetch")),
        ("Content-Length", json!("12")),
        ("Transfer-Encoding", json!("chunked")),
        ("X-HTTP-Method-Override", json!("POST")),
    ] {
        let mut event = ordinary.clone();
        event["params"]["response"]["requestHeaders"][name] = value;
        assert!(
            !direct_cdp_read_response(&event),
            "refined HTTP request header {name} contradicts passive GET"
        );
    }
    for invalid in [json!(null), json!([]), json!("untyped")] {
        let mut event = ordinary.clone();
        event["params"]["response"]["requestHeaders"] = invalid;
        assert!(!direct_cdp_read_response(&event));
    }
}

#[test]
fn raw_initial_response_headers_must_agree_with_json_200() {
    let original = json!({
        "status":200u16,
        "mimeType":"application/json",
        "headers":{"Content-Type":"application/json"},
        // jig-ignore-next-line: synthetic HTTP/1 response CRLF fixture.
        "headersText":"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
    });
    assert!(uncached_provider_response(&original));
    for invalid in [
        "HTTP/1.1 304 Not Modified\r\nContent-Type: application/json\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
        // jig-ignore-next-line: synthetic HTTP/1 duplicate header fixture.
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Type: text/html\r\n\r\n",
    ] {
        let mut response = original.clone();
        response["headersText"] = json!(invalid);
        assert!(!uncached_provider_response(&response));
    }
    let mut malformed = original;
    malformed["headersText"] = json!(null);
    assert!(!uncached_provider_response(&malformed));
}

#[test]
fn response_headers_cannot_contradict_json_200_metadata() {
    let original = json!({"url":"https://mail.proton.me/api/mail/v4/messages",
        "status":200u16,
        "headers":{"Content-Type":"application/json; charset=utf-8"}});
    assert!(uncached_provider_response(&original));
    let mut no_headers = original.clone();
    no_headers
        .as_object_mut()
        .expect("response object")
        .remove("headers");
    assert!(uncached_provider_response(&no_headers));

    for changed_headers in [
        json!({"Content-Type":"text/html"}),
        json!({"Content-Type":"application/json; charset=utf-8, text/html"}),
        json!({"Content-Type":"application/json; charset=iso-8859-1"}),
        // jig-ignore-next-line: synthetic duplicate charset fixture.
        json!({"Content-Type":"application/json; charset=utf-8; charset=iso-8859-1"}),
        json!({"Content-Type":"application/json", "content-type":"text/html"}),
        json!({"Content-Type":12i32}),
        json!({"Content-Type":"application/json", ":status":"304"}),
        json!({"Content-Type":"application/json", ":method":"GET"}),
        json!({"Content-Type":"application/json", "X-Invalid\nName":"a"}),
    ] {
        let mut changed = original.clone();
        changed["headers"] = changed_headers;
        assert!(!uncached_provider_response(&changed));
    }
    for invalid in [json!(null), json!([]), json!("untyped")] {
        let mut changed = original.clone();
        changed["headers"] = invalid;
        assert!(!uncached_provider_response(&changed));
    }
    let mut http2 = original;
    http2["headers"][":status"] = json!("200");
    assert!(uncached_provider_response(&http2));
}

#[test]
fn raw_http_request_headers_must_confirm_bodyless_mail_get() {
    let url = "https://mail.proton.me/api/mail/v4/messages?Page=0";
    let path = "/api/mail/v4/messages?Page=0";
    let safe_raw =
        // jig-ignore-next-line: synthetic HTTP/1 header fixture.
        format!("GET {path} HTTP/1.1\r\nHost: mail.proton.me\r\nCookie: opaque=private\r\n\r\n");
    let original = json!({"url":url, "requestHeaders":{
        "Host":"mail.proton.me", "Accept":"application/json"},
        "requestHeadersText":safe_raw});
    assert!(uncached_provider_response(&original));
    let mut absent = original.clone();
    absent
        .as_object_mut()
        .expect("response object")
        .remove("requestHeadersText");
    assert!(uncached_provider_response(&absent));

    for raw in [
        format!("POST {path} HTTP/1.1\r\nHost: mail.proton.me\r\n\r\n"),
        // jig-ignore-next-line: synthetic HTTP/1 header fixture.
        String::from("GET /api/core/v4/users HTTP/1.1\r\nHost: mail.proton.me\r\n\r\n"),
        format!("GET {path} HTTP/1.1\r\nHost: foreign.invalid\r\n\r\n"),
        // jig-ignore-next-line: synthetic HTTP/1 header fixture.
        format!("GET {path} HTTP/1.1\r\nHost: mail.proton.me\r\nContent-Length: 5\r\n\r\n"),
        // jig-ignore-next-line: synthetic HTTP/1 header fixture.
        format!("GET {path} HTTP/1.1\r\nHost: mail.proton.me\r\nPurpose: prefetch\r\n\r\n"),
        // jig-ignore-next-line: synthetic HTTP/1 header fixture.
        format!("GET {path} HTTP/1.1\r\nHost: mail.proton.me\r\nSec-Fetch-Mode: navigate\r\n\r\n"),
        // jig-ignore-next-line: synthetic HTTP/1 header fixture.
        format!("GET {path} HTTP/1.1\r\nHost: mail.proton.me\r\nHost: mail.proton.me\r\n\r\n"),
        format!(
            concat!(
                "GET {path} HTTP/1.1\r\n",
                "Host: mail.proton.me\r\n",
                "X-Forwarded-Prefix: /rewritten\r\n\r\n"
            ),
            path = path
        ),
        format!("GET {path} HTTP/1.1\nHost: mail.proton.me\n\n"),
    ] {
        let mut swapped = original.clone();
        swapped["requestHeadersText"] = json!(raw);
        assert!(
            !uncached_provider_response(&swapped),
            "contradictory raw request"
        );
    }
    for invalid in [json!(null), json!(12i32), json!([]), json!("")] {
        let mut swapped = original.clone();
        swapped["requestHeadersText"] = invalid;
        assert!(!uncached_provider_response(&swapped));
    }
}

#[test]
fn non_utf8_browser_charset_cannot_prove_mail_json() {
    let ordinary = json!({"params":{"type":"Fetch", "response":{
        "url":"https://mail.proton.me/api/mail/v4/messages",
        "status":200u16, "mimeType":"application/json",
        "headers":{"Content-Type":"application/json; charset=utf-8"}}}});
    assert!(direct_cdp_read_response(&ordinary));
    for charset in ["utf-8", "UTF-8", ""] {
        let mut valid = ordinary.clone();
        valid["params"]["response"]["charset"] = json!(charset);
        assert!(direct_cdp_read_response(&valid), "valid JSON {charset}");
    }
    for invalid in [
        json!("iso-8859-1"),
        json!("utf-16"),
        json!("x-user-defined"),
        json!(null),
        json!(12i32),
    ] {
        let mut response = ordinary.clone();
        response["params"]["response"]["charset"] = invalid;
        assert!(!direct_cdp_read_response(&response), "non-UTF-8 decoding");
    }
}

#[test]
fn non_http_response_protocol_cannot_prove_direct_mail_json() {
    let ordinary = json!({"params":{"type":"Fetch", "response":{
        "url":"https://mail.proton.me/api/mail/v4/messages",
        "status":200u16, "mimeType":"application/json"}}});
    assert!(direct_cdp_read_response(&ordinary));
    for protocol in ["http/1.0", "http/1.1", "h2", "h3"] {
        let mut valid = ordinary.clone();
        valid["params"]["response"]["protocol"] = json!(protocol);
        assert!(direct_cdp_read_response(&valid), "HTTP {protocol} is valid");
    }
    for invalid in [
        json!("data"),
        json!("file"),
        json!("ws"),
        json!("h2c"),
        json!("http"),
        json!(""),
        json!(null),
        json!(1i32),
    ] {
        let mut event = ordinary.clone();
        event["params"]["response"]["protocol"] = invalid;
        assert!(!direct_cdp_read_response(&event), "not direct HTTP");
    }
}

#[test]
fn response_event_resource_type_must_be_a_known_active_read() {
    let ordinary = json!({
        "params": {"type": "Fetch", "response": {
            "status": 200u16, "mimeType": "application/json",
            "fromDiskCache": false, "fromServiceWorker": false
        }}
    });
    assert!(direct_cdp_read_response(&ordinary));
    for invalid in [
        json!("Prefetch"),
        json!("Preflight"),
        json!("FedCM"),
        json!("prefetch"),
        json!("futureResource"),
        json!(null),
    ] {
        let mut event = ordinary.clone();
        event["params"]["type"] = invalid;
        assert!(!direct_cdp_read_response(&event));
    }
    let mut legacy = ordinary.clone();
    legacy["params"]
        .as_object_mut()
        .expect("synthetic params object")
        .remove("type");
    assert!(direct_cdp_read_response(&legacy));
    for invalid in [json!(true), json!({}), json!("network")] {
        let mut event = ordinary.clone();
        event["params"]["response"]["fromDiskCache"] = invalid;
        assert!(!direct_cdp_read_response(&event));
    }
}

#[test]
fn unreviewed_response_speculation_markers_cannot_prove_direct_http() {
    let ordinary = json!({
        "params": {"type": "Fetch", "response": {
            "status": 200u16, "mimeType": "application/json",
            "fromDiskCache": false, "fromServiceWorker": false}}
    });
    assert!(direct_cdp_read_response(&ordinary));
    for (name, value) in [
        ("wasPreloaded", json!(false)),
        ("servedFromPreload", json!(false)),
        ("wasPrerendered", json!(false)),
        ("speculativeResponse", json!(null)),
        ("isPreflight", json!(false)),
    ] {
        for level in ["event", "response"] {
            let mut event = ordinary.clone();
            if level == "event" {
                event["params"][name] = value.clone();
            } else {
                event["params"]["response"][name] = value.clone();
            }
            assert!(
                !direct_cdp_read_response(&event),
                "unreviewed {level} speculative marker {name} cannot prove HTTP"
            );
        }
    }
}

#[test]
fn response_event_level_source_markers_cannot_override_direct_http() {
    let ordinary = json!({
        "params": {"requestId": "synthetic", "type": "Fetch",
            "response": {"url": "https://mail.proton.me/api/mail/v4/messages",
                "status": 200u16, "mimeType": "application/json",
                "fromDiskCache": false, "fromServiceWorker": false}}
    });
    assert!(direct_cdp_read_response(&ordinary));
    for (name, value) in [
        ("fromDiskCache", json!(true)),
        ("fromServiceWorker", json!(true)),
        ("fromPrefetchCache", json!(true)),
        ("serviceWorkerResponseSource", json!("network")),
        ("responseSource", json!("cache")),
        ("isCached", json!(false)),
        ("SecurityState", json!("insecure")),
    ] {
        let mut event = ordinary.clone();
        event["params"][name] = value;
        assert!(
            !direct_cdp_read_response(&event),
            "event-level response provenance {name} cannot prove direct HTTP"
        );
    }
}

#[test]
fn passive_mail_reads_require_ajax_resource_type_when_reported() {
    let request = json!({
        "params": {"request": {"method": "GET"}, "type": "Fetch",
            "initiator": {"type": "script"}}
    });
    let response = json!({
        "params": {"type": "XHR", "response": {
            "status": 200u16, "mimeType": "application/json"}}
    });
    assert!(non_speculative_cdp_get(&request));
    assert!(direct_cdp_read_response(&response));
    for type_name in [
        "Document",
        "Stylesheet",
        "Image",
        "Media",
        "Font",
        "Script",
        "TextTrack",
        "EventSource",
        "WebSocket",
        "Manifest",
        "Ping",
        "SignedExchange",
        "CSPViolationReport",
        "Other",
    ] {
        let mut request_with_non_mail_type = request.clone();
        request_with_non_mail_type["params"]["type"] = json!(type_name);
        assert!(
            !non_speculative_cdp_get(&request_with_non_mail_type),
            "non-API resource {type_name} cannot prove a Mail JSON GET"
        );
        let mut response_with_non_mail_type = response.clone();
        response_with_non_mail_type["params"]["type"] = json!(type_name);
        assert!(
            !direct_cdp_read_response(&response_with_non_mail_type),
            "non-API response {type_name} cannot prove Mail JSON data"
        );
    }
}

#[test]
fn unknown_request_payload_markers_cannot_prove_bodyless_get() {
    let clean = json!({
        "method": "GET", "url": "https://mail.proton.me/api/mail/v4/messages",
        "hasPostData": false, "headers": {"Accept": "application/json"}
    });
    assert!(bodyless_cdp_get(&clean));
    for (marker, value) in [
        ("HasPostData", json!(false)),
        ("postDataLength", json!(1u64)),
        ("requestBody", json!("synthetic")),
        ("payloadBytes", json!(0u64)),
        ("uploadData", json!(null)),
        ("body", json!([])),
        ("contentLength", json!(3u64)),
        ("postD\u{0430}ta", json!("synthetic")),
        ("\u{5b89}\u{5168}", json!(null)),
    ] {
        let mut request = clean.clone();
        request[marker] = value;
        assert!(
            !bodyless_cdp_get(&request),
            "noncanonical payload hint {marker} must disqualify GET"
        );
    }
}

#[test]
fn malformed_cdp_headers_cannot_prove_bodyless_get() {
    let clean = json!({
        "method": "GET", "url": "https://mail.proton.me/api/mail/v4/messages",
        "headers": {"Accept": "application/json", "Content-Length": "0"}
    });
    assert!(bodyless_cdp_get(&clean));
    for invalid in [
        json!(null),
        json!(true),
        json!(0i32),
        json!([]),
        json!({"nested": "value"}),
        json!("application/json\r\nTransfer-Encoding: chunked"),
        json!("application/json\u{0}invalid"),
        json!("application/json\u{7f}invalid"),
    ] {
        let mut request = clean.clone();
        request["headers"]["Accept"] = invalid;
        assert!(
            !bodyless_cdp_get(&request),
            "untyped or control-bearing CDP header must reject a passive GET"
        );
    }
    for name in ["Content-Length\r\nTransfer-Encoding", "X-Test\nInjected"] {
        let mut request = clean.clone();
        request["headers"][name] = json!("0");
        assert!(
            !bodyless_cdp_get(&request),
            "invalid CDP header name must reject a passive GET"
        );
    }
    let mut duplicate = clean;
    duplicate["headers"]["content-length"] = json!("0");
    assert!(
        !bodyless_cdp_get(&duplicate),
        "case-aliased length fields cannot prove unambiguous GET framing"
    );
}

#[test]
fn method_override_headers_cannot_prove_read_only_get() {
    let ordinary = json!({
        "method": "GET", "hasPostData": false,
        "headers": {"Accept": "application/json"}
    });
    assert!(bodyless_cdp_get(&ordinary));
    for header in [
        "X-HTTP-Method-Override",
        "x-http-method-override",
        "X-Method-Override",
        "X-HTTP-Method",
        "X-Original-HTTP-Method",
        "X-Original-Method",
        "X-Rewrite-Method",
    ] {
        let mut request = ordinary.clone();
        request["headers"][header] = json!("POST");
        assert!(
            !bodyless_cdp_get(&request),
            "method override header {header} cannot prove a read-only GET"
        );
    }
    let mut even_get = ordinary;
    even_get["headers"]["X-HTTP-Method-Override"] = json!("GET");
    assert!(!bodyless_cdp_get(&even_get));
}

#[test]
fn request_headers_cannot_contradict_bodyless_get_provenance() {
    let clean = json!({
        "method": "GET", "url": "https://mail.proton.me/api/mail/v4/messages",
        "hasPostData": false,
        "headers": {"Content-Length": "0", "Accept": "application/json"}
    });
    assert!(bodyless_cdp_get(&clean));
    for (header, value) in [
        ("Content-Length", json!("1")),
        ("content-length", json!("123456")),
        ("CONTENT-LENGTH", json!(null)),
        ("Content-Length", json!(7u64)),
        ("content-length", json!("invalid")),
        ("Transfer-Encoding", json!("chunked")),
        ("transfer-encoding", json!("identity")),
    ] {
        let mut request = clean.clone();
        request["headers"][header] = value;
        assert!(
            !bodyless_cdp_get(&request),
            "header {header} must not contradict a body-free GET"
        );
    }
    let mut invalid = clean;
    invalid["headers"] = json!("not-an-object");
    assert!(!bodyless_cdp_get(&invalid));
}
