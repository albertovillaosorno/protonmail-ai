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
//   - Shared passive CDP request and response-source gates for read-only GETs.
// - Must-Not:
//   - Retain HTTP headers, request URLs, bodies, or browser session secrets.
// - Allows:
//   - Reject body-bearing, speculative, cached, or worker-served read evidence.
// - Split-When:
//   - Response provenance becomes provider-specific or authenticated.
// - Merge-When:
//   - One read adapter owns all CDP lifecycle and provenance validation.
// - Summary:
//   - Requires body-free, non-speculative GETs and direct HTTP responses.
// - Description:
//   - Inspects CDP request and response metadata without allocation or logging.
// - Usage:
//   - Call on exact requestWillBeSent and responseReceived read notifications.
// - Defaults:
//   - Omitted optional hints pass; explicit contradictory hints fail closed.
//

//! Shared cached-response provenance gate for passive provider evidence.

use serde_json::Value;

// A CDP Request claiming GET does not prove body-free read semantics when
// transport metadata also reports payload bytes. `Network.enable` may omit
// postData text, so the boolean and entry-array flags need checking too.
// Absence and an explicit false boolean are normal browser GET metadata.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private sibling read observers share one request-body predicate"
)]
pub(super) fn bodyless_cdp_get(request: &Value) -> bool {
    request.as_object().is_some_and(|fields| {
        // Request protocol names are ASCII. Future payload metadata, alias
        // spellings, or Unicode lookalikes cannot silently establish the
        // absence of a GET body, regardless of their reported value.
        let unreviewed_body_marker = fields.keys().any(|field| {
            if !field.is_ascii() {
                return true;
            }
            let body_markers = ["postdata", "body", "payload"];
            let length_markers = ["upload", "contentlength"];
            field != "hasPostData"
                && body_markers
                    .iter()
                    .chain(length_markers.iter())
                    .any(|marker| {
                        field.as_bytes().windows(marker.len()).any(|part| {
                            let needle = marker.as_bytes();
                            part.eq_ignore_ascii_case(needle)
                        })
                    })
        });
        let body_flag = fields.get("hasPostData");
        let bodyless = matches!(body_flag, None | Some(Value::Bool(false)));
        !unreviewed_body_marker
            && bodyless
            && !fields.contains_key("postData")
            && !fields.contains_key("postDataEntries")
    })
}

// The audited Mail API endpoints return JSON to application XHR/Fetch reads.
// A navigation, image, script, or other resource may independently GET the
// same URL, but must not establish the active mailbox's API read evidence.
fn read_api_cdp_resource_type(kind: &str) -> bool {
    matches!(kind, "XHR" | "Fetch")
}

// A speculative preload or prefetch can fetch an endpoint and return 200
// without the active Mail view requesting those records. Chromium reports
// these separately in Request, requestWillBeSent resource type and initiator.
// A foreign document/frame can likewise request a Mail API URL without the
// active Mail document owning it. Optional CDP hints must not contradict
// ordinary first-party activity; omission remains legacy-compatible.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private sibling read observers share speculative GET provenance"
)]
pub(super) fn non_speculative_cdp_get(event: &Value) -> bool {
    let Some(params) = event.get("params").and_then(Value::as_object) else {
        return false;
    };
    let Some(request) = params.get("request").and_then(Value::as_object) else {
        return false;
    };
    let normal_link = matches!(
        request.get("isLinkPreload"),
        None | Some(Value::Bool(false))
    );
    // CDP resource and initiator types are closed enums, not arbitrary text.
    // Browser navigations and resource fetches cannot prove Mail API reads.
    // In particular, unknown, speculative, or FedCM types fail closed.
    let normal_resource = match params.get("type") {
        None => true,
        Some(Value::String(kind)) => read_api_cdp_resource_type(kind),
        Some(_) => false,
    };
    let normal_initiator = match params.get("initiator") {
        None => true,
        Some(Value::Object(initiator)) => matches!(
            initiator.get("type").and_then(Value::as_str),
            Some("parser" | "script" | "SignedExchange" | "other")
        ),
        Some(_) => false,
    };
    // documentURL is the requesting document, not the API URL. Binding an
    // explicit hint to the active Mail origin prevents foreign iframes and
    // unrelated documents from laundering their GET as mailbox activity.
    // CDP URL strings are browser-serialized; reject raw Unicode/whitespace,
    // alternate ports or ambiguous host prefixes without retaining the URL.
    let normal_document = match params.get("documentURL") {
        None => true,
        Some(Value::String(url)) => {
            let bounded = url.len() <= 16 * 1024;
            let serialized = url.bytes().all(|byte| byte.is_ascii_graphic());
            let same_origin = url
                .strip_prefix("https://mail.proton.me")
                .is_some_and(|suffix| {
                    suffix.is_empty()
                        || suffix.starts_with('/')
                        || suffix.starts_with('?')
                        || suffix.starts_with('#')
                });
            bounded && serialized && same_origin
        }
        Some(_) => false,
    };
    normal_link && normal_resource && normal_initiator && normal_document
}

// Browser source flags may be absent on some CDP versions, but present values
// must be explicitly false. Other optional cache/SW hints cannot prove a
// direct provider response even if the booleans are absent or contradictory.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private sibling read observers share one provenance predicate"
)]
pub(super) fn uncached_provider_response(response: &Value) -> bool {
    response.as_object().is_some_and(uncached_source_fields)
}

// Interpret source/security markers consistently in the response metadata
// and in the enclosing CDP event. Otherwise contradictory explicit origin
// flags at the event level could silently authorize a passive read.
fn uncached_source_fields(fields: &serde_json::Map<String, Value>) -> bool {
    let source_flags = [
        "fromDiskCache",
        "fromServiceWorker",
        "fromPrefetchCache",
        "fromEarlyHints",
    ];
    let source_hints = [
        "serviceWorkerResponseSource",
        "cacheStorageCacheName",
        "serviceWorkerRouterInfo",
    ];
    // Future CDP releases may introduce cache/SW or security-state markers.
    // Check markers anywhere in the name: an extension such as `isCached`
    // or `responseSource` is ambiguous even though it does not start with a
    // known prefix. Avoid allocating or retaining untrusted field content.
    let unknown_source_marker = fields.keys().any(|field| {
        // CDP response properties are ASCII protocol names. A Unicode
        // lookalike can disguise a source/security marker from ASCII checks.
        if !field.is_ascii() {
            return true;
        }
        let contains_marker = [
            "cache",
            "prefetch",
            "serviceworker",
            "source",
            "securitystate",
        ]
        .iter()
        .any(|marker| {
            field
                .as_bytes()
                .windows(marker.len())
                .any(|window| window.eq_ignore_ascii_case(marker.as_bytes()))
        });
        let source_prefix = ["from", "isFrom", "servedFrom", "wasServedFrom"]
            .iter()
            .any(|prefix| {
                field
                    .get(..prefix.len())
                    .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
            });
        (contains_marker || source_prefix)
            && !source_flags.contains(&field.as_str())
            && !source_hints.contains(&field.as_str())
            && field != "securityState"
    });
    // An HTTPS endpoint cannot establish a trusted direct response if the
    // browser explicitly reports insecure, neutral, or unknown transport.
    // Keep omission compatible with older/synthetic CDP response shapes;
    // a reported value must be exactly the documented secure state.
    let security_valid = fields
        .get("securityState")
        .is_none_or(|state| state.as_str() == Some("secure"));
    !unknown_source_marker
        && security_valid
        && source_flags.iter().all(|field| {
            let value = fields.get(*field);
            matches!(value, None | Some(Value::Bool(false)))
        })
        && source_hints
            .iter()
            .all(|field| fields.get(*field).is_none())
}

// The request's resource hint alone cannot prove that the response belongs
// to an active read: responseReceived has its own ResourceType. Reject new,
// speculative or authentication types before any response-body consumption.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private sibling read observers share response type provenance"
)]
pub(super) fn direct_cdp_read_response(event: &Value) -> bool {
    let Some(params) = event.get("params").and_then(Value::as_object) else {
        return false;
    };
    let normal_type = match params.get("type") {
        None => true,
        Some(Value::String(kind)) => read_api_cdp_resource_type(kind),
        Some(_) => false,
    };
    normal_type
        && uncached_source_fields(params)
        && params
            .get("response")
            .is_some_and(uncached_provider_response)
}

// CDP can report a nominal 200 in responseReceived before the actual HTTP
// status arrives via responseReceivedExtraInfo. When hasExtraInfo is true,
// that separate status is required before a provider GET can be consumed.
// Extra-info notifications may precede responseReceived or loadingFinished.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private sibling observers share one status-evidence type"
)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct ExtraStatusEvidence {
    declared: Option<bool>,
    seen_200: bool,
}

impl ExtraStatusEvidence {
    pub(super) fn note_response(&mut self, params: &Value) -> bool {
        match params.get("hasExtraInfo") {
            None => true,
            Some(Value::Bool(expects)) => {
                self.declared = Some(*expects);
                *expects || !self.seen_200
            }
            Some(_) => false,
        }
    }

    pub(super) fn note_200(&mut self) -> bool {
        if self.seen_200 || self.declared == Some(false) {
            return false;
        }
        self.seen_200 = true;
        true
    }

    pub(super) fn ready(self) -> bool {
        self.declared != Some(true) || self.seen_200
    }
}

// A conditional HTTP-cache revalidation can report 200 in responseReceived
// while the network stack reports 304 here. Accept only exact 200 if the
// optional extra-info event is provided for a tracked provider GET.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private sibling observers share the extra-info status predicate"
)]
pub(super) fn direct_extra_status_is_200(event: &Value) -> bool {
    event
        .get("params")
        .and_then(|params| params.get("statusCode"))
        .and_then(Value::as_u64)
        == Some(200)
}

#[cfg(test)]
#[path = "../../../../tests/mail/web/adapter-outbound/response_provenance.rs"]
mod tests;
