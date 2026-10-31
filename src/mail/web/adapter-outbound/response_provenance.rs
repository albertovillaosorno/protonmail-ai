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
//   - Shared passive CDP response-source gate for read-only provider GETs.
// - Must-Not:
//   - Retain HTTP headers, request URLs, bodies, or browser session secrets.
// - Allows:
//   - Reject cached, prefetched, or service-worker-produced response evidence.
// - Split-When:
//   - Response provenance becomes provider-specific or authenticated.
// - Merge-When:
//   - One read adapter owns all CDP lifecycle and provenance validation.
// - Summary:
//   - Requires no affirmative or ambiguous browser cache-source markers.
// - Description:
//   - Reads only optional CDP response metadata without allocation or logging.
// - Usage:
//   - Call while accepting exact browser-owned responseReceived notifications.
// - Defaults:
//   - Omitted optional markers pass; present contradictory markers fail closed.
//

//! Shared cached-response provenance gate for passive provider evidence.

use serde_json::Value;

// Browser source flags may be absent on some CDP versions, but present values
// must be explicitly false. Other optional cache/SW hints cannot prove a
// direct provider response even if the booleans are absent or contradictory.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private sibling read observers share one provenance predicate"
)]
pub(super) fn uncached_provider_response(response: &Value) -> bool {
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
    let Some(fields) = response.as_object() else {
        return false;
    };
    // Future CDP releases may introduce cache/SW or security-state markers.
    // Do not silently treat an unknown source-like key as direct HTTP, even
    // when its current value appears false or spells a known key differently.
    let unknown_source_marker = fields.keys().any(|field| {
        let marker = ["from", "serviceWorker", "cacheStorage", "securityState"]
            .iter()
            .any(|prefix| {
                field
                    .get(..prefix.len())
                    .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
            });
        marker
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
