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
    source_flags.iter().all(|field| {
        let value = response.get(*field);
        matches!(value, None | Some(Value::Bool(false)))
    }) && source_hints
        .iter()
        .all(|field| response.get(*field).is_none())
}
