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
//   - Scrub-on-removal custody of browser request correlation identifiers.
// - Must-Not:
//   - Inspect request bodies, URLs, headers, or provider session state.
// - Allows:
//   - Preserve request ordering and membership while erasing retired keys.
// - Split-When:
//   - Request storage requires another correlation or concurrency strategy.
// - Merge-When:
//   - All Network captures share a single request lifecycle owner.
// - Summary:
//   - Erases tracked and completed CDP request keys before deallocation.
// - Description:
//   - Rebuilds bounded maps on retire; drains all keys during collector drop.
// - Usage:
//   - Passive read-only Network collectors call this for lifecycle cleanup.
// - Defaults:
//   - Existing and returned correlation IDs retain their matching semantics.
//

//! Private destruction custody for bounded CDP request correlation IDs.

use std::collections::{BTreeMap, BTreeSet};
use std::mem::take;

use zeroize::Zeroize as _;

#[expect(clippy::redundant_pub_crate, reason = "shared private module helper")]
// jig-ignore-next-line: rustfmt canonical generic request map signature.
pub(super) fn retain_request_ids<T, F>(requests: &mut BTreeMap<String, T>, keep: F)
where
    F: Fn(&T) -> bool,
{
    let mut retained = BTreeMap::new();
    for (mut id, tracked) in take(requests) {
        if keep(&tracked) {
            retained.insert(id, tracked);
        } else {
            id.zeroize();
        }
    }
    *requests = retained;
}

#[expect(clippy::redundant_pub_crate, reason = "shared private module helper")]
// jig-ignore-next-line: rustfmt canonical request removal signature.
pub(super) fn discard_request_id<T>(requests: &mut BTreeMap<String, T>, id: &str) {
    if let Some((mut id, _tracked)) = requests.remove_entry(id) {
        id.zeroize();
    }
}

#[expect(clippy::redundant_pub_crate, reason = "shared private module helper")]
pub(super) fn scrub_all_request_ids<T>(
    requests: &mut BTreeMap<String, T>,
    completed_ids: &mut BTreeSet<String>,
) {
    for (mut id, _tracked) in take(requests) {
        id.zeroize();
    }
    for mut id in take(completed_ids) {
        id.zeroize();
    }
}

#[cfg(test)]
#[path = "../../../../tests/mail/web/adapter-outbound/request_id_custody.rs"]
mod tests;
