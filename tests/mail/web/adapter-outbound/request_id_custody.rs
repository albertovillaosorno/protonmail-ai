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
//   - Offline regression proof of tracked request-id cleanup and ordering.
// - Must-Not:
//   - Contact a provider, reveal real session IDs, or access browser state.
// - Allows:
//   - Exercise map retention, rejection, and exact lookup after cleanup.
// - Split-When:
//   - Additional request-key storage schemes require distinct cases.
// - Merge-When:
//   - One capture-state suite covers all request ownership boundaries.
// - Summary:
//   - Preserves exact CDP request membership during key custody cleanup.
// - Description:
//   - Synthetic IDs prove retained keys and failed removes remain stable.
// - Usage:
//   - Included under private request_id_custody module tests.
// - Defaults:
//   - Tests contain only synthetic local data.
//

//! Synthetic request-key custody regression coverage.

use std::collections::{BTreeMap, BTreeSet};

use super::{discard_request_id, retain_request_ids, scrub_all_request_ids};

#[test]
fn retiring_and_discarding_requests_preserve_exact_remaining_membership() {
    let mut requests = BTreeMap::from([
        (String::from("synthetic-a"), 1u8),
        (String::from("synthetic-b"), 2u8),
        (String::from("synthetic-c"), 3u8),
    ]);
    retain_request_ids(&mut requests, |state| *state != 2);
    assert_eq!(requests.len(), 2);
    assert_eq!(requests.get("synthetic-a"), Some(&1));
    assert_eq!(requests.get("synthetic-b"), None);
    assert_eq!(requests.get("synthetic-c"), Some(&3));
    discard_request_id(&mut requests, "synthetic-c");
    discard_request_id(&mut requests, "unknown");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests.get("synthetic-a"), Some(&1));
    let mut completed = BTreeSet::from([String::from("synthetic-b")]);
    scrub_all_request_ids(&mut requests, &mut completed);
    assert!(requests.is_empty());
    assert!(completed.is_empty());
}
