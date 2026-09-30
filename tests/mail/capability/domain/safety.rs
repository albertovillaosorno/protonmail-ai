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
//   - Integration evidence for capability safety invariants.
// - Must-Not:
//   - Access a live account, network, credential, message, or provider adapter.
// - Allows:
//   - Assert externally visible classifications using synthetic declarations.
// - Split-When:
//   - A distinct capability family needs independent acceptance evidence.
// - Merge-When:
//   - Safety invariants become fully owned by another accepted test boundary.
// - Summary:
//   - Verifies capability safety classifications.
// - Description:
//   - Prevents destructive operations from being presented as reversible.
// - Usage:
//   - Run through the workspace test gate.
// - Defaults:
//   - Synthetic, deterministic, local-only execution.
//

//! Integration checks for declared mail capability safety classes.

use mail_capability_domain::{SafetyClass, planned_capabilities};

#[test]
fn permanent_delete_is_never_classified_as_reversible() {
    let delete_safety = planned_capabilities()
        .iter()
        .find(|capability| capability.name() == "delete_messages")
        .map(|capability| capability.safety());

    assert_eq!(
        delete_safety,
        Some(SafetyClass::Destructive),
        "permanent deletion must retain destructive classification"
    );
}
