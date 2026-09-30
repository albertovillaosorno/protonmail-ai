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

use mail_capability_domain::{ActionGrant, Capability, MailProviderPort};
use mail_capability_domain::{SafetyClass, SecretRef};
use mail_capability_domain::{planned_capabilities, select_adapter};

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

struct SyntheticAdapter {
    id: &'static str,
    supported: &'static [&'static str],
}

impl MailProviderPort for SyntheticAdapter {
    fn adapter_id(&self) -> &str {
        self.id
    }

    fn supports(&self, capability: Capability) -> bool {
        self.supported.contains(&capability.name())
    }
}

#[test]
fn adapter_selection_never_combines_partial_coverage() {
    let capabilities = planned_capabilities();
    let search = capabilities[0];
    let message = capabilities[1];
    let search_only = SyntheticAdapter {
        id: "search-only",
        supported: &["search_messages"],
    };
    let message_only = SyntheticAdapter {
        id: "message-only",
        supported: &["get_message"],
    };
    let candidates = [search_only, message_only];

    assert!(select_adapter(&[search, message], &candidates).is_none());
}

#[test]
fn adapter_selection_uses_ordered_complete_candidate() {
    let capabilities = planned_capabilities();
    let required = [capabilities[0], capabilities[1]];
    let partial = SyntheticAdapter {
        id: "partial",
        supported: &["search_messages"],
    };
    let complete = SyntheticAdapter {
        id: "complete",
        supported: &["search_messages", "get_message"],
    };
    let candidates = [partial, complete];

    let selected = select_adapter(&required, &candidates);
    let selected = selected.expect("a complete adapter should be selected");
    assert_eq!(selected.adapter_id(), "complete");
}

#[test]
fn side_effect_classes_require_distinct_authority() {
    assert!(SafetyClass::ReadOnly.authorizes(ActionGrant::Observe));
    assert!(SafetyClass::Reversible.authorizes(ActionGrant::ReversibleChange));
    let external = SafetyClass::ExternalSideEffect;
    assert!(external.authorizes(ActionGrant::ExternalSideEffect));
    assert!(!SafetyClass::Destructive.authorizes(ActionGrant::Observe));
    assert!(
        SafetyClass::Destructive.required_grant().is_none(),
        "permanent deletion must remain disabled by policy"
    );

    assert!(!SafetyClass::ReadOnly.authorizes(ActionGrant::ReversibleChange));
    assert!(!SafetyClass::Reversible.authorizes(ActionGrant::Observe));
    assert!(!external.authorizes(ActionGrant::ReversibleChange));
}

#[test]
fn secret_values_are_structurally_redacted_in_diagnostics() {
    let synthetic_value = "synthetic-secret-never-real-account-data";
    let synthetic_secret = SecretRef::new(synthetic_value);

    assert_eq!(format!("{synthetic_secret}"), "[REDACTED]");
    assert_eq!(format!("{synthetic_secret:?}"), "[REDACTED]");
    assert_eq!(synthetic_secret.expose(), synthetic_value);
}
