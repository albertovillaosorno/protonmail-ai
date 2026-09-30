// SPDX-License-Identifier: GPL-3.0-only

//! Integration checks for the declared capability safety classes.

use protonmail_ai_core::{SafetyClass, planned_capabilities};

#[test]
fn permanent_delete_is_never_classified_as_reversible() {
    let delete = planned_capabilities()
        .iter()
        .find(|capability| capability.name == "delete_messages")
        .expect("delete capability belongs to the declared inventory");

    assert_eq!(delete.safety, SafetyClass::Destructive);
}
