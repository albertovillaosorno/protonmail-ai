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
//   - Translation-free Proton Mail shell evidence from accessibility roles.
// - Must-Not:
//   - Retain accessible names, DOM text, selectors, or mailbox content.
// - Allows:
//   - Classify structural landmarks and blocking dialogs from role queries.
// - Split-When:
//   - Composer or mailbox-item semantics need independently versioned evidence.
// - Merge-When:
//   - Browser transport can own semantic classification without mixing policy.
// - Summary:
//   - Reduces role-filtered accessibility output to non-content shell booleans.
// - Description:
//   - Recognizes navigation/search landmarks and visible dialog blockers only.
// - Usage:
//   - Managed browser inspection calls this after revalidating Proton Mail.
// - Defaults:
//   - Missing, ignored, or malformed shell evidence fails closed.
//

//! Translation-independent Proton Mail shell evidence.

use serde_json::Value;

/// Structural Mail-shell evidence that contains no accessible names or text.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MailShellEvidence {
    modal_blocker_visible: bool,
    navigation_visible: bool,
    search_visible: bool,
}

impl MailShellEvidence {
    /// Returns whether a visible navigation landmark was observed.
    #[must_use]
    pub const fn navigation_visible(self) -> bool {
        self.navigation_visible
    }

    /// Returns whether a visible search landmark was observed.
    #[must_use]
    pub const fn search_visible(self) -> bool {
        self.search_visible
    }

    /// Returns whether a visible dialog-like blocker was observed.
    #[must_use]
    pub const fn modal_blocker_visible(self) -> bool {
        self.modal_blocker_visible
    }

    /// Returns whether the minimal translation-free Mail shell is ready.
    #[must_use]
    pub const fn ready(self) -> bool {
        let landmarks = self.navigation_visible && self.search_visible;
        landmarks && !self.modal_blocker_visible
    }

    pub(crate) fn from_role_queries(
        navigation: &Value,
        search: &Value,
        dialog: &Value,
        alertdialog: &Value,
    ) -> Result<Self, ()> {
        let dialog_visible = visible_match(dialog)?;
        let alertdialog_visible = visible_match(alertdialog)?;
        let modal_blocker_visible = dialog_visible || alertdialog_visible;
        Ok(Self {
            navigation_visible: visible_match(navigation)?,
            search_visible: visible_match(search)?,
            modal_blocker_visible,
        })
    }
}

fn visible_match(result: &Value) -> Result<bool, ()> {
    let nodes = result.get("nodes").and_then(Value::as_array).ok_or(())?;
    for node in nodes {
        let ignored = node.get("ignored").and_then(Value::as_bool).ok_or(())?;
        if !ignored {
            return Ok(true);
        }
    }
    Ok(false)
}
