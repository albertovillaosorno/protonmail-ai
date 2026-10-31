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
use std::collections::HashSet;

const MAX_AX_ROLE_MATCH_NODES: usize = 256;

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

    pub(crate) fn from_role_queries<'role_nodes>(
        navigation: &'role_nodes Value,
        search: &'role_nodes Value,
        dialog: &'role_nodes Value,
        alertdialog: &'role_nodes Value,
    ) -> Result<Self, ()> {
        // CDP AXNodeId identifies one accessibility node for the session.
        // A node cannot simultaneously establish distinct role-filtered
        // landmarks; aliases across responses are contradictory shell proof.
        let mut ids = HashSet::new();
        let dialog_visible = visible_match(dialog, "dialog", &mut ids)?;
        let alert = visible_match(alertdialog, "alertdialog", &mut ids)?;
        let nav = visible_match(navigation, "navigation", &mut ids)?;
        let search = visible_match(search, "search", &mut ids)?;
        Ok(Self {
            modal_blocker_visible: dialog_visible || alert,
            navigation_visible: nav,
            search_visible: search,
        })
    }
}

fn visible_match<'role_nodes>(
    result: &'role_nodes Value,
    expected_role: &str,
    ids: &mut HashSet<&'role_nodes str>,
) -> Result<bool, ()> {
    let nodes = result.get("nodes").and_then(Value::as_array).ok_or(())?;
    if nodes.len() > MAX_AX_ROLE_MATCH_NODES {
        return Err(());
    }
    let mut any_visible = false;
    for node in nodes {
        let ignored = node.get("ignored").and_then(Value::as_bool).ok_or(())?;
        // CDP AXNode requires a unique string nodeId and a typed role. A
        // sparse or aliased node cannot prove a visible browser landmark.
        let id = node.get("nodeId").and_then(Value::as_str).ok_or(())?;
        if id.is_empty()
            || id.len() > 512
            || !id.bytes().all(|byte| byte.is_ascii_graphic())
            || !ids.insert(id)
        {
            return Err(());
        }
        let role = node.get("role").ok_or(())?;
        let kind = role.get("type").and_then(Value::as_str);
        let value = role.get("value").and_then(Value::as_str);
        if kind != Some("role") || value != Some(expected_role) {
            return Err(());
        }
        // Even after a visible landmark is found, malformed later nodes
        // invalidate the query instead of being silently skipped.
        any_visible |= !ignored;
    }
    Ok(any_visible)
}
