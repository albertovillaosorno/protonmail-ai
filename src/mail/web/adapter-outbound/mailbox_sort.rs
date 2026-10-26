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
//   - Locale-independent observation of Proton Mail's visible sort selection.
// - Must-Not:
//   - Change sort/filter state, read localized labels, or inspect private store
//     state.
// - Allows:
//   - Open the filter/sort menu, read aria-pressed test-ID state, then close
//     it.
// - Split-When:
//   - Public list ordering gains a provider-independent snapshot
//     implementation.
// - Merge-When:
//   - Read-workflow negotiation owns the same observable sort proof directly.
// - Summary:
//   - Proves which visible Mail sort option is active without changing it.
// - Description:
//   - Uses stable test IDs and aria-pressed state, never translated text.
// - Usage:
//   - List-message preflight requires newest-first evidence before proceeding.
// - Defaults:
//   - Missing, partial, duplicated, or multiply-active sort controls fail
//     closed.
//

//! Observable Proton Mail sort state without mutating mailbox ordering.

use serde_json::Value;

const SORT_MENU_OPEN_EXPRESSION: &str = concat!(
    "(() => {",
    // Origin is rechecked atomically with the ensuing UI click.
    "if(location.origin!=='https://mail.proton.me'){return null;}",
    // Refuse common auth challenge fields immediately before a UI click.
    "if(document.querySelector('input[type=\"password\"],",
    "input[autocomplete=\"one-time-code\"]')){return null;}",
    "const ids=['toolbar:sort-new-to-old','toolbar:sort-old-to-new',",
    "'toolbar:sort-desc','toolbar:sort-asc'];",
    "const groups=ids.map((id)=>[...document.querySelectorAll(",
    "'[data-testid=\"'+id+'\"]')]);",
    "if(groups.every((group)=>group.length===1)){",
    "return {alreadyOpen:true,clicked:false};}",
    "if(!groups.every((group)=>group.length===0)){return null;}",
    "const q='[data-testid=\"filter-dropdown:show-filters\"]';",
    "const nodes=[...document.querySelectorAll(q)];",
    "if(nodes.length!==1||",
    "!(nodes[0] instanceof HTMLButtonElement)){return null;}",
    "if(nodes[0].getClientRects().length===0||",
    "getComputedStyle(nodes[0]).visibility!=='visible'||",
    "getComputedStyle(nodes[0]).pointerEvents==='none'||",
    "getComputedStyle(nodes[0]).opacity==='0'||",
    "nodes[0].closest('[aria-hidden=\"true\"]')){return null;}",
    "nodes[0].click();",
    "return {alreadyOpen:false,clicked:true};",
    "})()"
);

const SORT_EVIDENCE_EXPRESSION: &str = concat!(
    "(() => {",
    "if(location.origin!=='https://mail.proton.me'){return null;}",
    "if(document.querySelector('input[type=\"password\"],",
    "input[autocomplete=\"one-time-code\"]')){return null;}",
    "const ids=['toolbar:sort-new-to-old','toolbar:sort-old-to-new',",
    "'toolbar:sort-desc','toolbar:sort-asc'];",
    "const nodes=ids.map((id)=>[...document.querySelectorAll(",
    "'[data-testid=\"'+id+'\"]')]);",
    "const counts=nodes.map((group)=>group.length);",
    "if(counts.every((count)=>count===0)){return {ready:false};}",
    "if(counts.some((count)=>count!==1)){return {ready:true,valid:false};}",
    "const controls=nodes.map((group)=>group[0]);",
    "if(controls.some((node)=>",
    "node.getClientRects().length===0||",
    "getComputedStyle(node).visibility!=='visible'||",
    "node.closest('[aria-hidden=\"true\"]'))){return null;}",
    "const pressed=(node)=>{const value=node.getAttribute('aria-pressed');",
    "return value==='true'?true:value==='false'?false:null;};",
    "const values=nodes.map((group)=>pressed(group[0]));",
    "if(values.some((value)=>value===null)){return null;}",
    "return {ready:true,valid:true,newest:values[0],oldest:values[1],",
    "largest:values[2],smallest:values[3]};",
    "})()"
);

const SORT_MENU_CLOSE_EXPRESSION: &str = concat!(
    "(() => {",
    // Origin is rechecked atomically with the ensuing UI click.
    "if(location.origin!=='https://mail.proton.me'){return false;}",
    // Refuse common auth challenge fields immediately before a UI click.
    "if(document.querySelector('input[type=\"password\"],",
    "input[autocomplete=\"one-time-code\"]')){return false;}",
    "const ids=['toolbar:sort-new-to-old','toolbar:sort-old-to-new',",
    "'toolbar:sort-desc','toolbar:sort-asc'];",
    "const menuNodes=ids.map((id)=>[...document.querySelectorAll(",
    "'[data-testid=\"'+id+'\"]')]);",
    "if(!menuNodes.every((group)=>group.length===1)){return false;}",
    "if(menuNodes.some((group)=>group[0].getClientRects().length===0||",
    "getComputedStyle(group[0]).visibility!=='visible'||",
    "group[0].closest('[aria-hidden=\"true\"]'))){return false;}",
    "const q='[data-testid=\"filter-dropdown:show-filters\"]';",
    "const nodes=[...document.querySelectorAll(q)];",
    "if(nodes.length!==1||",
    "!(nodes[0] instanceof HTMLButtonElement)){return false;}",
    "if(nodes[0].getClientRects().length===0||",
    "getComputedStyle(nodes[0]).visibility!=='visible'||",
    "getComputedStyle(nodes[0]).pointerEvents==='none'||",
    "getComputedStyle(nodes[0]).opacity==='0'||",
    "nodes[0].closest('[aria-hidden=\"true\"]')){return false;}",
    "nodes[0].click();return true;",
    "})()"
);

const SORT_MENU_CLOSED_EXPRESSION: &str = concat!(
    "(() => {",
    "if(location.origin!=='https://mail.proton.me'){return null;}",
    "if(document.querySelector('input[type=\"password\"],",
    "input[autocomplete=\"one-time-code\"]')){return null;}",
    "const ids=['toolbar:sort-new-to-old','toolbar:sort-old-to-new',",
    "'toolbar:sort-desc','toolbar:sort-asc'];",
    "return ids.every((id)=>document.querySelector(",
    "'[data-testid=\"'+id+'\"]')===null);",
    "})()"
);

/// Visible provider sort order proven by non-localized UI state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxSortOrder {
    /// Size descending.
    LargestFirst,
    /// Time/newest semantic option selected by `WebClients`.
    NewestFirst,
    /// Time/oldest semantic option selected by `WebClients`.
    OldestFirst,
    /// Size ascending.
    SmallestFirst,
}

impl MailboxSortOrder {
    pub(crate) const fn open_expression() -> &'static str {
        SORT_MENU_OPEN_EXPRESSION
    }

    pub(crate) const fn close_expression() -> &'static str {
        SORT_MENU_CLOSE_EXPRESSION
    }

    pub(crate) const fn closed_expression() -> &'static str {
        SORT_MENU_CLOSED_EXPRESSION
    }

    /// Returns true only for the provider's semantic newest-first selection.
    #[must_use]
    pub const fn is_newest_first(self) -> bool {
        matches!(self, Self::NewestFirst)
    }

    pub(crate) const fn expression() -> &'static str {
        SORT_EVIDENCE_EXPRESSION
    }

    pub(crate) fn from_value(value: &Value) -> Result<Option<Self>, ()> {
        let ready = bool_field(value, "ready")?;
        if !ready {
            // A closed menu may expose only readiness, not a purported
            // selection. Contradictory flags cannot trigger a reopening click.
            if value.as_object().is_none_or(|fields| fields.len() != 1) {
                return Err(());
            }
            return Ok(None);
        }
        if !bool_field(value, "valid")? {
            return Err(());
        }
        // The audited projection emits exactly readiness, validity, and the
        // four mutually exclusive sort buttons. Refuse a changed response.
        if value.as_object().is_none_or(|fields| fields.len() != 6) {
            return Err(());
        }
        let states = [
            bool_field(value, "newest")?,
            bool_field(value, "oldest")?,
            bool_field(value, "largest")?,
            bool_field(value, "smallest")?,
        ];
        if states.iter().filter(|active| **active).count() != 1 {
            return Err(());
        }
        let order = match states {
            [true, false, false, false] => Self::NewestFirst,
            [false, true, false, false] => Self::OldestFirst,
            [false, false, true, false] => Self::LargestFirst,
            [false, false, false, true] => Self::SmallestFirst,
            _ => return Err(()),
        };
        Ok(Some(order))
    }
}

fn bool_field(value: &Value, key: &str) -> Result<bool, ()> {
    value.get(key).and_then(Value::as_bool).ok_or(())
}
