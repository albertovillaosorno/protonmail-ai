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
    "const ids=['toolbar:sort-new-to-old','toolbar:sort-old-to-new',",
    "'toolbar:sort-desc','toolbar:sort-asc'];",
    "const count=ids.filter((id)=>document.querySelector(",
    "'[data-testid=\"'+id+'\"]')).length;",
    "if(count===4){return {alreadyOpen:true,clicked:false};}",
    "if(count!==0){return null;}",
    "const q='[data-testid=\"filter-dropdown:show-filters\"]';",
    "const nodes=[...document.querySelectorAll(q)];",
    "if(nodes.length!==1||",
    "!(nodes[0] instanceof HTMLButtonElement)){return null;}",
    "nodes[0].click();",
    "return {alreadyOpen:false,clicked:true};",
    "})()"
);

const SORT_EVIDENCE_EXPRESSION: &str = concat!(
    "(() => {",
    "const ids=['toolbar:sort-new-to-old','toolbar:sort-old-to-new',",
    "'toolbar:sort-desc','toolbar:sort-asc'];",
    "const nodes=ids.map((id)=>[...document.querySelectorAll(",
    "'[data-testid=\"'+id+'\"]')]);",
    "const counts=nodes.map((group)=>group.length);",
    "if(counts.every((count)=>count===0)){return {ready:false};}",
    "if(counts.some((count)=>count!==1)){return {ready:true,valid:false};}",
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
    "const q='[data-testid=\"filter-dropdown:show-filters\"]';",
    "const nodes=[...document.querySelectorAll(q)];",
    "if(nodes.length!==1||",
    "!(nodes[0] instanceof HTMLButtonElement)){return false;}",
    "nodes[0].click();return true;",
    "})()"
);

const SORT_MENU_CLOSED_EXPRESSION: &str = concat!(
    "(() => {",
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
            return Ok(None);
        }
        if !bool_field(value, "valid")? {
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
