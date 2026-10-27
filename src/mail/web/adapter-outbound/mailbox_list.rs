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
//   - Content-free mailbox-list loading, row-ID, empty, and paging evidence.
// - Must-Not:
//   - Retain subjects, senders, accessible names, message bodies, or DOM nodes.
// - Allows:
//   - Classify observable list state and opaque loaded-row identifiers.
// - Split-When:
//   - Message/thread projection requires content-bearing read models.
// - Merge-When:
//   - One read adapter owns list settling and page projection together.
// - Summary:
//   - Reduces a bounded DOM observation to conservative mailbox-list evidence.
// - Description:
//   - Distinguishes loading, loaded rows, explicit empty, and unproven no-rows.
// - Usage:
//   - Managed browser reads this only after same-session Mail-shell validation.
// - Defaults:
//   - Contradictory, duplicate, malformed, or oversized evidence fails closed.
//

//! Content-free mailbox-list evidence for the Proton Mail web adapter.

use std::collections::HashSet;
use std::fmt;

use crate::opaque_read_id::safe_read_id;
use serde_json::Value;

const MAILBOX_LIST_EXPRESSION: &str = concat!(
    "(() => {",
    // Read content only in the proved Mail origin within this JavaScript task.
    "if(location.origin!=='https://mail.proton.me'){return null;}",
    // Do not project mailbox content into a page showing a login challenge.
    "if(document.querySelector('input[type=\"password\"],",
    "input[autocomplete=\"one-time-code\"]')){return null;}",
    "if(document.querySelector('[role=\"dialog\"],",
    "[role=\"alertdialog\"]')){return null;}",
    // jig-ignore-next-line: indivisible JavaScript query fragment.
    "const loadingNodes=[...document.querySelectorAll('[data-testid=\"message-list-loading\"]')];",
    // jig-ignore-next-line: indivisible JavaScript query fragment.
    "const loadedNodes=[...document.querySelectorAll('[data-testid=\"message-list-loaded\"]')];",
    "if(loadedNodes.length>1||loadingNodes.length>1){return null;}",
    "const loading=loadingNodes[0],loaded=loadedNodes[0];",
    // A simultaneous transition cannot prove that the list is settled.
    "if(loading&&loaded){return null;}",
    "const root=loaded||loading;",
    "if(!root){return {loading:false,loaded:false,rowIds:[],skeletonCount:0,",
    // jig-ignore-next-line: indivisible JavaScript query fragment.
    "emptyMarker:false,nextPresent:false,nextDisabled:null,currentTestId:null};}",
    // CSS opacity does not inherit: rendered descendant boxes may still be
    // visually hidden by a transparent ancestor. Bound ancestor inspection.
    "const visibleTree=(node)=>{let current=node;",
    "for(let depth=0;depth<64;depth++){",
    "if(!current){return true;}",
    "const style=getComputedStyle(current);",
    "if(!style||style.visibility!=='visible'||",
    "!(Number(style.opacity)>0)){return false;}",
    "current=current.parentElement;}",
    "return false;};",
    "if(!visibleTree(root)){return null;}",
    "const base='[data-shortcut-target=\"item-container\"][data-element-id]';",
    "const real=[...root.querySelectorAll(base+'[role=\"region\"]')];",
    "if(real.length>200||real.some((row)=>",
    "row.getClientRects().length===0||",
    "getComputedStyle(row).visibility!=='visible'||",
    "getComputedStyle(row).opacity==='0'||",
    "!visibleTree(row)||",
    "row.closest('[aria-hidden=\"true\"],[inert]'))){return null;}",
    // jig-ignore-next-line: indivisible JavaScript query fragment.
    "const skeleton=[...root.querySelectorAll(base+':not([role=\"region\"])')];",
    // jig-ignore-next-line: indivisible JavaScript query fragment.
    "const emptyNodes=[...root.querySelectorAll('[data-testid=\"empty-view-placeholder--empty-title\"]')];",
    "if(emptyNodes.length>1){return null;}",
    "const emptyNode=emptyNodes[0];",
    "if(emptyNode&&(emptyNode.getClientRects().length===0||",
    "getComputedStyle(emptyNode).visibility!=='visible'||",
    "getComputedStyle(emptyNode).opacity==='0'||",
    "!visibleTree(emptyNode)||",
    "emptyNode.closest('[aria-hidden=\"true\"],[inert]'))){return null;}",
    "const empty=!!emptyNode;",
    // jig-ignore-next-line: indivisible JavaScript query fragment.
    "const nextNodes=[...document.querySelectorAll('[data-testid=\"pagination-row:go-to-next-page\"]')];",
    // jig-ignore-next-line: indivisible JavaScript query fragment.
    "const currentNodes=[...document.querySelectorAll('[data-testid^=\"pagination-row:go-to-page-\"][aria-current=\"true\"]')];",
    "if(nextNodes.length>1||currentNodes.length>1){return null;}",
    "const next=nextNodes[0],current=currentNodes[0];",
    "if(current&&(current.getClientRects().length===0||",
    "getComputedStyle(current).visibility!=='visible'||",
    "getComputedStyle(current).opacity==='0'||",
    "!visibleTree(current)||",
    "current.closest('[aria-hidden=\"true\"],[inert]'))){return null;}",
    "const inheritedDisabled=next?",
    "!!next.closest('[aria-disabled=\"true\"]'):false;",
    "if(next&&(!(next instanceof HTMLButtonElement)||",
    "next.getClientRects().length===0||",
    "getComputedStyle(next).visibility!=='visible'||",
    "(!next.disabled&&next.getAttribute('aria-disabled')!=='true'&&",
    "!inheritedDisabled&&",
    "getComputedStyle(next).pointerEvents==='none')||",
    "getComputedStyle(next).opacity==='0'||",
    "!visibleTree(next)||",
    "next.closest('[aria-hidden=\"true\"],[inert]'))){return null;}",
    // Preflight projected IDs and page selectors before CDP serialization.
    "const ids=real.map((row)=>row.getAttribute('data-element-id'));",
    "if(ids.some((id)=>typeof id!=='string'||id.length===0||",
    "id.length>512||new TextEncoder().encode(id).length>512)){",
    "return null;}",
    "const page=current?current.getAttribute('data-testid'):null;",
    "if(page!==null&&(typeof page!=='string'||",
    "!/^pagination-row:go-to-page-[1-9]\\d{0,9}$/.test(page))){",
    "return null;}",
    "return {loading:!!loading,loaded:!!loaded,rowIds:ids,",
    "skeletonCount:skeleton.length,emptyMarker:empty,nextPresent:!!next,",
    "nextDisabled:next?(!!next.disabled||inheritedDisabled||",
    "next.getAttribute('aria-disabled')==='true'):null,",
    "currentTestId:page};",
    "})()"
);
const MAX_VISIBLE_ROWS: usize = 200;
const MAX_ROW_ID_BYTES: usize = 512;
const PAGE_TEST_ID_PREFIX: &str = "pagination-row:go-to-page-";

/// Conservative state of the currently rendered mailbox-list surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxListState {
    /// Provider explicitly marks the list as loading.
    Loading,
    /// Provider marks the list loaded and exposes an explicit empty marker.
    SettledExplicitEmpty,
    /// Provider marks the list loaded and exposes one or more real rows.
    SettledRows,
    // jig-ignore-next-line: concise boundary documentation.
    /// Provider marks the list loaded but exposes neither rows nor empty marker.
    SettledNoRowsUnproven,
}

/// Observable state of the next-page control.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NextPageControl {
    /// No next-page control is rendered.
    Absent,
    /// A next-page control is rendered and disabled.
    Disabled,
    /// A next-page control is rendered and enabled.
    Enabled,
}

/// Content-free current-list snapshot using provider-opaque row identifiers.
#[derive(Clone, Eq, PartialEq)]
pub struct MailboxListEvidence {
    current_page: Option<u32>,
    next_page: NextPageControl,
    row_ids: Vec<String>,
    state: MailboxListState,
}

impl fmt::Debug for MailboxListEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailboxListEvidence")
            .field("current_page", &self.current_page)
            .field("next_page", &self.next_page)
            .field("row_count", &self.row_ids.len())
            .field("state", &self.state)
            .finish()
    }
}

impl MailboxListEvidence {
    pub(crate) const fn expression() -> &'static str {
        MAILBOX_LIST_EXPRESSION
    }

    /// Returns the conservative rendered-list state.
    #[must_use]
    pub const fn state(&self) -> MailboxListState {
        self.state
    }

    /// Returns provider-opaque IDs of real loaded rows in rendered order.
    #[must_use]
    pub fn row_ids(&self) -> &[String] {
        &self.row_ids
    }

    /// Returns the visible current page when pagination renders one explicitly.
    #[must_use]
    pub const fn current_page(&self) -> Option<u32> {
        self.current_page
    }

    /// Returns observable next-page control state.
    #[must_use]
    pub const fn next_page(&self) -> NextPageControl {
        self.next_page
    }

    // jig-ignore-next-line: concise boundary documentation.
    /// Returns whether the UI provides explicit evidence that this page is empty.
    #[must_use]
    pub const fn explicitly_empty(&self) -> bool {
        matches!(self.state, MailboxListState::SettledExplicitEmpty)
    }

    pub(crate) fn from_runtime_value(value: &Value) -> Result<Self, ()> {
        // Only accept the exact projection schema owned by the audited DOM
        // expression, including when the list is still loading.
        if value.as_object().is_none_or(|fields| fields.len() != 8) {
            return Err(());
        }
        let loading = bool_field(value, "loading")?;
        let loaded = bool_field(value, "loaded")?;
        if loading == loaded {
            return Err(());
        }
        let empty_marker = bool_field(value, "emptyMarker")?;
        // Loading evidence can carry transitional rows and pagination state.
        // It may discard their values, but never their shape validation.
        let row_ids = row_ids(value)?;
        let skeleton_count = usize_field(value, "skeletonCount")?;
        let next_present = bool_field(value, "nextPresent")?;
        let next_disabled = optional_bool_field(value, "nextDisabled")?;
        let current_test_id = optional_str_field(value, "currentTestId")?;
        if loading {
            if empty_marker {
                return Err(());
            }
            return Ok(Self {
                current_page: None,
                next_page: NextPageControl::Absent,
                row_ids: Vec::new(),
                state: MailboxListState::Loading,
            });
        }

        if skeleton_count != 0 || (empty_marker && !row_ids.is_empty()) {
            return Err(());
        }

        let current_page = current_test_id.map(parse_page).transpose()?;
        let next_page = match (next_present, next_disabled) {
            (false, None) => NextPageControl::Absent,
            (true, Some(true)) => NextPageControl::Disabled,
            (true, Some(false)) => NextPageControl::Enabled,
            _ => return Err(()),
        };
        // jig-ignore-next-line: canonical rustfmt guard line.
        if next_page == NextPageControl::Enabled && (empty_marker || current_page == Some(u32::MAX))
        {
            return Err(());
        }
        let state = if !row_ids.is_empty() {
            MailboxListState::SettledRows
        } else if empty_marker {
            MailboxListState::SettledExplicitEmpty
        } else {
            MailboxListState::SettledNoRowsUnproven
        };
        Ok(Self {
            current_page,
            next_page,
            row_ids,
            state,
        })
    }
}

fn bool_field(value: &Value, key: &str) -> Result<bool, ()> {
    value.get(key).and_then(Value::as_bool).ok_or(())
}

fn optional_bool_field(value: &Value, key: &str) -> Result<Option<bool>, ()> {
    let Some(field) = value.get(key) else {
        return Err(());
    };
    if field.is_null() {
        return Ok(None);
    }
    field.as_bool().map(Some).ok_or(())
}

// jig-ignore-next-line: canonical rustfmt line.
fn optional_str_field<'value>(value: &'value Value, key: &str) -> Result<Option<&'value str>, ()> {
    let Some(field) = value.get(key) else {
        return Err(());
    };
    if field.is_null() {
        return Ok(None);
    }
    field.as_str().map(Some).ok_or(())
}

fn usize_field(value: &Value, key: &str) -> Result<usize, ()> {
    let raw = value.get(key).and_then(Value::as_u64).ok_or(())?;
    usize::try_from(raw).map_err(|_error| ())
}

fn row_ids(value: &Value) -> Result<Vec<String>, ()> {
    let rows = value.get("rowIds").and_then(Value::as_array).ok_or(())?;
    if rows.len() > MAX_VISIBLE_ROWS {
        return Err(());
    }
    let mut unique = HashSet::with_capacity(rows.len());
    let mut ids = Vec::with_capacity(rows.len());
    for row in rows {
        let id = row.as_str().ok_or(())?;
        if !safe_read_id(id, MAX_ROW_ID_BYTES) || !unique.insert(id) {
            return Err(());
        }
        ids.push(String::from(id));
    }
    Ok(ids)
}

fn parse_page(test_id: &str) -> Result<u32, ()> {
    let page = test_id.strip_prefix(PAGE_TEST_ID_PREFIX).ok_or(())?;
    if page.is_empty()
        || page.len() > 10
        || (page.len() > 1 && page.starts_with('0'))
        || !page.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(());
    }
    let parsed = page.parse::<u32>().map_err(|_error| ())?;
    if parsed == 0 {
        return Err(());
    }
    Ok(parsed)
}
