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
use zeroize::Zeroize as _;

const MAILBOX_LIST_EXPRESSION: &str = concat!(
    "(() => {",
    // Read content only in the proved Mail origin within this JavaScript task.
    "if(location.origin!=='https://mail.proton.me'){return null;}",
    // Do not project mailbox content into a page showing a login challenge.
    "if(document.querySelector('input[type=\"password\"],",
    "input[autocomplete=\"one-time-code\"]')){return null;}",
    "if(document.querySelector('[role~=\"dialog\" i],",
    "[role~=\"alertdialog\" i],dialog[open],",
    "[aria-modal=\"true\" i]')){return null;}",
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
    "style.contentVisibility==='hidden'||",
    // Rectangles remain positive for fully clipped or filtered-out trees.
    "(style.clipPath&&style.clipPath!=='none')||",
    "(style.filter&&style.filter!=='none')||",
    // CSS masks can hide all painted pixels without altering box geometry.
    "(style.maskImage&&style.maskImage!=='none')||",
    "(style.webkitMaskImage&&style.webkitMaskImage!=='none')||",
    "!(Number(style.opacity)>0)){return false;}",
    "current=current.parentElement;}",
    "return false;};",
    // Disabled pagination remains observable, while an enabled control
    // must have an actionable ancestry; child pointer styles can override
    // a blocked parent yet do not make the programmatic click legitimate.
    "const pointerTree=(node)=>{let current=node;",
    "for(let depth=0;depth<64;depth++){",
    "if(!current){return true;}",
    "const style=getComputedStyle(current);",
    "if(!style||style.pointerEvents==='none'){return false;}",
    "current=current.parentElement;}",
    "return false;};",
    // Nonempty client-rect arrays can contain only collapsed boxes.
    // Require real button area before calling the Next control visible.
    "const hasArea=(node)=>[...node.getClientRects()].some(",
    "(rect)=>rect.width>0&&rect.height>0);",
    // Enabled Next must agree with the later click's viewport hit test.
    "const hitTest=(node)=>[...node.getClientRects()].some((rect)=>{",
    "if(!(rect.width>0&&rect.height>0)){return false;}",
    "const x=rect.left+rect.width/2,y=rect.top+rect.height/2;",
    "if(!Number.isFinite(x)||!Number.isFinite(y)){return false;}",
    "const hit=document.elementFromPoint(x,y);",
    "return !!hit&&(hit===node||node.contains(hit));});",
    "if(!visibleTree(root)){return null;}",
    // Loading is a non-authoritative state. Do not inspect or serialize
    // transient row IDs, skeleton details, or pagination while it is active.
    "if(loading){return {loading:true,loaded:false,rowIds:[],",
    "skeletonCount:0,emptyMarker:false,nextPresent:false,",
    "nextDisabled:null,currentTestId:null};}",
    "const base='[data-shortcut-target=\"item-container\"][data-element-id]';",
    "const real=[...root.querySelectorAll(base+'[role=\"region\"]')];",
    "if(real.length>200||real.some((row)=>",
    "row.getClientRects().length===0||",
    "!hasArea(row)||!hitTest(row)||",
    "getComputedStyle(row).visibility!=='visible'||",
    "getComputedStyle(row).opacity==='0'||",
    "!visibleTree(row)||",
    "row.closest('[aria-hidden=\"true\" i],[inert]'))){return null;}",
    // jig-ignore-next-line: indivisible JavaScript query fragment.
    "const skeleton=[...root.querySelectorAll(base+':not([role=\"region\"])')];",
    // jig-ignore-next-line: indivisible JavaScript query fragment.
    "const emptyNodes=[...root.querySelectorAll('[data-testid=\"empty-view-placeholder--empty-title\"]')];",
    "if(emptyNodes.length>1){return null;}",
    "const emptyNode=emptyNodes[0];",
    "if(emptyNode&&(emptyNode.getClientRects().length===0||",
    "!hasArea(emptyNode)||!hitTest(emptyNode)||",
    "getComputedStyle(emptyNode).visibility!=='visible'||",
    "getComputedStyle(emptyNode).opacity==='0'||",
    "!visibleTree(emptyNode)||",
    "emptyNode.closest('[aria-hidden=\"true\" i],[inert]'))){return null;}",
    "const empty=!!emptyNode;",
    // jig-ignore-next-line: indivisible JavaScript query fragment.
    "const nextNodes=[...document.querySelectorAll('[data-testid=\"pagination-row:go-to-next-page\"]')];",
    // jig-ignore-next-line: indivisible JavaScript query fragment.
    "const currentNodes=[...document.querySelectorAll('[data-testid^=\"pagination-row:go-to-page-\"][aria-current=\"true\" i]')];",
    "if(nextNodes.length>1||currentNodes.length>1){return null;}",
    "const next=nextNodes[0],current=currentNodes[0];",
    "if(current&&(current.getClientRects().length===0||",
    "!hasArea(current)||!hitTest(current)||",
    "getComputedStyle(current).visibility!=='visible'||",
    "getComputedStyle(current).opacity==='0'||",
    "!visibleTree(current)||",
    "current.closest('[aria-hidden=\"true\" i],[inert]'))){return null;}",
    "const inheritedDisabled=next?",
    "!!next.closest('[aria-disabled=\"true\" i]'):false;",
    // An eligible next-page control may never be a form submit action.
    "if(next&&(!(next instanceof HTMLButtonElement)||",
    "next.type!=='button'||next.form!==null||",
    "next.getClientRects().length===0||",
    "!hasArea(next)||",
    "getComputedStyle(next).visibility!=='visible'||",
    "(!next.matches(':disabled')&&!next.disabled&&",
    "next.getAttribute('aria-disabled')?.toLowerCase()!=='true'&&",
    "!inheritedDisabled&&",
    "(!pointerTree(next)||!hitTest(next)))||",
    "getComputedStyle(next).opacity==='0'||",
    "!visibleTree(next)||",
    "next.closest('[aria-hidden=\"true\" i],[inert]'))){return null;}",
    // Unicode noncharacters have no interchange identity. Reject every plane
    // before Chrome serializes the ID or projects any message text.
    "const unsafeScalar=(text)=>[...text].some((c)=>{",
    "const point=c.codePointAt(0);",
    "return (point>=0xFDD0&&point<=0xFDEF)||",
    "(point&0xFFFE)===0xFFFE;});",
    // Reject ambiguous opaque IDs before CDP, matching the Rust read guard.
    "const invalidId=/[\\s\\/?#%;\\\\\\u0000-\\u001f\\u007f-\\u009f",
    "\\ud800-\\udfff",
    "\\u00ad\\u034f\\u061c\\u115f\\u1160\\u180b-\\u180f",
    "\\u17b4-\\u17b5\\u{1bca0}-\\u{1bca3}",
    "\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u206f",
    "\\u0600-\\u0605\\u06dd\\u070f\\u0890-\\u0891\\u08e2",
    "\\ufff9-\\ufffb\\u{110bd}\\u{110cd}",
    "\\u{13430}-\\u{1343f}\\u{1d173}-\\u{1d17a}",
    "\\u2800\\u3164\\ufe00-\\ufe0f\\ufeff\\uffa0\\ufffd",
    "\\u{e0001}\\u{e0020}-\\u{e007f}\\u{e0100}-\\u{e01ef}]/u;",
    // Preflight projected IDs and page selectors before CDP serialization.
    "const ids=real.map((row)=>row.getAttribute('data-element-id'));",
    "if(ids.some((id)=>typeof id!=='string'||id.length===0||",
    "id==='.'||id==='..'||invalidId.test(id)||unsafeScalar(id)||",
    "id.length>512||new TextEncoder().encode(id).length>512)||",
    "new Set(ids).size!==ids.length){",
    "return null;}",
    "const page=current?current.getAttribute('data-testid'):null;",
    "if(page!==null&&(typeof page!=='string'||",
    "!/^pagination-row:go-to-page-[1-9]\\d{0,9}$/.test(page))){",
    "return null;}",
    "return {loading:!!loading,loaded:!!loaded,rowIds:ids,",
    "skeletonCount:skeleton.length,emptyMarker:empty,nextPresent:!!next,",
    "nextDisabled:next?(next.matches(':disabled')||",
    "!!next.disabled||inheritedDisabled||",
    "next.getAttribute('aria-disabled')?.toLowerCase()==='true'):null,",
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

#[expect(
    clippy::missing_trait_methods,
    reason = "Drop is the explicit scrub-on-drop contract"
)]
impl Drop for MailboxListEvidence {
    fn drop(&mut self) {
        for id in &mut self.row_ids {
            id.zeroize();
        }
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
        // Loading evidence must remain the exact content-free projection.
        // Transitional IDs and pagination are never serialized from Chromium.
        let row_ids = row_ids(value)?;
        let skeleton_count = usize_field(value, "skeletonCount")?;
        let next_present = bool_field(value, "nextPresent")?;
        let next_disabled = optional_bool_field(value, "nextDisabled")?;
        let current_test_id = optional_str_field(value, "currentTestId")?;
        if loading {
            if empty_marker
                || !row_ids.is_empty()
                || skeleton_count != 0
                || next_present
                || next_disabled.is_some()
                || current_test_id.is_some()
            {
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
            // Allocate only into the accepted evidence's scrub-on-drop owner.
            row_ids: row_ids.into_iter().map(String::from).collect(),
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

fn row_ids(value: &Value) -> Result<Vec<&str>, ()> {
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
        // Keep identifiers borrowed from the guarded CDP response until
        // the remaining list and pagination metadata passes validation.
        ids.push(id);
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
