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
//   - Bounded content-bearing projection of the currently visible Mail rows.
// - Must-Not:
//   - Read message bodies, hidden store state, cookies, or infer message mode.
// - Allows:
//   - Return opaque row ID, subject, displayed addresses, and unread state.
// - Split-When:
//   - Opening a message or projecting full headers requires a separate model.
// - Merge-When:
//   - One provider read model can preserve these snapshot invariants directly.
// - Summary:
//   - Projects a stable visible mailbox page after conservative settle checks.
// - Description:
//   - Requires unchanged list evidence before/after bounded row extraction.
// - Usage:
//   - Managed browser uses this only after same-session Mail-shell validation.
// - Defaults:
//   - Loading, unproven empty, malformed, reordered, or changing rows fail
//     closed.
//

//! Stable content-bearing snapshot of the currently visible Proton Mail page.

use std::collections::HashSet;
use std::fmt;

use serde_json::Value;

use crate::driver::BrowserDriverError;
// jig-ignore-next-line: canonical rustfmt line.
use crate::mailbox_list::{MailboxListEvidence, MailboxListState, NextPageControl};

const MAX_VISIBLE_ROWS: usize = 200;
const MAX_ROW_ID_BYTES: usize = 512;
const MAX_SUBJECT_BYTES: usize = 16_384;
const MAX_ADDRESSES_BYTES: usize = 16_384;
const MAILBOX_PAGE_EXPRESSION: &str = concat!(
    "(() => {",
    // jig-ignore-next-line: indivisible JavaScript query fragment.
    "const root=document.querySelector('[data-testid=\"message-list-loaded\"]');",
    "if(!root){return null;}",
    "const base='[data-shortcut-target=\"item-container\"]',",
    // jig-ignore-next-line: indivisible JavaScript query fragment.
    "rows=[...root.querySelectorAll(base+'[data-element-id][role=\"region\"]')];",
    "return rows.map((row)=>{",
    "const id=row.getAttribute('data-element-id');",
    "const labelled=row.getAttribute('aria-labelledby');",
    "const heading=labelled?document.getElementById(labelled):null;",
    // jig-ignore-next-line: indivisible JavaScript query fragment.
    "const sender=row.querySelector('[data-testid=\"message-column:sender-address\"][title]');",
    "return {id:id,subject:heading?(heading.getAttribute('title')??''):null,",
    "addresses:sender?sender.getAttribute('title'):null,",
    "unread:row.classList.contains('unread')};",
    "});",
    "})()"
);

/// Content-bearing summary of one currently rendered Mail row.
#[derive(Clone, Eq, PartialEq)]
pub struct VisibleMailboxRow {
    id: String,
    subject: String,
    displayed_addresses: String,
    unread: bool,
}

impl fmt::Debug for VisibleMailboxRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VisibleMailboxRow")
            .field("id", &"<redacted>")
            .field("subject", &"<redacted>")
            .field("displayed_addresses", &"<redacted>")
            .field("unread", &self.unread)
            .finish()
    }
}

impl VisibleMailboxRow {
    /// Returns the provider-opaque row identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the visible message/conversation subject.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the addresses shown by Mail for this row's correspondents.
    ///
    /// Mail may show senders or recipients depending on the current mailbox.
    #[must_use]
    pub fn displayed_addresses(&self) -> &str {
        &self.displayed_addresses
    }

    /// Returns whether Mail renders this row as unread.
    #[must_use]
    pub const fn unread(&self) -> bool {
        self.unread
    }
}

/// Stable snapshot of the currently visible Mail list page.
#[derive(Clone, Eq, PartialEq)]
pub struct MailboxPageSnapshot {
    current_page: Option<u32>,
    next_page: NextPageControl,
    rows: Vec<VisibleMailboxRow>,
}

impl fmt::Debug for MailboxPageSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailboxPageSnapshot")
            .field("current_page", &self.current_page)
            .field("next_page", &self.next_page)
            .field("row_count", &self.rows.len())
            .field("explicitly_empty", &self.rows.is_empty())
            .finish()
    }
}

impl MailboxPageSnapshot {
    /// Returns the rendered page number when explicitly exposed by Mail.
    #[must_use]
    pub const fn current_page(&self) -> Option<u32> {
        self.current_page
    }

    /// Returns the observed next-page control state.
    #[must_use]
    pub const fn next_page(&self) -> NextPageControl {
        self.next_page
    }

    /// Returns visible rows in provider-rendered order.
    #[must_use]
    pub fn rows(&self) -> &[VisibleMailboxRow] {
        &self.rows
    }

    /// Returns true only when Mail rendered an explicit empty marker.
    #[must_use]
    pub const fn explicitly_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub(crate) const fn expression() -> &'static str {
        MAILBOX_PAGE_EXPRESSION
    }

    pub(crate) fn from_observations(
        before: &MailboxListEvidence,
        rows_value: Option<&Value>,
        after: &MailboxListEvidence,
    ) -> Result<Self, BrowserDriverError> {
        if before != after {
            return Err(BrowserDriverError::MailboxPageChanged);
        }
        match before.state() {
            // jig-ignore-next-line: canonical rustfmt line.
            MailboxListState::Loading | MailboxListState::SettledNoRowsUnproven => {
                Err(BrowserDriverError::MailboxPageNotSettled)
            }
            MailboxListState::SettledExplicitEmpty => {
                if rows_value.is_some() {
                    return Err(BrowserDriverError::MailboxPageIncompatible);
                }
                Ok(Self {
                    current_page: before.current_page(),
                    next_page: before.next_page(),
                    rows: Vec::new(),
                })
            }
            MailboxListState::SettledRows => {
                // jig-ignore-next-line: canonical rustfmt line.
                let value = rows_value.ok_or(BrowserDriverError::MailboxPageIncompatible)?;
                let rows = parse_rows(value)?;
                if !ids_match(before.row_ids(), &rows) {
                    return Err(BrowserDriverError::MailboxPageChanged);
                }
                Ok(Self {
                    current_page: before.current_page(),
                    next_page: before.next_page(),
                    rows,
                })
            }
        }
    }
}

// jig-ignore-next-line: canonical rustfmt line.
fn parse_rows(value: &Value) -> Result<Vec<VisibleMailboxRow>, BrowserDriverError> {
    let rows = value
        .as_array()
        .ok_or(BrowserDriverError::MailboxPageIncompatible)?;
    if rows.is_empty() || rows.len() > MAX_VISIBLE_ROWS {
        return Err(BrowserDriverError::MailboxPageIncompatible);
    }
    let mut seen = HashSet::with_capacity(rows.len());
    let mut parsed = Vec::with_capacity(rows.len());
    for row in rows {
        let id = bounded_string(row, "id", MAX_ROW_ID_BYTES, false)?;
        if !seen.insert(id.clone()) {
            return Err(BrowserDriverError::MailboxPageIncompatible);
        }
        let subject = bounded_string(row, "subject", MAX_SUBJECT_BYTES, true)?;
        // jig-ignore-next-line: canonical rustfmt line.
        let displayed_addresses = bounded_string(row, "addresses", MAX_ADDRESSES_BYTES, true)?;
        let unread = row
            .get("unread")
            .and_then(Value::as_bool)
            .ok_or(BrowserDriverError::MailboxPageIncompatible)?;
        parsed.push(VisibleMailboxRow {
            id,
            subject,
            displayed_addresses,
            unread,
        });
    }
    Ok(parsed)
}

fn bounded_string(
    row: &Value,
    key: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<String, BrowserDriverError> {
    let value = row
        .get(key)
        .and_then(Value::as_str)
        .ok_or(BrowserDriverError::MailboxPageIncompatible)?;
    if value.len() > max_bytes || (!allow_empty && value.is_empty()) {
        return Err(BrowserDriverError::MailboxPageIncompatible);
    }
    Ok(String::from(value))
}

fn ids_match(expected: &[String], rows: &[VisibleMailboxRow]) -> bool {
    expected.len() == rows.len()
        && expected
            .iter()
            .zip(rows)
            .all(|(expected_id, row)| expected_id == row.id())
}
