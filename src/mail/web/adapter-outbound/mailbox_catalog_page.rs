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
//   - Immutable paging over one already captured mailbox or label catalog.
// - Must-Not:
//   - Read provider state, serialize cursors, or infer public wire schemas.
// - Allows:
//   - Bind offsets and page sizes to one opaque in-memory snapshot boundary.
// - Split-When:
//   - Snapshot storage outlives one managed browser generation.
// - Merge-When:
//   - Catalog projection and paging become one inseparable adapter boundary.
// - Summary:
//   - Pages complete catalog evidence without re-reading Proton between pages.
// - Description:
//   - Retains one kind-specific immutable item vector and opaque boundary tag.
// - Usage:
//   - Managed browser captures a catalog once, then slices this snapshot.
// - Defaults:
//   - Empty snapshots return one empty page and no continuation state.
//

//! Immutable in-memory pagination for captured mailbox and label catalogs.

use std::fmt;

use mail_capability_domain::contract_v1::{DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE};

// jig-ignore-next-line: canonical rustfmt line.
use crate::mailbox_catalog::{ObservedMailboxCatalog, ObservedMailboxCatalogItem};

const SNAPSHOT_BOUNDARY_CHARS: usize = 32;

/// Catalog collection selected by one paginated read chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxCatalogPageKind {
    /// Built-in and custom message folders.
    Mailboxes,
    /// Custom message labels.
    Labels,
}

impl MailboxCatalogPageKind {
    pub(crate) const fn token_name(self) -> &'static str {
        match self {
            Self::Mailboxes => "mailboxes",
            Self::Labels => "labels",
        }
    }

    pub(crate) fn from_token_name(value: &str) -> Option<Self> {
        match value {
            "mailboxes" => Some(Self::Mailboxes),
            "labels" => Some(Self::Labels),
            _ => None,
        }
    }
}

/// Exact adapter-owned continuation state before opaque cursor serialization.
#[expect(
    clippy::redundant_pub_crate,
    reason = "sibling codec and driver access while paging module stays private"
)]
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct MailboxCatalogCursorState {
    snapshot_boundary: String,
    kind: MailboxCatalogPageKind,
    page_size: u16,
    offset: usize,
}

impl MailboxCatalogCursorState {
    pub(super) fn new(
        snapshot_boundary: &str,
        kind: MailboxCatalogPageKind,
        page_size: u16,
        offset: usize,
    ) -> Result<Self, MailboxCatalogPageError> {
        validate_snapshot_boundary(snapshot_boundary)?;
        validate_page_size(Some(page_size))?;
        if offset == 0 {
            return Err(MailboxCatalogPageError::InvalidCursorState);
        }
        Ok(Self {
            snapshot_boundary: String::from(snapshot_boundary),
            kind,
            page_size,
            offset,
        })
    }

    pub(super) fn snapshot_boundary(&self) -> &str {
        &self.snapshot_boundary
    }

    pub(super) const fn kind(&self) -> MailboxCatalogPageKind {
        self.kind
    }

    pub(super) const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub(super) const fn offset(&self) -> usize {
        self.offset
    }
}

impl fmt::Debug for MailboxCatalogCursorState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailboxCatalogCursorState")
            .field("snapshot_boundary", &"<redacted>")
            .field("kind", &self.kind)
            .field("page_size", &self.page_size)
            .field("offset", &"<redacted>")
            .finish()
    }
}

/// One immutable kind-specific catalog snapshot retained for cursor resumption.
#[expect(
    clippy::redundant_pub_crate,
    reason = "sibling driver access while the paging module remains private"
)]
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct MailboxCatalogSnapshot {
    boundary: String,
    kind: MailboxCatalogPageKind,
    items: Vec<ObservedMailboxCatalogItem>,
}

impl MailboxCatalogSnapshot {
    pub(super) fn from_catalog(
        boundary: &str,
        kind: MailboxCatalogPageKind,
        catalog: &ObservedMailboxCatalog,
    ) -> Result<Self, MailboxCatalogPageError> {
        validate_snapshot_boundary(boundary)?;
        let items = match kind {
            MailboxCatalogPageKind::Mailboxes => catalog.mailboxes(),
            MailboxCatalogPageKind::Labels => catalog.labels(),
        };
        Ok(Self {
            boundary: String::from(boundary),
            kind,
            items: items.to_vec(),
        })
    }

    pub(super) fn first_page(
        &self,
        requested_page_size: Option<u16>,
    ) -> Result<MailboxCatalogSnapshotPage, MailboxCatalogPageError> {
        let page_size = validate_page_size(requested_page_size)?;
        self.page_from_offset(0, page_size)
    }

    pub(super) fn resume_page(
        &self,
        state: &MailboxCatalogCursorState,
    ) -> Result<MailboxCatalogSnapshotPage, MailboxCatalogPageError> {
        if state.snapshot_boundary != self.boundary {
            return Err(MailboxCatalogPageError::CursorExpired);
        }
        if state.kind != self.kind {
            return Err(MailboxCatalogPageError::InvalidCursorState);
        }
        self.page_from_offset(state.offset, state.page_size)
    }

    fn page_from_offset(
        &self,
        offset: usize,
        page_size: u16,
    ) -> Result<MailboxCatalogSnapshotPage, MailboxCatalogPageError> {
        // jig-ignore-next-line: canonical rustfmt line.
        if offset > self.items.len() || (offset == self.items.len() && offset != 0) {
            return Err(MailboxCatalogPageError::InvalidCursorState);
        }
        let page_size = usize::from(page_size);
        let end = offset
            .checked_add(page_size)
            .ok_or(MailboxCatalogPageError::InvalidCursorState)?
            .min(self.items.len());
        let items = self.items[offset..end].to_vec();
        let next_state = if end < self.items.len() {
            let normalized_page_size = u16::try_from(page_size)
                .map_err(|_error| MailboxCatalogPageError::InvalidPageSize)?;
            Some(MailboxCatalogCursorState::new(
                &self.boundary,
                self.kind,
                normalized_page_size,
                end,
            )?)
        } else {
            None
        };
        Ok(MailboxCatalogSnapshotPage { items, next_state })
    }
}

impl fmt::Debug for MailboxCatalogSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailboxCatalogSnapshot")
            .field("boundary", &"<redacted>")
            .field("kind", &self.kind)
            .field("item_count", &self.items.len())
            .finish()
    }
}

/// One unencoded page slice and its exact optional continuation state.
#[expect(
    clippy::redundant_pub_crate,
    reason = "sibling driver access while the paging module remains private"
)]
pub(crate) struct MailboxCatalogSnapshotPage {
    items: Vec<ObservedMailboxCatalogItem>,
    next_state: Option<MailboxCatalogCursorState>,
}

impl MailboxCatalogSnapshotPage {
    pub(super) fn into_parts(
        self,
    ) -> (
        Vec<ObservedMailboxCatalogItem>,
        Option<MailboxCatalogCursorState>,
    ) {
        (self.items, self.next_state)
    }
}

/// One catalog page with an authenticated opaque continuation token.
#[derive(Clone, Eq, PartialEq)]
pub struct SerializedMailboxCatalogPage {
    items: Vec<ObservedMailboxCatalogItem>,
    next_cursor: Option<String>,
}

impl SerializedMailboxCatalogPage {
    pub(super) const fn new(
        items: Vec<ObservedMailboxCatalogItem>,
        next_cursor: Option<String>,
    ) -> Self {
        Self { items, next_cursor }
    }

    /// Returns the immutable snapshot items in provider catalog order.
    #[must_use]
    pub fn items(&self) -> &[ObservedMailboxCatalogItem] {
        &self.items
    }

    /// Returns the opaque continuation cursor when more snapshot items remain.
    #[must_use]
    pub fn next_cursor(&self) -> Option<&str> {
        self.next_cursor.as_deref()
    }
}

impl fmt::Debug for SerializedMailboxCatalogPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SerializedMailboxCatalogPage")
            .field("item_count", &self.items.len())
            .field(
                "next_cursor",
                &self.next_cursor.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Fail-closed immutable catalog paging errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxCatalogPageError {
    /// Page size is zero or exceeds the frozen version-one maximum.
    InvalidPageSize,
    /// Cursor state cannot identify a valid next slice in the snapshot.
    InvalidCursorState,
    /// Cursor refers to a catalog snapshot no longer retained by the adapter.
    CursorExpired,
}

#[expect(
    clippy::redundant_pub_crate,
    reason = "sibling driver access while the paging module remains private"
)]
// jig-ignore-next-line: canonical rustfmt line.
pub(crate) fn validate_page_size(requested: Option<u16>) -> Result<u16, MailboxCatalogPageError> {
    let page_size = requested.unwrap_or(DEFAULT_PAGE_SIZE);
    if page_size == 0 || page_size > MAX_PAGE_SIZE {
        return Err(MailboxCatalogPageError::InvalidPageSize);
    }
    Ok(page_size)
}

// jig-ignore-next-line: canonical rustfmt line.
fn validate_snapshot_boundary(value: &str) -> Result<(), MailboxCatalogPageError> {
    if value.len() != SNAPSHOT_BOUNDARY_CHARS
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MailboxCatalogPageError::InvalidCursorState);
    }
    Ok(())
}
