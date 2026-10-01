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
//   - Explicit blockers between verified visible pages and public
//     list_messages.
// - Must-Not:
//   - Claim contract support from approximate ordering or page-number state.
// - Allows:
//   - Report why the current web boundary cannot issue a compliant cursor.
// - Split-When:
//   - A durable snapshot/cursor implementation replaces these blockers.
// - Merge-When:
//   - Provider-neutral read workflows own capability negotiation directly.
// - Summary:
//   - Prevents visible-page reads from masquerading as list_messages support.
// - Description:
//   - Records tie-break and snapshot requirements after timestamp proof.
// - Usage:
//   - Web adapter preflight exposes diagnostic-only readiness to composition.
// - Defaults:
//   - Current WebClients evidence is not sufficient for list_messages.
//

//! Contract blockers for provider-neutral `list_messages` on the web adapter.

use crate::mailbox_sort::MailboxSortOrder;

/// A proven reason public `list_messages` cannot yet be advertised.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListMessagesBlocker {
    /// Visible sort UI does not prove provider `Time` descending.
    ProviderSortKeyUnproven,
    /// `WebClients` falls back to element Order, not provider-neutral ID, on
    /// ties.
    ProviderTieBreakDiffers,
    /// Page-number navigation does not expose a stable snapshot boundary token.
    MissingSnapshotBoundary,
    /// The current visible UI sort is not semantic newest-first.
    SortNotNewestFirst,
}

/// Fail-closed readiness report for the provider-neutral list contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListMessagesReadiness {
    blockers: Vec<ListMessagesBlocker>,
    observed_sort: MailboxSortOrder,
}

impl ListMessagesReadiness {
    pub(crate) fn current(observed_sort: MailboxSortOrder) -> Self {
        let mut blockers = vec![
            ListMessagesBlocker::ProviderSortKeyUnproven,
            ListMessagesBlocker::ProviderTieBreakDiffers,
            ListMessagesBlocker::MissingSnapshotBoundary,
        ];
        if !observed_sort.is_newest_first() {
            blockers.push(ListMessagesBlocker::SortNotNewestFirst);
        }
        Self {
            blockers,
            observed_sort,
        }
    }

    /// Returns every currently proven contract blocker.
    #[must_use]
    pub fn blockers(&self) -> &[ListMessagesBlocker] {
        &self.blockers
    }

    /// Returns the visible sort order proven through semantic UI state.
    #[must_use]
    pub const fn observed_sort(&self) -> MailboxSortOrder {
        self.observed_sort
    }

    /// Returns true only when no blocker remains.
    ///
    /// The current implementation deliberately cannot return true because
    /// `WebClients` does not expose all required snapshot/order evidence.
    #[must_use]
    pub const fn ready(&self) -> bool {
        self.blockers.is_empty()
    }
}
