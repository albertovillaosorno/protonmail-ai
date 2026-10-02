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
//   - Provider-neutral event-cursor scope and binding semantics.
// - Must-Not:
//   - Know provider event formats, browser state, credentials, or transports.
// - Allows:
//   - Bind opaque adapter state to account, adapter, and generation identity.
// - Split-When:
//   - Cursor serialization or authentication acquires an independent lifecycle.
// - Merge-When:
//   - Event cursors become inseparable from the public change envelope.
// - Summary:
//   - Prevents event cursors from crossing account or adapter generations.
// - Description:
//   - Keeps provider state opaque while validating provider-neutral scope.
// - Usage:
//   - Adapters bind resume state before transport-specific cursor encoding.
// - Defaults:
//   - Diagnostics redact scope and provider state.
//

//! Provider-neutral event-cursor scope and binding semantics.

use core::fmt::{Debug, Formatter, Result as FmtResult};

const MAX_CURSOR_SCOPE_COMPONENT_BYTES: usize = 512;

/// Validated scope required by the version-one `event_cursor` contract.
#[derive(Clone, Eq, PartialEq)]
pub struct EventCursorScope {
    account: String,
    adapter: String,
    generation: String,
}

impl EventCursorScope {
    /// Constructs one account/adapter/generation scope.
    ///
    /// # Errors
    ///
    /// Rejects empty or excessively large opaque scope components.
    pub fn new(
        account: &str,
        adapter: &str,
        generation: &str,
    ) -> Result<Self, EventCursorBindingError> {
        for value in [account, adapter, generation] {
            validate_component(value)?;
        }
        Ok(Self {
            account: String::from(account),
            adapter: String::from(adapter),
            generation: String::from(generation),
        })
    }

    /// Binds opaque adapter-owned resume state to this validated scope.
    #[must_use]
    pub const fn bind<State>(self, state: State) -> ScopedEventCursor<State> {
        ScopedEventCursor { scope: self, state }
    }

    /// Reports whether two scope values identify the same cursor domain.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self == other
    }
}

impl Debug for EventCursorScope {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("EventCursorScope")
            .field("account", &"<redacted>")
            .field("adapter", &"<redacted>")
            .field("generation", &"<redacted>")
            .finish()
    }
}

/// Opaque adapter state bound to one provider-neutral event-cursor scope.
#[derive(Clone, Eq, PartialEq)]
pub struct ScopedEventCursor<State> {
    scope: EventCursorScope,
    state: State,
}

impl<State> ScopedEventCursor<State> {
    /// Releases adapter-owned state only for an exact current scope.
    ///
    /// # Errors
    ///
    /// Returns a typed mismatch for account, adapter, or generation drift.
    // jig-ignore-next-line: canonical rustfmt line.
    pub fn state_for(&self, current: &EventCursorScope) -> Result<&State, EventCursorBindingError> {
        if self.scope.account != current.account {
            return Err(EventCursorBindingError::AccountMismatch);
        }
        if self.scope.adapter != current.adapter {
            return Err(EventCursorBindingError::AdapterMismatch);
        }
        if self.scope.generation != current.generation {
            return Err(EventCursorBindingError::GenerationMismatch);
        }
        Ok(&self.state)
    }

    /// Returns the validated scope without exposing individual components.
    #[must_use]
    pub const fn scope(&self) -> &EventCursorScope {
        &self.scope
    }
}

impl<State> Debug for ScopedEventCursor<State> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("ScopedEventCursor")
            .field("scope", &self.scope)
            .field("state", &"<redacted>")
            .finish()
    }
}

/// Stable provider-neutral event-cursor resume failure class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventCursorResumeFailure {
    /// Cursor is malformed or belongs to another account/adapter scope.
    InvalidCursor,
    /// Cursor was valid for an older adapter generation or lost exact resume.
    CursorExpired,
}

/// Fail-closed provider-neutral event-cursor binding failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventCursorBindingError {
    /// One required scope component was empty or exceeded the fixed bound.
    MalformedScope,
    /// Cursor belongs to another authenticated account.
    AccountMismatch,
    /// Cursor belongs to another selected adapter.
    AdapterMismatch,
    /// Cursor belongs to an older or otherwise different adapter generation.
    GenerationMismatch,
}

impl EventCursorBindingError {
    /// Maps scope validation/binding failure into the frozen cursor semantics.
    #[must_use]
    pub const fn resume_failure(self) -> EventCursorResumeFailure {
        match self {
            Self::GenerationMismatch => EventCursorResumeFailure::CursorExpired,
            // jig-ignore-next-line: canonical rustfmt line.
            Self::MalformedScope | Self::AccountMismatch | Self::AdapterMismatch => {
                EventCursorResumeFailure::InvalidCursor
            }
        }
    }
}

// jig-ignore-next-line: canonical rustfmt line.
const fn validate_component(value: &str) -> Result<(), EventCursorBindingError> {
    if value.is_empty() || value.len() > MAX_CURSOR_SCOPE_COMPONENT_BYTES {
        return Err(EventCursorBindingError::MalformedScope);
    }
    Ok(())
}
