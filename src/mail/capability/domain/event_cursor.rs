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
use zeroize::Zeroize as _;

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
        Self::validate_account(account)?;
        for value in [adapter, generation] {
            validate_component(value)?;
        }
        Ok(Self {
            account: String::from(account),
            adapter: String::from(adapter),
            generation: String::from(generation),
        })
    }

    /// Rejects ambiguous account-binding text before a scoped cursor is made.
    ///
    /// Other scope components remain opaque; account identities may contain
    /// printable Unicode but not controls, whitespace, or invisible aliases.
    ///
    /// # Errors
    ///
    /// Returns `MalformedScope` for an empty, unbounded, or ambiguous account.
    // jig-ignore-next-line: rustfmt fixes the account method signature.
    pub fn validate_account(account: &str) -> Result<(), EventCursorBindingError> {
        validate_component(account)?;
        if account.chars().any(ambiguous_account_character) {
            return Err(EventCursorBindingError::MalformedScope);
        }
        Ok(())
    }

    /// Binds opaque adapter-owned resume state to this validated scope.
    #[must_use]
    pub const fn bind<State>(self, state: State) -> ScopedEventCursor<State>
    where
        State: zeroize::Zeroize,
    {
        ScopedEventCursor { scope: self, state }
    }

    /// Returns scope components for authenticated adapter cursor codecs.
    ///
    /// These values are internal binding material, not diagnostic fields.
    #[must_use]
    pub fn binding_components(&self) -> (&str, &str, &str) {
        (&self.account, &self.adapter, &self.generation)
    }

    /// Reports whether two scope values identify the same cursor domain.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self == other
    }
}

#[expect(
    clippy::missing_trait_methods,
    reason = "Drop scrubs private account and scope identifiers"
)]
impl Drop for EventCursorScope {
    fn drop(&mut self) {
        self.account.zeroize();
        self.adapter.zeroize();
        self.generation.zeroize();
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
pub struct ScopedEventCursor<State>
where
    State: zeroize::Zeroize,
{
    scope: EventCursorScope,
    state: State,
}

impl<State> ScopedEventCursor<State>
where
    State: zeroize::Zeroize,
{
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

#[expect(
    clippy::missing_trait_methods,
    reason = "Drop scrubs adapter-owned resume state"
)]
impl<State> Drop for ScopedEventCursor<State>
where
    State: zeroize::Zeroize,
{
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

impl<State> Debug for ScopedEventCursor<State>
where
    State: zeroize::Zeroize,
{
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

// Cursor-bound accounts must not permit visually hidden identity aliases.
// Keep printable Unicode while excluding default-ignorable format characters
// already refused by the offline session account-binding boundary.
// Account identity must not contain code points with no interchange meaning.
// The exact scalar conversion is lossless; stable const From<char> is absent.
#[expect(
    clippy::as_conversions,
    reason = "lossless char to u32 conversion in a stable const predicate"
)]
const fn is_account_noncharacter(character: char) -> bool {
    let codepoint = character as u32;
    matches!(codepoint, 0xfdd0..=0xfdef) || codepoint & 0xfffe == 0xfffe
}

const fn ambiguous_account_character(character: char) -> bool {
    character.is_control()
        || character.is_whitespace()
        || is_account_noncharacter(character)
        || matches!(
            character,
            '\u{00ad}' | '\u{034f}' | '\u{0600}'..='\u{0605}'
                | '\u{061c}' | '\u{06dd}' | '\u{070f}'
                | '\u{0890}'..='\u{0891}' | '\u{08e2}'
                | '\u{115f}'..='\u{1160}' | '\u{17b4}'..='\u{17b5}'
                | '\u{180b}'..='\u{180f}' | '\u{1bca0}'..='\u{1bca3}'
                | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}' | '\u{2800}' | '\u{3164}'
                | '\u{fe00}'..='\u{fe0f}' | '\u{feff}' | '\u{ffa0}'
                | '\u{fff9}'..='\u{fffb}' | '\u{110bd}' | '\u{110cd}'
                | '\u{13430}'..='\u{1343f}' | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0001}' | '\u{e0020}'..='\u{e007f}'
                | '\u{e0100}'..='\u{e01ef}' | '\u{fffd}'
        )
}
