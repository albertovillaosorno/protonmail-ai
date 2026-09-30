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
//   - Provider-neutral authentication session state and transitions.
// - Must-Not:
//   - Store secrets, launch browsers, access credential stores, or call Proton.
// - Allows:
//   - Model fail-closed session status and deterministic lifecycle transitions.
// - Split-When:
//   - Account identity and session lifecycle gain independent change cadence.
// - Merge-When:
//   - Authentication state becomes inseparable from provider integration.
// - Summary:
//   - Defines the secret-free authentication session state machine.
// - Description:
//   - Keeps login, expiry, revocation, and logout semantics deterministic.
// - Usage:
//   - Authentication application logic applies provider and store observations.
// - Defaults:
//   - No authority is available until a session is installed successfully.
//

//! Provider-neutral authentication session state rules.
//!
//! This domain deliberately contains no credential material. Browser, provider,
//! and operating-system secret-store adapters translate observations into the
//! events modeled here.

#![forbid(unsafe_code)]

/// Observable account-scoped session status without secret material.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SessionState {
    /// No project-owned local authority exists.
    #[default]
    Absent,
    /// Loaded authority belongs to a different account identity.
    AccountMismatch,
    /// Provider authority expired and cannot be used as-is.
    Expired,
    /// Provider or user explicitly revoked the authority.
    Revoked,
    /// Durable secret storage cannot be accessed safely.
    StoreUnavailable,
    /// The stored authority is accepted for the bound account.
    Valid,
}

impl SessionState {
    /// Reports whether mailbox authority is currently usable.
    #[must_use]
    pub const fn authority_available(self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// Secret-free observation that can change session status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionEvent {
    /// Loaded authority resolves to an unexpected account identity.
    AccountMismatchDetected,
    /// Interactive login ended before a complete durable installation.
    InteractiveLoginAborted,
    /// A complete session was durably installed for the intended account.
    LoginInstalled,
    /// Local logout removed all project-owned local authority.
    LocalLogoutCompleted,
    /// The provider accepted the current or refreshed authority.
    ProviderAccepted,
    /// The provider reported that authority expired.
    ProviderExpired,
    /// The provider reported that authority was revoked.
    ProviderRevoked,
    /// The operating-system credential store is unavailable or ambiguous.
    StoreUnavailable,
}

/// Applies one observed event to the current account-scoped session state.
///
/// Login cancellation preserves the previously installed session, if any.
/// Local logout is idempotent and always leaves the account without local
/// authority. Every failure state is fail-closed.
#[must_use]
pub const fn apply(current: SessionState, event: SessionEvent) -> SessionState {
    use SessionEvent::{LoginInstalled, ProviderAccepted};

    match event {
        SessionEvent::AccountMismatchDetected => SessionState::AccountMismatch,
        SessionEvent::InteractiveLoginAborted => current,
        LoginInstalled | ProviderAccepted => SessionState::Valid,
        SessionEvent::LocalLogoutCompleted => SessionState::Absent,
        SessionEvent::ProviderExpired => SessionState::Expired,
        SessionEvent::ProviderRevoked => SessionState::Revoked,
        SessionEvent::StoreUnavailable => SessionState::StoreUnavailable,
    }
}
