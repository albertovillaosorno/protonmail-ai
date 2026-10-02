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
//   - Provider-neutral mail capability identity and safety classification.
// - Must-Not:
//   - Depend on transports, providers, credentials, or deployment details.
// - Allows:
//   - Declare stable mail operations and their side-effect classes.
// - Split-When:
//   - A capability family acquires an independent semantic lifecycle.
// - Merge-When:
//   - Capability identity and safety can no longer change independently.
// - Summary:
//   - Defines the provider-neutral mail capability domain.
// - Description:
//   - Keeps safety semantics stable across CLI, MCP, and remote transports.
// - Usage:
//   - Runtime composition consumes the declared capability inventory.
// - Defaults:
//   - No provider access, credentials, network traffic, or side effects.
//

//! Provider-neutral mail capability and safety contracts.
//!
//! This domain owns tool identity and side-effect classification. It must not
//! depend on MCP, browser automation, Proton APIs, IMAP, SMTP, or deployment.

#![forbid(unsafe_code)]

mod event_cursor;

pub use event_cursor::EventCursorBindingError;
pub use event_cursor::{EventCursorScope, ScopedEventCursor};

/// Frozen version-one public tool contract.
#[path = "../contract/v1.rs"]
pub mod contract_v1;

use core::fmt::{Debug, Display, Formatter, Result as FmtResult};

/// The side-effect class attached to a public mail operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SafetyClass {
    /// Removes data without a guaranteed recovery path.
    Destructive,
    /// Causes an external side effect such as sending mail.
    ExternalSideEffect,
    /// Observes mailbox state without changing it.
    ReadOnly,
    /// Changes state with a documented inverse or recovery path.
    Reversible,
}

/// The authority required to execute one non-destructive operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionGrant {
    /// Authority to cause one external side effect such as sending mail.
    ExternalSideEffect,
    /// Authority to observe mailbox state only.
    Observe,
    /// Authority to make one reversible mailbox change.
    ReversibleChange,
}

impl SafetyClass {
    /// Reports whether the supplied authority permits this side-effect class.
    #[must_use]
    pub const fn authorizes(self, grant: ActionGrant) -> bool {
        matches!(
            (self, grant),
            (Self::ReadOnly, ActionGrant::Observe)
                | (Self::Reversible, ActionGrant::ReversibleChange)
                | (Self::ExternalSideEffect, ActionGrant::ExternalSideEffect)
        )
    }

    /// Returns the exact authority required for this side-effect class.
    ///
    /// Destructive operations deliberately have no grant while permanent
    /// deletion remains disabled by repository policy.
    #[must_use]
    pub const fn required_grant(self) -> Option<ActionGrant> {
        match self {
            Self::Destructive => None,
            Self::ExternalSideEffect => Some(ActionGrant::ExternalSideEffect),
            Self::ReadOnly => Some(ActionGrant::Observe),
            Self::Reversible => Some(ActionGrant::ReversibleChange),
        }
    }
}

/// A borrowed secret whose common formatting traits always redact its value.
///
/// This type is a diagnostic boundary, not durable secret storage. Adapters may
/// expose the wrapped value only when calling the provider or credential store.
pub struct SecretRef<'secret> {
    value: &'secret str,
}

impl<'secret> SecretRef<'secret> {
    /// Exposes the secret to an explicitly secret-aware integration boundary.
    #[must_use]
    pub const fn expose(self) -> &'secret str {
        self.value
    }

    /// Wraps a value that must not appear in diagnostics.
    #[must_use]
    pub const fn new(value: &'secret str) -> Self {
        Self { value }
    }
}

impl Debug for SecretRef<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("[REDACTED]")
    }
}

impl Display for SecretRef<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("[REDACTED]")
    }
}

/// A planned public capability, independent of its adapter or transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capability {
    name: &'static str,
    safety: SafetyClass,
}

impl Capability {
    /// Returns the stable public operation name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Creates a capability declaration.
    #[must_use]
    pub const fn new(name: &'static str, safety: SafetyClass) -> Self {
        Self { name, safety }
    }

    /// Returns the operation's side-effect classification.
    #[must_use]
    pub const fn safety(self) -> SafetyClass {
        self.safety
    }
}

/// A provider-neutral boundary implemented by exactly one mail adapter.
pub trait MailProviderPort {
    /// Returns a stable, diagnostic-only adapter identifier.
    fn adapter_id(&self) -> &str;

    /// Reports whether this adapter can implement one public capability.
    fn supports(&self, capability: Capability) -> bool;
}

const PLANNED_CAPABILITIES: [Capability; 29] = [
    Capability::new("search_messages", SafetyClass::ReadOnly),
    Capability::new("search_threads", SafetyClass::ReadOnly),
    Capability::new("list_messages", SafetyClass::ReadOnly),
    Capability::new("list_threads", SafetyClass::ReadOnly),
    Capability::new("get_message", SafetyClass::ReadOnly),
    Capability::new("get_thread", SafetyClass::ReadOnly),
    Capability::new("get_attachment", SafetyClass::ReadOnly),
    Capability::new("list_mailboxes", SafetyClass::ReadOnly),
    Capability::new("list_labels", SafetyClass::ReadOnly),
    Capability::new("list_senders", SafetyClass::ReadOnly),
    Capability::new("create_draft", SafetyClass::Reversible),
    Capability::new("read_draft", SafetyClass::ReadOnly),
    Capability::new("update_draft", SafetyClass::Reversible),
    Capability::new("discard_draft", SafetyClass::Reversible),
    Capability::new("send_draft", SafetyClass::ExternalSideEffect),
    Capability::new("reply", SafetyClass::ExternalSideEffect),
    Capability::new("reply_all", SafetyClass::ExternalSideEffect),
    Capability::new("forward", SafetyClass::ExternalSideEffect),
    Capability::new("mark_read", SafetyClass::Reversible),
    Capability::new("mark_unread", SafetyClass::Reversible),
    Capability::new("apply_labels", SafetyClass::Reversible),
    Capability::new("remove_labels", SafetyClass::Reversible),
    Capability::new("archive", SafetyClass::Reversible),
    Capability::new("unarchive", SafetyClass::Reversible),
    Capability::new("move_messages", SafetyClass::Reversible),
    Capability::new("trash_messages", SafetyClass::Reversible),
    Capability::new("restore_messages", SafetyClass::Reversible),
    Capability::new("wait_for_changes", SafetyClass::ReadOnly),
    Capability::new("delete_messages", SafetyClass::Destructive),
];

/// Selects the first adapter that can satisfy the complete capability set.
///
/// Selection never combines partial capability coverage from multiple adapters.
/// Callers may order candidates by policy, but once selected, one adapter owns
/// the complete requested operation set.
#[must_use]
pub fn select_adapter<'adapter, T>(
    required: &[Capability],
    candidates: &'adapter [T],
) -> Option<&'adapter T>
where
    T: MailProviderPort,
{
    candidates.iter().find(|adapter| {
        required
            .iter()
            .all(|capability| adapter.supports(*capability))
    })
}

/// Returns the bootstrap capability inventory.
///
/// This inventory plans the contract; it does not claim that an adapter or
/// transport already implements any operation.
#[must_use]
pub const fn planned_capabilities() -> &'static [Capability] {
    &PLANNED_CAPABILITIES
}
