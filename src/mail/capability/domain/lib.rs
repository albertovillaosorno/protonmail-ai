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

/// The side-effect class attached to a public mail operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SafetyClass {
    /// Observes mailbox state without changing it.
    ReadOnly,
    /// Changes state with a documented inverse or recovery path.
    Reversible,
    /// Causes an external side effect such as sending mail.
    ExternalSideEffect,
    /// Removes data without a guaranteed recovery path.
    Destructive,
}

/// The authority required to execute one non-destructive operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionGrant {
    /// Authority to observe mailbox state only.
    Observe,
    /// Authority to make one reversible mailbox change.
    ReversibleChange,
    /// Authority to cause one external side effect such as sending mail.
    ExternalSideEffect,
}

impl SafetyClass {
    /// Returns the exact authority required for this side-effect class.
    ///
    /// Destructive operations deliberately have no grant while permanent
    /// deletion remains disabled by repository policy.
    #[must_use]
    pub const fn required_grant(self) -> Option<ActionGrant> {
        match self {
            Self::ReadOnly => Some(ActionGrant::Observe),
            Self::Reversible => Some(ActionGrant::ReversibleChange),
            Self::ExternalSideEffect => Some(ActionGrant::ExternalSideEffect),
            Self::Destructive => None,
        }
    }

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
}

/// A borrowed secret whose common formatting traits always redact its value.
///
/// This type is a diagnostic boundary, not durable secret storage. Adapters may
/// expose the wrapped value only when calling the provider or credential store.
pub struct SecretRef<'a> {
    value: &'a str,
}

impl<'a> SecretRef<'a> {
    /// Wraps a value that must not appear in diagnostics.
    #[must_use]
    pub const fn new(value: &'a str) -> Self {
        Self { value }
    }

    /// Exposes the secret to an explicitly secret-aware integration boundary.
    #[must_use]
    pub const fn expose(self) -> &'a str {
        self.value
    }
}

impl core::fmt::Debug for SecretRef<'_> {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        out.write_str("[REDACTED]")
    }
}

impl core::fmt::Display for SecretRef<'_> {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        out.write_str("[REDACTED]")
    }
}

/// A planned public capability, independent of its adapter or transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capability {
    name: &'static str,
    safety: SafetyClass,
}

impl Capability {
    /// Creates a capability declaration.
    #[must_use]
    pub const fn new(name: &'static str, safety: SafetyClass) -> Self {
        Self { name, safety }
    }

    /// Returns the stable public operation name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
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

/// Selects the first adapter that can satisfy the complete capability set.
///
/// Selection never combines partial capability coverage from multiple adapters.
/// Callers may order candidates by policy, but once selected, one adapter owns
/// the complete requested operation set.
#[must_use]
pub fn select_adapter<'a, T: MailProviderPort>(
    required: &[Capability],
    candidates: &'a [T],
) -> Option<&'a T> {
    candidates.iter().find(|adapter| {
        required
            .iter()
            .all(|capability| adapter.supports(*capability))
    })
}

const PLANNED_CAPABILITIES: [Capability; 16] = [
    Capability::new("search_messages", SafetyClass::ReadOnly),
    Capability::new("get_message", SafetyClass::ReadOnly),
    Capability::new("get_thread", SafetyClass::ReadOnly),
    Capability::new("get_attachment", SafetyClass::ReadOnly),
    Capability::new("list_mailboxes", SafetyClass::ReadOnly),
    Capability::new("list_labels", SafetyClass::ReadOnly),
    Capability::new("create_draft", SafetyClass::Reversible),
    Capability::new("update_draft", SafetyClass::Reversible),
    Capability::new("send_draft", SafetyClass::ExternalSideEffect),
    Capability::new("reply", SafetyClass::ExternalSideEffect),
    Capability::new("forward", SafetyClass::ExternalSideEffect),
    Capability::new("mark_read", SafetyClass::Reversible),
    Capability::new("apply_labels", SafetyClass::Reversible),
    Capability::new("move_messages", SafetyClass::Reversible),
    Capability::new("trash_messages", SafetyClass::Reversible),
    Capability::new("delete_messages", SafetyClass::Destructive),
];

/// Returns the bootstrap capability inventory.
///
/// This inventory plans the contract; it does not claim that an adapter or
/// transport already implements any operation.
#[must_use]
pub const fn planned_capabilities() -> &'static [Capability] {
    &PLANNED_CAPABILITIES
}
