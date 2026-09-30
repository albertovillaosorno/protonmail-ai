// SPDX-License-Identifier: GPL-3.0-only

//! Provider-neutral capability and safety contracts for `protonmail-ai`.
//!
//! The crate intentionally contains no network or credential implementation in
//! the bootstrap phase.

#![forbid(unsafe_code)]

/// The side-effect class attached to a future MCP tool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SafetyClass {
    /// Observes mailbox state without changing it.
    ReadOnly,
    /// Changes state that has a documented inverse or recovery path.
    Reversible,
    /// Causes an external side effect such as sending mail.
    ExternalSideEffect,
    /// Removes data without a guaranteed recovery path.
    Destructive,
}

/// A planned MCP capability, independent of its Proton adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capability {
    /// Stable MCP-facing tool name.
    pub name: &'static str,
    /// Safety classification used by policy and tool annotations.
    pub safety: SafetyClass,
}

/// Bootstrap capability inventory.
///
/// This is a planning surface, not a claim that the capabilities work yet.
#[must_use]
pub const fn planned_capabilities() -> &'static [Capability] {
    &[
        Capability {
            name: "search_messages",
            safety: SafetyClass::ReadOnly,
        },
        Capability {
            name: "get_message",
            safety: SafetyClass::ReadOnly,
        },
        Capability {
            name: "get_thread",
            safety: SafetyClass::ReadOnly,
        },
        Capability {
            name: "get_attachment",
            safety: SafetyClass::ReadOnly,
        },
        Capability {
            name: "list_mailboxes",
            safety: SafetyClass::ReadOnly,
        },
        Capability {
            name: "list_labels",
            safety: SafetyClass::ReadOnly,
        },
        Capability {
            name: "create_draft",
            safety: SafetyClass::Reversible,
        },
        Capability {
            name: "update_draft",
            safety: SafetyClass::Reversible,
        },
        Capability {
            name: "send_draft",
            safety: SafetyClass::ExternalSideEffect,
        },
        Capability {
            name: "reply",
            safety: SafetyClass::ExternalSideEffect,
        },
        Capability {
            name: "forward",
            safety: SafetyClass::ExternalSideEffect,
        },
        Capability {
            name: "mark_read",
            safety: SafetyClass::Reversible,
        },
        Capability {
            name: "apply_labels",
            safety: SafetyClass::Reversible,
        },
        Capability {
            name: "move_messages",
            safety: SafetyClass::Reversible,
        },
        Capability {
            name: "trash_messages",
            safety: SafetyClass::Reversible,
        },
        Capability {
            name: "delete_messages",
            safety: SafetyClass::Destructive,
        },
    ]
}
