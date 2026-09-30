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
//   - Versioned provider-neutral mail tool contract metadata.
// - Must-Not:
//   - Depend on transports, Proton, Bridge, credentials, or deployment details.
// - Allows:
//   - Serialize stable identifiers, limits, errors, schemas, and tool hints.
// - Split-When:
//   - A new incompatible public contract version is accepted.
// - Merge-When:
//   - Tool contract metadata no longer changes independently from capabilities.
// - Summary:
//   - Freezes the version-one provider-neutral mail tool contract.
// - Description:
//   - Declares stable machine-readable metadata before adapters or MCP wiring.
// - Usage:
//   - Transport and CLI layers consume this inventory after capability checks.
// - Defaults:
//   - Destructive operations are declared but disabled.
//

//! Version-one provider-neutral mail tool contract.

use serde::{Deserialize, Serialize};
use serde_json::{Error as JsonError, from_str, to_string_pretty};

/// Stable contract version identifier.
pub const CONTRACT_VERSION: &str = "mail-tools/v1";
/// Default number of items in one page.
pub const DEFAULT_PAGE_SIZE: u16 = 50;
/// Maximum number of items in one batch mutation.
pub const MAX_BATCH_ITEMS: u16 = 100;
/// Maximum attachment bytes returned inline through a tool result.
pub const MAX_INLINE_ATTACHMENT_BYTES: u32 = 32_768;
/// Maximum number of items in one page.
pub const MAX_PAGE_SIZE: u16 = 100;
/// Maximum bounded mailbox-change wait in milliseconds.
pub const MAX_WAIT_MILLISECONDS: u32 = 30_000;

/// Machine-readable version-one contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractV1 {
    /// Structured error vocabulary.
    pub errors: Vec<ErrorSpec>,
    /// Opaque identifier classes exposed by the public surface.
    pub identifiers: Vec<IdentifierSpec>,
    /// Global request and response bounds.
    pub limits: LimitSpec,
    /// Pagination semantics shared by list and search tools.
    pub pagination: PaginationSpec,
    /// Frozen public tool inventory.
    pub tools: Vec<ToolSpec>,
    /// Stable contract version.
    pub version: String,
}

/// One stable structured error code.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ErrorSpec {
    /// Stable machine-readable code.
    pub code: String,
    /// Retry behavior.
    pub retry: RetryClass,
}

/// Boolean annotation value serialized exactly as an MCP boolean hint.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Hint(bool);

impl Hint {
    const NO: Self = Self(false);
    const YES: Self = Self(true);
}

/// One opaque identifier class.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdentifierSpec {
    /// Stable schema name.
    pub name: String,
    /// Whether clients may parse provider meaning from the value.
    pub opaque: bool,
    /// Identity scope.
    pub scope: String,
}

/// Shared hard limits for version one.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LimitSpec {
    /// Default list or search page size.
    pub default_page_size: u16,
    /// Maximum items in one batch mutation.
    pub max_batch_items: u16,
    /// Maximum attachment size returned inline.
    pub max_inline_attachment_bytes: u32,
    /// Maximum list or search page size.
    pub max_page_size: u16,
    /// Maximum bounded change wait.
    pub max_wait_milliseconds: u32,
}

/// Shared cursor and ordering contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PaginationSpec {
    /// Cursor representation.
    pub cursor: String,
    /// Behavior when a snapshot can no longer continue safely.
    pub expired_cursor_error: String,
    /// Stable primary sort key.
    pub primary_order: String,
    /// Stable tie breaker.
    pub tie_breaker: String,
}

/// Retry behavior attached to one structured error.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryClass {
    /// The same request must not be retried automatically.
    Never,
    /// Authentication must be re-established first.
    Reauthenticate,
    /// Outcome is ambiguous and must be resolved before another side effect.
    ResolveAmbiguity,
    /// Pagination must restart from the first page.
    RestartPagination,
    /// Retry may repeat the identical request under its idempotency rules.
    SameRequest,
}

/// MCP tool-annotation hints frozen with the public contract.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolAnnotations {
    /// Whether the operation may perform irreversible deletion.
    pub destructive_hint: Hint,
    /// Whether identical arguments may be safely repeated.
    pub idempotent_hint: Hint,
    /// Whether the tool crosses an open-world trust boundary.
    pub open_world_hint: Hint,
    /// Whether the operation changes mailbox or external state.
    pub read_only_hint: Hint,
}

/// Safety class carried in the serialized contract.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolSafety {
    /// Irreversible operation disabled by default.
    Destructive,
    /// Causes an external side effect such as sending mail.
    ExternalSideEffect,
    /// Observes state only.
    ReadOnly,
    /// Mutates state with a documented recovery path.
    Reversible,
}

/// One frozen public tool definition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ToolSpec {
    /// MCP behavior hints.
    pub annotations: ToolAnnotations,
    /// Required provider-neutral capability.
    pub capability: String,
    /// Whether the tool may be advertised without an extra destructive gate.
    pub enabled_by_default: bool,
    /// Input schema identifier defined in the written contract.
    pub input_schema: String,
    /// Stable public tool name.
    pub name: String,
    /// Output schema identifier defined in the written contract.
    pub output_schema: String,
    /// Side-effect class.
    pub safety: ToolSafety,
}

#[derive(Clone, Copy)]
struct ToolRow {
    input: &'static str,
    name: &'static str,
    output: &'static str,
    safety: ToolSafety,
}

const TOOL_ROWS: [ToolRow; 29] = [
    row(
        "search_messages",
        "search_v1",
        "message_page_v1",
        ToolSafety::ReadOnly,
    ),
    row(
        "search_threads",
        "search_v1",
        "thread_page_v1",
        ToolSafety::ReadOnly,
    ),
    row(
        "list_messages",
        "page_v1",
        "message_page_v1",
        ToolSafety::ReadOnly,
    ),
    row(
        "list_threads",
        "page_v1",
        "thread_page_v1",
        ToolSafety::ReadOnly,
    ),
    row(
        "get_message",
        "message_ref_v1",
        "message_v1",
        ToolSafety::ReadOnly,
    ),
    row(
        "get_thread",
        "thread_ref_v1",
        "thread_v1",
        ToolSafety::ReadOnly,
    ),
    row(
        "get_attachment",
        "attachment_get_v1",
        "attachment_v1",
        ToolSafety::ReadOnly,
    ),
    row(
        "list_mailboxes",
        "page_v1",
        "mailbox_page_v1",
        ToolSafety::ReadOnly,
    ),
    row(
        "list_labels",
        "page_v1",
        "label_page_v1",
        ToolSafety::ReadOnly,
    ),
    row(
        "list_senders",
        "page_v1",
        "sender_page_v1",
        ToolSafety::ReadOnly,
    ),
    row(
        "create_draft",
        "draft_create_v1",
        "draft_v1",
        ToolSafety::Reversible,
    ),
    row(
        "read_draft",
        "draft_ref_v1",
        "draft_v1",
        ToolSafety::ReadOnly,
    ),
    row(
        "update_draft",
        "draft_update_v1",
        "draft_v1",
        ToolSafety::Reversible,
    ),
    row(
        "discard_draft",
        "draft_ref_v1",
        "mutation_v1",
        ToolSafety::Reversible,
    ),
    row(
        "send_draft",
        "send_draft_v1",
        "send_v1",
        ToolSafety::ExternalSideEffect,
    ),
    row(
        "reply",
        "reply_v1",
        "send_v1",
        ToolSafety::ExternalSideEffect,
    ),
    row(
        "reply_all",
        "reply_v1",
        "send_v1",
        ToolSafety::ExternalSideEffect,
    ),
    row(
        "forward",
        "forward_v1",
        "send_v1",
        ToolSafety::ExternalSideEffect,
    ),
    row(
        "mark_read",
        "message_batch_v1",
        "batch_v1",
        ToolSafety::Reversible,
    ),
    row(
        "mark_unread",
        "message_batch_v1",
        "batch_v1",
        ToolSafety::Reversible,
    ),
    row(
        "apply_labels",
        "label_batch_v1",
        "batch_v1",
        ToolSafety::Reversible,
    ),
    row(
        "remove_labels",
        "label_batch_v1",
        "batch_v1",
        ToolSafety::Reversible,
    ),
    row(
        "archive",
        "message_batch_v1",
        "batch_v1",
        ToolSafety::Reversible,
    ),
    row(
        "unarchive",
        "message_batch_v1",
        "batch_v1",
        ToolSafety::Reversible,
    ),
    row(
        "move_messages",
        "move_batch_v1",
        "batch_v1",
        ToolSafety::Reversible,
    ),
    row(
        "trash_messages",
        "message_batch_v1",
        "batch_v1",
        ToolSafety::Reversible,
    ),
    row(
        "restore_messages",
        "message_batch_v1",
        "batch_v1",
        ToolSafety::Reversible,
    ),
    row(
        "wait_for_changes",
        "change_wait_v1",
        "change_page_v1",
        ToolSafety::ReadOnly,
    ),
    row(
        "delete_messages",
        "message_batch_v1",
        "batch_v1",
        ToolSafety::Destructive,
    ),
];

/// Returns the complete frozen version-one tool contract.
#[must_use]
pub fn contract() -> ContractV1 {
    ContractV1 {
        errors: errors(),
        identifiers: identifiers(),
        limits: LimitSpec {
            default_page_size: DEFAULT_PAGE_SIZE,
            max_batch_items: MAX_BATCH_ITEMS,
            max_inline_attachment_bytes: MAX_INLINE_ATTACHMENT_BYTES,
            max_page_size: MAX_PAGE_SIZE,
            max_wait_milliseconds: MAX_WAIT_MILLISECONDS,
        },
        pagination: PaginationSpec {
            cursor: "opaque-request-bound-snapshot-cursor".to_owned(),
            expired_cursor_error: "cursor_expired".to_owned(),
            primary_order: "received_at_desc".to_owned(),
            tie_breaker: "provider_neutral_id_asc".to_owned(),
        },
        tools: tools(),
        version: CONTRACT_VERSION.to_owned(),
    }
}

/// Deserializes one version-one contract from JSON.
///
/// # Errors
///
/// Returns the JSON parser error when the input is not a valid contract.
pub fn from_json(serialized: &str) -> Result<ContractV1, JsonError> {
    from_str(serialized)
}

/// Serializes one version-one contract as deterministic pretty JSON.
///
/// # Errors
///
/// Returns the JSON serializer error if serialization fails.
pub fn to_json(contract: &ContractV1) -> Result<String, JsonError> {
    to_string_pretty(contract)
}

const fn annotations(safety: ToolSafety) -> ToolAnnotations {
    match safety {
        ToolSafety::Destructive => hints(Hint::NO, Hint::YES, Hint::YES),
        ToolSafety::ExternalSideEffect | ToolSafety::Reversible => {
            hints(Hint::NO, Hint::NO, Hint::YES)
        }
        ToolSafety::ReadOnly => hints(Hint::YES, Hint::NO, Hint::YES),
    }
}

fn errors() -> Vec<ErrorSpec> {
    use RetryClass as Retry;

    [
        ("authentication_required", Retry::Reauthenticate),
        ("session_expired", Retry::Reauthenticate),
        ("permission_denied", Retry::Never),
        ("capability_unavailable", Retry::Never),
        ("not_found", Retry::Never),
        ("invalid_argument", Retry::Never),
        ("invalid_cursor", Retry::Never),
        ("cursor_expired", Retry::RestartPagination),
        ("conflict", Retry::Never),
        ("rate_limited", Retry::SameRequest),
        ("transient_provider", Retry::SameRequest),
        ("compatibility_error", Retry::Never),
        ("ambiguous_outcome", Retry::ResolveAmbiguity),
        ("size_limit", Retry::Never),
        ("unsafe_path", Retry::Never),
        ("destructive_disabled", Retry::Never),
    ]
    .into_iter()
    .map(|(code, retry)| ErrorSpec {
        code: code.to_owned(),
        retry,
    })
    .collect()
}

const fn hints(read: Hint, destructive: Hint, repeat: Hint) -> ToolAnnotations {
    ToolAnnotations {
        destructive_hint: destructive,
        idempotent_hint: repeat,
        open_world_hint: Hint::YES,
        read_only_hint: read,
    }
}

fn identifiers() -> Vec<IdentifierSpec> {
    [
        ("message_id", "account"),
        ("thread_id", "account"),
        ("mailbox_id", "account"),
        ("label_id", "account"),
        ("draft_id", "account"),
        ("sender_identity_id", "account"),
        ("attachment_id", "message"),
        ("event_cursor", "account_adapter_generation"),
    ]
    .into_iter()
    .map(|(name, scope)| IdentifierSpec {
        name: name.to_owned(),
        opaque: true,
        scope: scope.to_owned(),
    })
    .collect()
}

const fn row(
    name: &'static str,
    input: &'static str,
    output: &'static str,
    safety: ToolSafety,
) -> ToolRow {
    ToolRow {
        input,
        name,
        output,
        safety,
    }
}

fn tools() -> Vec<ToolSpec> {
    TOOL_ROWS
        .iter()
        .map(|item| ToolSpec {
            annotations: annotations(item.safety),
            capability: item.name.to_owned(),
            enabled_by_default: item.safety != ToolSafety::Destructive,
            input_schema: item.input.to_owned(),
            name: item.name.to_owned(),
            output_schema: item.output.to_owned(),
            safety: item.safety,
        })
        .collect()
}
