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
//   - Semantic Proton Mail UI state and side-effect gating.
// - Must-Not:
//   - Contain DOM selectors, credentials, browser session state, or live I/O.
// - Allows:
//   - Authorize a typed mailbox target from explicit visible-state evidence.
// - Split-When:
//   - Provider page-state parsing requires independent browser-driver
//     ownership.
// - Merge-When:
//   - A single reviewed web adapter owns policy and browser execution together.
// - Summary:
//   - Fails closed before browser UI targets can cause an unintended action.
// - Description:
//   - Cross-checks semantic target, capability, authority, and visible surface.
// - Usage:
//   - Browser-driver code calls the gate immediately before a UI interaction.
// - Defaults:
//   - Login, challenge, unknown, and drifted surfaces authorize no target.
//

//! Semantic UI state and action gate for the Proton Mail web adapter.

use mail_capability_domain::{ActionGrant, Capability, SafetyClass};

const BOX_CAPS: [&str; 3] = ["list_mailboxes", "list_labels", "list_senders"];
const MESSAGE_NAV_CAPS: [&str; 5] = [
    "list_messages",
    "list_threads",
    "get_message",
    "get_thread",
    "read_draft",
];

/// High-level visible state derived from semantic page evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebSurface {
    /// Proton authentication challenge is visible and must remain human-owned.
    AuthenticationChallenge,
    /// An authenticated composer is visible inside the Mail application.
    Composer,
    /// The authenticated mailbox shell is visible without an open composer.
    Mailbox,
    /// A Proton login surface is visible and must remain human-owned.
    SignedOut,
    /// Expected Mail application evidence is missing or contradicted.
    Incompatible,
}

/// Human-owned authentication surface currently visible, if any.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthSurface {
    /// No Proton authentication surface is visible.
    None,
    /// Proton login is visible and remains human-controlled.
    Login,
    /// Proton authentication challenge is visible and remains human-controlled.
    Challenge,
}

/// Minimal semantic evidence supplied by a future browser driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiEvidence {
    auth_surface: AuthSurface,
    composer_visible: bool,
    mail_shell_visible: bool,
    unexpected_blocker_visible: bool,
}

impl UiEvidence {
    /// Builds one semantic page observation without carrying DOM selectors.
    #[must_use]
    pub const fn new(
        mail_shell_visible: bool,
        composer_visible: bool,
        auth_surface: AuthSurface,
        unexpected_blocker_visible: bool,
    ) -> Self {
        Self {
            auth_surface,
            composer_visible,
            mail_shell_visible,
            unexpected_blocker_visible,
        }
    }

    /// Classifies the page conservatively before any mailbox interaction.
    #[must_use]
    pub const fn surface(self) -> WebSurface {
        match self.auth_surface {
            AuthSurface::Challenge => {
                return WebSurface::AuthenticationChallenge;
            }
            AuthSurface::Login => return WebSurface::SignedOut,
            AuthSurface::None => {}
        }
        if self.unexpected_blocker_visible || !self.mail_shell_visible {
            return WebSurface::Incompatible;
        }
        if self.composer_visible {
            return WebSurface::Composer;
        }
        WebSurface::Mailbox
    }
}

/// Semantic mailbox control the browser driver may target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiTarget {
    /// Archive or unarchive control for selected messages.
    ArchiveControl,
    /// Attachment download or open control.
    AttachmentControl,
    /// Button that opens a new draft composer.
    ComposeButton,
    /// Button that discards the currently open draft.
    DiscardDraftControl,
    /// Draft body, subject, recipient, or attachment editor.
    DraftEditor,
    /// Label application or removal control.
    LabelControl,
    /// Mark-read or mark-unread control.
    MarkControl,
    /// Mailbox or label navigation control.
    MailboxNavigation,
    /// Message or thread row/open control.
    MessageNavigation,
    /// Move-to-folder control.
    MoveControl,
    /// Passive mailbox observation target used for change waiting.
    ObserveMailbox,
    /// Search input or search-submit control.
    SearchControl,
    /// Send button in an authenticated composer.
    SendButton,
    /// Trash or restore control.
    TrashControl,
}

impl UiTarget {
    /// Returns every UI target the adapter is allowed to request.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &ALL_UI_TARGETS
    }

    /// Stable diagnostic-only target name; never a DOM selector.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ArchiveControl => "archive_control",
            Self::AttachmentControl => "attachment_control",
            Self::ComposeButton => "compose_button",
            Self::DiscardDraftControl => "discard_draft_control",
            Self::DraftEditor => "draft_editor",
            Self::LabelControl => "label_control",
            Self::MarkControl => "mark_control",
            Self::MailboxNavigation => "mailbox_navigation",
            Self::MessageNavigation => "message_navigation",
            Self::MoveControl => "move_control",
            Self::ObserveMailbox => "observe_mailbox",
            Self::SearchControl => "search_control",
            Self::SendButton => "send_button",
            Self::TrashControl => "trash_control",
        }
    }

    const fn safety(self) -> SafetyClass {
        match self {
            Self::AttachmentControl
            | Self::MailboxNavigation
            | Self::MessageNavigation
            | Self::ObserveMailbox
            | Self::SearchControl => SafetyClass::ReadOnly,
            Self::ArchiveControl
            | Self::ComposeButton
            | Self::DiscardDraftControl
            | Self::DraftEditor
            | Self::LabelControl
            | Self::MarkControl
            | Self::MoveControl
            | Self::TrashControl => SafetyClass::Reversible,
            Self::SendButton => SafetyClass::ExternalSideEffect,
        }
    }

    fn supports(self, capability: Capability) -> bool {
        let name = capability.name();
        match self {
            Self::ArchiveControl => matches!(name, "archive" | "unarchive"),
            Self::AttachmentControl => name == "get_attachment",
            Self::ComposeButton => name == "create_draft",
            Self::DiscardDraftControl => name == "discard_draft",
            Self::DraftEditor => {
                matches!(name, "create_draft" | "update_draft")
            }
            Self::LabelControl => {
                matches!(name, "apply_labels" | "remove_labels")
            }
            Self::MarkControl => matches!(name, "mark_read" | "mark_unread"),
            Self::MailboxNavigation => BOX_CAPS.contains(&name),
            Self::MessageNavigation => MESSAGE_NAV_CAPS.contains(&name),
            Self::MoveControl => name == "move_messages",
            Self::ObserveMailbox => name == "wait_for_changes",
            Self::SearchControl => {
                matches!(name, "search_messages" | "search_threads")
            }
            Self::SendButton => {
                matches!(name, "send_draft" | "reply" | "reply_all" | "forward")
            }
            Self::TrashControl => {
                matches!(name, "trash_messages" | "restore_messages")
            }
        }
    }

    const fn required_surface(self) -> WebSurface {
        if matches!(
            self,
            Self::DiscardDraftControl | Self::DraftEditor | Self::SendButton
        ) {
            WebSurface::Composer
        } else {
            WebSurface::Mailbox
        }
    }

    const fn surface_allows(self, view: WebSurface) -> bool {
        matches!(
            (self.required_surface(), view),
            (WebSurface::Composer, WebSurface::Composer)
                | (WebSurface::Mailbox, WebSurface::Mailbox)
        )
    }
}

const ALL_UI_TARGETS: [UiTarget; 14] = [
    UiTarget::ArchiveControl,
    UiTarget::AttachmentControl,
    UiTarget::ComposeButton,
    UiTarget::DiscardDraftControl,
    UiTarget::DraftEditor,
    UiTarget::LabelControl,
    UiTarget::MarkControl,
    UiTarget::MailboxNavigation,
    UiTarget::MessageNavigation,
    UiTarget::MoveControl,
    UiTarget::ObserveMailbox,
    UiTarget::SearchControl,
    UiTarget::SendButton,
    UiTarget::TrashControl,
];

/// Reason a semantic UI target was rejected before browser interaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiGateError {
    /// A human-owned authentication challenge is visible.
    AuthenticationChallenge,
    /// The user must complete visible Proton login first.
    AuthenticationRequired,
    /// Capability and UI target have different side-effect classes.
    SafetyMismatch,
    /// The requested target is not valid for this specific capability.
    TargetMismatch,
    /// The current page surface cannot safely host this target.
    SurfaceMismatch,
    /// The caller did not provide the grant required by the capability.
    Unauthorized,
    /// Required Mail UI evidence is missing or an unknown blocker is visible.
    ProviderShapeMismatch,
}

/// Authorizes one semantic UI target immediately before browser interaction.
///
/// # Errors
///
/// Fails closed for login/challenge pages, provider-shape drift, wrong surface,
/// wrong target, mismatched side-effect class, or insufficient authority.
pub fn authorize_ui_target(
    evidence: UiEvidence,
    capability: Capability,
    grant: ActionGrant,
    target: UiTarget,
) -> Result<(), UiGateError> {
    let surface = evidence.surface();
    match surface {
        WebSurface::AuthenticationChallenge => {
            return Err(UiGateError::AuthenticationChallenge);
        }
        WebSurface::SignedOut => {
            return Err(UiGateError::AuthenticationRequired);
        }
        WebSurface::Incompatible => {
            return Err(UiGateError::ProviderShapeMismatch);
        }
        WebSurface::Composer | WebSurface::Mailbox => {}
    }
    if target.safety() != capability.safety() {
        return Err(UiGateError::SafetyMismatch);
    }
    if !target.supports(capability) {
        return Err(UiGateError::TargetMismatch);
    }
    if !capability.safety().authorizes(grant) {
        return Err(UiGateError::Unauthorized);
    }
    if !target.surface_allows(surface) {
        return Err(UiGateError::SurfaceMismatch);
    }
    Ok(())
}
