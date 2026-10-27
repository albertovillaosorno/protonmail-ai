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
//   - Content-free proof of externally forced Proton Mail list mode.
// - Must-Not:
//   - Return URL text, settings/store state, row IDs, or mailbox content.
// - Allows:
//   - Prove message mode from provider route/hash rules inside the browser.
// - Split-When:
//   - A stable externally observable conversation-mode signal is accepted.
// - Merge-When:
//   - Mailbox read projection owns location-mode proof directly.
// - Summary:
//   - Reduces visible location rules to non-content message-mode booleans.
// - Description:
//   - Recognizes always-message routes and active searches before CDP return.
// - Usage:
//   - Message-page reads require proof before and after content projection.
// - Defaults:
//   - Any malformed, contradictory, or non-forced state is unknown/fail-closed.
//

//! Content-free visible-location proof for Proton Mail message mode.

use std::fmt;

use serde_json::Value;

const MAILBOX_MODE_EXPRESSION: &str = concat!(
    "(() => {",
    "if(location.origin!=='https://mail.proton.me'){return null;}",
    "if(document.querySelector('input[type=\"password\"],",
    "input[autocomplete=\"one-time-code\"]')){return null;}",
    "if(document.querySelector('[role=\"dialog\"],",
    "[role=\"alertdialog\"]')){return null;}",
    "if(location.pathname.length>512||",
    "location.pathname.includes('//')){return null;}",
    "const parts=location.pathname.split('/').filter(Boolean);",
    "const account=parts[1]||'';",
    "const scoped=parts[0]==='u';",
    "const exactScope=parts.length===3&&account.length<=10&&",
    "/^(0|[1-9]\\d*)$/.test(account);",
    "const validRoute=scoped?exactScope:parts.length===1;",
    "if(!validRoute){return null;}",
    "const route=scoped?parts[2]:parts[0];",
    "const forced=['drafts','all-drafts','sent','all-sent','deleted']",
    ".includes(route);",
    "const searchable=forced||['inbox','archive','spam','starred',",
    "'all-mail','search'].includes(route);",
    "const raw=location.hash.startsWith('#')?location.hash.slice(1):'';",
    "if(raw.length>8192||/%(?![0-9a-fA-F]{2})/.test(raw)){return null;}",
    "const params=new URLSearchParams(raw);",
    "const strings=['address','from','keyword','to'];",
    "const numbers=['begin','end','wildcard'];",
    "const duplicate=[...strings,...numbers].some(",
    "(key)=>params.getAll(key).length>1);",
    "const text=strings.some((key)=>{const value=params.get(key);",
    "return !!value&&value.length<=2048&&value.trim().length>0&&",
    "[...value].every((c)=>c.codePointAt(0)>=32&&",
    "c.codePointAt(0)!==127&&c.codePointAt(0)!==65533);});",
    "const numeric=numbers.some((key)=>{const value=params.get(key);",
    "if(!value||value.length>20||!/^\\d+$/.test(value)){return false;}",
    "if(value.length>1&&value.startsWith('0')){return false;}",
    "const parsed=Number(value);",
    "return Number.isSafeInteger(parsed)&&parsed>0;});",
    "return {forcedMessageRoute:forced,",
    "activeSearch:searchable&&!duplicate&&(text||numeric)};",
    "})()"
);

/// Provider-render mode that can be proven without private application state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxRenderMode {
    /// `WebClients` rules prove that visible rows are individual messages.
    Messages,
    /// Observable provider rules do not prove message-versus-conversation mode.
    Unknown,
}

/// Content-free mode evidence reduced inside the browser execution context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MailboxModeEvidence {
    mode: MailboxRenderMode,
}

/// Fail-closed visible-location classification error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxModeError {
    /// Provider returned malformed mode evidence.
    InvalidEvidence,
}

impl fmt::Display for MailboxModeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEvidence => f.write_str("invalid mode evidence"),
        }
    }
}

impl MailboxModeEvidence {
    /// Reduces provider-owned non-content signals to one conservative mode.
    #[must_use]
    pub const fn from_signals(forced: bool, search: bool) -> Self {
        let mode = if forced || search {
            MailboxRenderMode::Messages
        } else {
            MailboxRenderMode::Unknown
        };
        Self { mode }
    }

    /// Returns the externally proven render mode.
    #[must_use]
    pub const fn mode(self) -> MailboxRenderMode {
        self.mode
    }

    pub(crate) const fn expression() -> &'static str {
        MAILBOX_MODE_EXPRESSION
    }

    pub(crate) fn from_value(value: &Value) -> Result<Self, MailboxModeError> {
        // The audited script projects exactly two non-content booleans.
        if value.as_object().is_none_or(|fields| fields.len() != 2) {
            return Err(MailboxModeError::InvalidEvidence);
        }
        let forced = value
            .get("forcedMessageRoute")
            .and_then(Value::as_bool)
            .ok_or(MailboxModeError::InvalidEvidence)?;
        let search = value
            .get("activeSearch")
            .and_then(Value::as_bool)
            .ok_or(MailboxModeError::InvalidEvidence)?;
        Ok(Self::from_signals(forced, search))
    }
}
