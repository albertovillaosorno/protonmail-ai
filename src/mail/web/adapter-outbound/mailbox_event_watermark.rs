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
//   - Content-minimizing projection of legacy Mail core event-loop responses.
// - Must-Not:
//   - Retain message, conversation, count, header, cookie, or body content.
// - Allows:
//   - Retain bounded opaque event watermarks and change-presence booleans.
// - Split-When:
//   - Event-cursor traversal becomes a complete mailbox-events capability.
// - Merge-When:
//   - Public snapshot pagination owns event-boundary proof directly.
// - Summary:
//   - Reduces observed Mail event polls to safe snapshot-research evidence.
// - Description:
//   - Validates exact core-v5 event GETs and discards event payload contents.
// - Usage:
//   - Passive CDP observation may project a completed event response body.
// - Defaults:
//   - Projection alone does not prove list snapshot isolation.
//

//! Content-minimizing projection of Proton Mail's legacy core event loop.

use std::fmt;

use serde_json::Value;

// jig-ignore-next-line: canonical rustfmt line.
const CORE_EVENT_URL_PREFIX: &str = concat!("https://mail.proton.me/api/", "core/v5/events/");
const MAX_EVENT_BODY_BYTES: usize = 262_144;
const MAX_EVENT_ID_BYTES: usize = 512;

/// Sanitized evidence from one completed Mail core-event poll.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedMailboxEventWatermark {
    requested_event_id: String,
    response_event_id: String,
    more: bool,
    refresh: bool,
    mailbox_changes: bool,
}

impl ObservedMailboxEventWatermark {
    /// Validates one exact core-v5 event response and projects only safe state.
    ///
    /// # Errors
    ///
    /// Rejects non-GET traffic, non-Mail core-event endpoints, oversized or
    /// malformed bodies, invalid watermarks, and malformed event collections.
    // jig-ignore-next-line: canonical rustfmt line.
    pub fn parse(method: &str, url: &str, body: &str) -> Result<Self, MailboxEventWatermarkError> {
        if method != "GET" {
            return Err(MailboxEventWatermarkError::UnexpectedEndpoint);
        }
        let requested_event_id = event_id_from_url(url)?;
        if body.len() > MAX_EVENT_BODY_BYTES {
            return Err(MailboxEventWatermarkError::BodyTooLarge);
        }
        let value: Value =
            // jig-ignore-next-line: canonical rustfmt line.
            serde_json::from_str(body).map_err(|_error| MailboxEventWatermarkError::Malformed)?;
        let response_event_id = value
            .get("EventID")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty() && id.len() <= MAX_EVENT_ID_BYTES)
            .ok_or(MailboxEventWatermarkError::Malformed)?;
        let more = match value.get("More").and_then(Value::as_u64) {
            Some(0) => false,
            Some(1) => true,
            _ => return Err(MailboxEventWatermarkError::Malformed),
        };
        let refresh = match value.get("Refresh") {
            None | Some(Value::Null) => false,
            Some(refresh) => refresh
                .as_u64()
                .map(|code| code != 0)
                .ok_or(MailboxEventWatermarkError::Malformed)?,
        };
        let mailbox_changes = [
            "Messages",
            "Conversations",
            "MessageCounts",
            "ConversationCounts",
        ]
        .into_iter()
        .try_fold(false, |changed, key| {
            Ok(changed || event_collection_nonempty(&value, key)?)
        })?;
        Ok(Self {
            requested_event_id: String::from(requested_event_id),
            response_event_id: String::from(response_event_id),
            more,
            refresh,
            mailbox_changes,
        })
    }

    /// Returns true only after the provider says no event pages remain.
    #[must_use]
    pub const fn settled(&self) -> bool {
        !self.more && !self.refresh
    }

    /// Returns whether this response contains mailbox-list change signals.
    #[must_use]
    pub const fn mailbox_changes(&self) -> bool {
        self.mailbox_changes
    }

    /// Returns whether response and requested watermarks are identical.
    #[must_use]
    pub fn unchanged_watermark(&self) -> bool {
        self.requested_event_id == self.response_event_id
    }

    /// Returns the bounded opaque response event watermark.
    #[must_use]
    pub fn response_event_id(&self) -> &str {
        &self.response_event_id
    }
}

impl fmt::Debug for ObservedMailboxEventWatermark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedMailboxEventWatermark")
            .field("requested_event_id", &"<redacted>")
            .field("response_event_id", &"<redacted>")
            .field("more", &self.more)
            .field("refresh", &self.refresh)
            .field("mailbox_changes", &self.mailbox_changes)
            .finish()
    }
}

/// Fail-closed event-watermark projection errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxEventWatermarkError {
    /// Request was not the exact read-only legacy core-event endpoint.
    UnexpectedEndpoint,
    /// Event response exceeded the bounded observation body size.
    BodyTooLarge,
    /// Event metadata shape was missing or invalid.
    Malformed,
}

fn event_id_from_url(url: &str) -> Result<&str, MailboxEventWatermarkError> {
    if url.contains('#') {
        return Err(MailboxEventWatermarkError::UnexpectedEndpoint);
    }
    let path = url.split_once('?').map_or(url, |(path, _query)| path);
    let Some(event_id) = path.strip_prefix(CORE_EVENT_URL_PREFIX) else {
        return Err(MailboxEventWatermarkError::UnexpectedEndpoint);
    };
    // jig-ignore-next-line: canonical rustfmt line.
    if event_id.is_empty() || event_id.len() > MAX_EVENT_ID_BYTES || event_id.contains('/') {
        return Err(MailboxEventWatermarkError::UnexpectedEndpoint);
    }
    Ok(event_id)
}

// jig-ignore-next-line: canonical rustfmt line.
fn event_collection_nonempty(value: &Value, key: &str) -> Result<bool, MailboxEventWatermarkError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Array(items)) => Ok(!items.is_empty()),
        Some(_) => Err(MailboxEventWatermarkError::Malformed),
    }
}
