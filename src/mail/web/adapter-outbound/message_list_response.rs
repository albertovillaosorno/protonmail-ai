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
//   - Narrow projection of Proton Mail message-list HTTP response metadata.
// - Must-Not:
//   - Retain message subjects, addresses, bodies, request headers, or tokens.
// - Allows:
//   - Validate the exact read-only list endpoint and project ID, Time, Order.
// - Split-When:
//   - Provider response capture and provider-neutral pagination diverge.
// - Merge-When:
//   - A complete read adapter owns response projection directly.
// - Summary:
//   - Minimizes observed message-list responses to pagination metadata.
// - Description:
//   - Rejects non-GET/non-list traffic and malformed or duplicate metadata.
// - Usage:
//   - CDP Network observation validates traffic before projecting its body.
// - Defaults:
//   - Exact same-origin list endpoint only; unrelated responses are rejected.
//

//! Content-minimizing projection of Proton Mail message-list responses.

use std::collections::BTreeSet;
use std::fmt;

use serde_json::Value;

// jig-ignore-next-line: canonical rustfmt line.
const MESSAGE_LIST_URL_PREFIX: &str = concat!("https://mail.proton.me/api/", "mail/v4/messages");
const MAX_MESSAGE_LIST_BODY_BYTES: usize = 1_048_576;
const MAX_MESSAGE_LIST_ITEMS: usize = 100;

/// One metadata row projected from the provider's message-list response.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedMessageMetadata {
    id: String,
    time: u64,
    order: i64,
}

impl ObservedMessageMetadata {
    /// Returns the provider message identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns provider numeric `Time` without assigning contract semantics.
    #[must_use]
    pub const fn time(&self) -> u64 {
        self.time
    }

    /// Returns the provider-private ordering value observed in the response.
    #[must_use]
    pub const fn order(&self) -> i64 {
        self.order
    }
}

impl fmt::Debug for ObservedMessageMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedMessageMetadata")
            .field("id", &"<redacted>")
            .field("time", &"<redacted>")
            .field("order", &"<redacted>")
            .finish()
    }
}

/// Safe projection of one Proton Mail message-list HTTP response.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedMessageListResponse {
    total: u64,
    messages: Vec<ObservedMessageMetadata>,
}

impl ObservedMessageListResponse {
    /// Validates a network response and projects only pagination metadata.
    ///
    /// # Errors
    ///
    /// Rejects methods other than `GET`, non-list URLs, oversized bodies,
    /// malformed JSON, more than 100 rows, missing numeric metadata, or
    /// duplicate message IDs.
    // jig-ignore-next-line: canonical rustfmt line.
    pub fn parse(method: &str, url: &str, body: &str) -> Result<Self, MessageListResponseError> {
        if method != "GET" || !is_message_list_url(url) {
            return Err(MessageListResponseError::UnexpectedEndpoint);
        }
        if body.len() > MAX_MESSAGE_LIST_BODY_BYTES {
            return Err(MessageListResponseError::BodyTooLarge);
        }
        let value: Value =
    // jig-ignore-next-line: canonical rustfmt line.
            serde_json::from_str(body).map_err(|_error| MessageListResponseError::Malformed)?;
        let total = value
            .get("Total")
            .and_then(Value::as_u64)
            .ok_or(MessageListResponseError::Malformed)?;
        let messages = value
            .get("Messages")
            .and_then(Value::as_array)
            .ok_or(MessageListResponseError::Malformed)?;
        if messages.len() > MAX_MESSAGE_LIST_ITEMS {
            return Err(MessageListResponseError::TooManyMessages);
        }

        let mut ids = BTreeSet::new();
        let mut projected = Vec::with_capacity(messages.len());
        for message in messages {
            let id = message
                .get("ID")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or(MessageListResponseError::Malformed)?;
            let time = message
                .get("Time")
                .and_then(Value::as_u64)
                .ok_or(MessageListResponseError::Malformed)?;
            let order = message
                .get("Order")
                .and_then(Value::as_i64)
                .ok_or(MessageListResponseError::Malformed)?;
            if !ids.insert(id) {
                return Err(MessageListResponseError::DuplicateMessageId);
            }
            projected.push(ObservedMessageMetadata {
                id: String::from(id),
                time,
                order,
            });
        }

        Ok(Self {
            total,
            messages: projected,
        })
    }

    /// Returns the provider-reported total for the first list batch.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.total
    }

    /// Returns the projected message metadata in provider response order.
    #[must_use]
    pub fn messages(&self) -> &[ObservedMessageMetadata] {
        &self.messages
    }
}

impl fmt::Debug for ObservedMessageListResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedMessageListResponse")
            .field("total", &"<redacted>")
            .field("message_count", &self.messages.len())
            .finish()
    }
}

/// Why a captured response cannot be treated as message-list metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageListResponseError {
    /// HTTP method or URL is not the exact read-only message-list endpoint.
    UnexpectedEndpoint,
    /// Response body exceeds the bounded parser input size.
    BodyTooLarge,
    /// JSON shape or required metadata is malformed.
    Malformed,
    /// Response contains more rows than the adapter's maximum page size.
    TooManyMessages,
    /// Response repeats a provider message identifier.
    DuplicateMessageId,
}

fn is_message_list_url(url: &str) -> bool {
    let Some(remainder) = url.strip_prefix(MESSAGE_LIST_URL_PREFIX) else {
        return false;
    };
    remainder.is_empty() || remainder.starts_with('?')
}
