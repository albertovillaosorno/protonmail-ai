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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde_json::Value;

// jig-ignore-next-line: canonical rustfmt line.
const MESSAGE_LIST_URL_PREFIX: &str = concat!("https://mail.proton.me/api/", "mail/v4/messages");
const MAX_MESSAGE_LIST_BODY_BYTES: usize = 1_048_576;
const MAX_MESSAGE_LIST_ITEMS: usize = 100;
const MAX_TRACKED_MESSAGE_LIST_REQUESTS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NetworkRequestState {
    Requested,
    Responded,
    Finished,
}

/// Bounded CDP Network event state for exact message-list GET requests.
#[derive(Clone, Eq, PartialEq)]
pub struct MessageListNetworkCapture {
    session_id: String,
    requests: BTreeMap<String, NetworkRequestState>,
}

impl MessageListNetworkCapture {
    /// Creates an empty capture scoped to one flattened CDP target session.
    #[must_use]
    pub fn new(session_id: &str) -> Self {
        Self {
            session_id: String::from(session_id),
            requests: BTreeMap::new(),
        }
    }

    /// Consumes one unsolicited CDP event without retaining request content.
    ///
    /// Events from other target sessions are ignored before their request
    // jig-ignore-next-line: canonical rustfmt line.
    /// fields are inspected. Only exact `GET` message-list requests are tracked.
    ///
    /// # Errors
    ///
    /// Returns an error when a tracked request redirects, fails, has a non-200
    /// JSON response, repeats a lifecycle event, or arrives out of sequence.
    // jig-ignore-next-line: canonical rustfmt line.
    pub fn observe(&mut self, event: &Value) -> Result<(), MessageListNetworkError> {
        // jig-ignore-next-line: canonical rustfmt line.
        if event.get("sessionId").and_then(Value::as_str) != Some(self.session_id.as_str()) {
            return Ok(());
        }
        let method = event.get("method").and_then(Value::as_str);
        match method {
            Some("Network.requestWillBeSent") => self.observe_request(event),
            Some("Network.responseReceived") => self.observe_response(event),
            Some("Network.loadingFinished") => self.observe_finished(event),
            Some("Network.loadingFailed") => self.observe_failed(event),
            _ => Ok(()),
        }
    }

    /// Removes and returns request IDs whose safe response lifecycle completed.
    pub fn take_finished_request_ids(&mut self) -> Vec<String> {
        let finished = self
            .requests
            .iter()
            .filter(|(_id, state)| **state == NetworkRequestState::Finished)
            .map(|(id, _state)| id.clone())
            .collect::<Vec<_>>();
        self.requests
            .retain(|_id, state| *state != NetworkRequestState::Finished);
        finished
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_request(&mut self, event: &Value) -> Result<(), MessageListNetworkError> {
        let params = event
            .get("params")
            .ok_or(MessageListNetworkError::MalformedEvent)?;
        let request_id = params
            .get("requestId")
            .and_then(Value::as_str)
            .ok_or(MessageListNetworkError::MalformedEvent)?;
        let request = params
            .get("request")
            .ok_or(MessageListNetworkError::MalformedEvent)?;
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or(MessageListNetworkError::MalformedEvent)?;
        let url = request
            .get("url")
            .and_then(Value::as_str)
            .ok_or(MessageListNetworkError::MalformedEvent)?;
        let tracked = self.requests.contains_key(request_id);
        let message_list_get = method == "GET" && is_message_list_url(url);
        if tracked && !message_list_get {
            return Err(MessageListNetworkError::RedirectedAway);
        }
        if !message_list_get {
            return Ok(());
        }
        if tracked {
            return Err(MessageListNetworkError::InvalidSequence);
        }
        if self.requests.len() >= MAX_TRACKED_MESSAGE_LIST_REQUESTS {
            return Err(MessageListNetworkError::CapacityExceeded);
        }
        self.requests
            .insert(String::from(request_id), NetworkRequestState::Requested);
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_response(&mut self, event: &Value) -> Result<(), MessageListNetworkError> {
        let params = event
            .get("params")
            .ok_or(MessageListNetworkError::MalformedEvent)?;
        let request_id = params
            .get("requestId")
            .and_then(Value::as_str)
            .ok_or(MessageListNetworkError::MalformedEvent)?;
        let Some(state) = self.requests.get_mut(request_id) else {
            return Ok(());
        };
        if *state != NetworkRequestState::Requested {
            return Err(MessageListNetworkError::InvalidSequence);
        }
        let response = params
            .get("response")
            .ok_or(MessageListNetworkError::MalformedEvent)?;
        let url = response
            .get("url")
            .and_then(Value::as_str)
            .ok_or(MessageListNetworkError::MalformedEvent)?;
        let status = response.get("status").and_then(Value::as_u64);
        let mime = response.get("mimeType").and_then(Value::as_str);
        // jig-ignore-next-line: canonical rustfmt line.
        if !is_message_list_url(url) || status != Some(200) || mime != Some("application/json") {
            return Err(MessageListNetworkError::ResponseRejected);
        }
        *state = NetworkRequestState::Responded;
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_finished(&mut self, event: &Value) -> Result<(), MessageListNetworkError> {
        let request_id = network_request_id(event)?;
        let Some(state) = self.requests.get_mut(request_id) else {
            return Ok(());
        };
        if *state != NetworkRequestState::Responded {
            return Err(MessageListNetworkError::InvalidSequence);
        }
        *state = NetworkRequestState::Finished;
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_failed(&self, event: &Value) -> Result<(), MessageListNetworkError> {
        let request_id = network_request_id(event)?;
        if self.requests.contains_key(request_id) {
            return Err(MessageListNetworkError::RequestFailed);
        }
        Ok(())
    }
}

impl fmt::Debug for MessageListNetworkCapture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageListNetworkCapture")
            .field("session_id", &"<redacted>")
            .field("tracked_request_count", &self.requests.len())
            .finish()
    }
}

/// Why exact message-list CDP Network evidence failed closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageListNetworkError {
    /// Required event structure is missing or malformed.
    MalformedEvent,
    /// A tracked request redirected away from the exact safe endpoint.
    RedirectedAway,
    /// A tracked response is not HTTP 200 JSON.
    ResponseRejected,
    /// A tracked request reported `Network.loadingFailed`.
    RequestFailed,
    /// A tracked lifecycle event repeated or arrived out of order.
    InvalidSequence,
    /// Too many unfinished exact message-list requests are already tracked.
    CapacityExceeded,
}

fn network_request_id(event: &Value) -> Result<&str, MessageListNetworkError> {
    event
        .get("params")
        .and_then(|params| params.get("requestId"))
        .and_then(Value::as_str)
        .ok_or(MessageListNetworkError::MalformedEvent)
}

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
        let message_count =
        // jig-ignore-next-line: canonical rustfmt line.
            u64::try_from(messages.len()).map_err(|_error| MessageListResponseError::Malformed)?;
        if total < message_count {
            return Err(MessageListResponseError::Malformed);
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
