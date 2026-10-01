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
const MAX_MESSAGE_LIST_ITEMS: usize = 100;
const MAX_TRACKED_MESSAGE_LIST_REQUESTS: usize = 128;
const MAX_VISIBLE_MESSAGE_METADATA: usize = 200;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NetworkRequestState {
    Requested,
    Responded,
    Finished,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MessageListRequestKind {
    Initial,
    Continuation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TrackedMessageListRequest {
    state: NetworkRequestState,
    kind: MessageListRequestKind,
    limit: usize,
}

/// Bounded CDP Network event state for exact message-list GET requests.
#[derive(Clone, Eq, PartialEq)]
pub struct MessageListNetworkCapture {
    session_id: String,
    requests: BTreeMap<String, TrackedMessageListRequest>,
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
        self.take_finished_requests()
            .into_iter()
            .map(|(request_id, _continuation, _limit)| request_id)
            .collect()
    }

    /// Returns the number of matching requests whose lifecycle is retained.
    #[must_use]
    pub(crate) fn tracked_request_count(&self) -> usize {
        self.requests.len()
    }

    /// Removes completed batches as `(request_id, continuation, limit)` tuples.
    ///
    /// The tuple deliberately excludes the original URL and all request
    /// headers. `continuation` is true only for the proven anchor-shaped batch.
    // jig-ignore-next-line: canonical rustfmt line.
    pub(crate) fn take_finished_requests(&mut self) -> Vec<(String, bool, usize)> {
        let finished = self
            .requests
            .iter()
            // jig-ignore-next-line: canonical rustfmt line.
            .filter(|(_id, request)| request.state == NetworkRequestState::Finished)
            .map(|(id, request)| {
                (
                    id.clone(),
                    request.kind == MessageListRequestKind::Continuation,
                    request.limit,
                )
            })
            .collect::<Vec<_>>();
        self.requests
            // jig-ignore-next-line: canonical rustfmt line.
            .retain(|_id, request| request.state != NetworkRequestState::Finished);
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
        let Some((kind, limit)) = message_list_request_shape(url)? else {
            return Ok(());
        };
        if self.requests.len() >= MAX_TRACKED_MESSAGE_LIST_REQUESTS {
            return Err(MessageListNetworkError::CapacityExceeded);
        }
        self.requests.insert(
            String::from(request_id),
            TrackedMessageListRequest {
                state: NetworkRequestState::Requested,
                kind,
                limit,
            },
        );
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
        let Some(request) = self.requests.get_mut(request_id) else {
            return Ok(());
        };
        if request.state != NetworkRequestState::Requested {
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
        request.state = NetworkRequestState::Responded;
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_finished(&mut self, event: &Value) -> Result<(), MessageListNetworkError> {
        let request_id = network_request_id(event)?;
        let Some(request) = self.requests.get_mut(request_id) else {
            return Ok(());
        };
        if request.state != NetworkRequestState::Responded {
            return Err(MessageListNetworkError::InvalidSequence);
        }
        request.state = NetworkRequestState::Finished;
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

fn message_list_request_shape(
    url: &str,
) -> Result<Option<(MessageListRequestKind, usize)>, MessageListNetworkError> {
    let Some(raw_limit) = numeric_query_parameter(url, "Limit")? else {
        return Ok(None);
    };
    let maximum = u64::try_from(MAX_MESSAGE_LIST_ITEMS)
        .map_err(|_error| MessageListNetworkError::MalformedEvent)?;
    if raw_limit == 0 || raw_limit > maximum {
        return Err(MessageListNetworkError::MalformedEvent);
    }
    let limit =
        // jig-ignore-next-line: canonical rustfmt line.
        usize::try_from(raw_limit).map_err(|_error| MessageListNetworkError::MalformedEvent)?;
    let page = numeric_query_parameter(url, "Page")?;
    let page_size = numeric_query_parameter(url, "PageSize")?;
    let anchor = query_parameter_present(url, "Anchor")?;
    let anchor_id = query_parameter_present(url, "AnchorID")?;
    let kind = match (page, page_size, anchor, anchor_id) {
        (Some(_page), Some(size), false, false) if size == raw_limit => {
            MessageListRequestKind::Initial
        }
        (None, None, true, true) => MessageListRequestKind::Continuation,
        _ => return Ok(None),
    };
    Ok(Some((kind, limit)))
}

// jig-ignore-next-line: canonical rustfmt line.
fn numeric_query_parameter(url: &str, name: &str) -> Result<Option<u64>, MessageListNetworkError> {
    let Some(value) = raw_query_parameter(url, name)? else {
        return Ok(None);
    };
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|_error| MessageListNetworkError::MalformedEvent)
}

// jig-ignore-next-line: canonical rustfmt line.
fn query_parameter_present(url: &str, name: &str) -> Result<bool, MessageListNetworkError> {
    Ok(raw_query_parameter(url, name)?.is_some_and(|value| !value.is_empty()))
}

fn raw_query_parameter<'url>(
    url: &'url str,
    name: &str,
) -> Result<Option<&'url str>, MessageListNetworkError> {
    let Some((_path, query)) = url.split_once('?') else {
        return Ok(None);
    };
    let query = query.split('#').next().unwrap_or(query);
    let mut found = None;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key != name {
            continue;
        }
        if found.replace(value).is_some() {
            return Err(MessageListNetworkError::MalformedEvent);
        }
    }
    Ok(found)
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
    pub(crate) const MAX_BODY_BYTES: usize = 262_144;

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
        if body.len() > Self::MAX_BODY_BYTES {
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

    /// Projects one `Network.getResponseBody` result after endpoint proof.
    ///
    /// The caller must first verify the request lifecycle with
    /// [`MessageListNetworkCapture`]. This parser rejects base64 envelopes so
    /// only Chromium's decoded JSON text can cross the projection boundary.
    ///
    /// # Errors
    ///
    /// Rejects malformed CDP envelopes, base64 bodies, or any invalid list
    /// response accepted by [`Self::parse`].
    // jig-ignore-next-line: canonical rustfmt line.
    pub fn parse_cdp_body(result: &Value) -> Result<Self, MessageListResponseError> {
        let encoded = result
            .get("base64Encoded")
            .and_then(Value::as_bool)
            .ok_or(MessageListResponseError::Malformed)?;
        if encoded {
            return Err(MessageListResponseError::UnsupportedEncoding);
        }
        let body = result
            .get("body")
            .and_then(Value::as_str)
            .ok_or(MessageListResponseError::Malformed)?;
        Self::parse("GET", MESSAGE_LIST_URL_PREFIX, body)
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

/// Machine-readable metadata reconciled to stable visible message IDs.
#[derive(Clone, Eq, PartialEq)]
pub struct ReconciledVisibleMessageMetadata {
    messages: Vec<ObservedMessageMetadata>,
}

impl ReconciledVisibleMessageMetadata {
    /// Reconciles one stable visible ID sequence against observed list batches.
    ///
    /// Extra observed IDs are allowed because `WebClients` may prefetch beyond
    /// the rendered rows. Every visible ID must occur exactly once across all
    /// batches, and observed batches themselves may not overlap by ID.
    ///
    /// # Errors
    ///
    /// Rejects too many visible IDs, duplicate visible IDs, duplicate observed
    /// IDs across batches, missing visible metadata, or metadata returned for
    /// an explicitly empty visible page.
    pub fn reconcile(
        visible_ids: &[&str],
        responses: &[ObservedMessageListResponse],
    ) -> Result<Self, MessageListReconciliationError> {
        if visible_ids.len() > MAX_VISIBLE_MESSAGE_METADATA {
            return Err(MessageListReconciliationError::TooManyVisibleMessages);
        }
        let mut observed = BTreeMap::new();
        for response in responses {
            for message in response.messages() {
                if observed.insert(message.id(), message).is_some() {
                    // jig-ignore-next-line: canonical rustfmt line.
                    return Err(MessageListReconciliationError::DuplicateObservedId);
                }
            }
        }
        if visible_ids.is_empty() {
            if observed.is_empty() {
                return Ok(Self {
                    messages: Vec::new(),
                });
            }
            // jig-ignore-next-line: canonical rustfmt line.
            return Err(MessageListReconciliationError::UnexpectedObservedMessage);
        }

        let mut visible = BTreeSet::new();
        for id in visible_ids {
            if id.is_empty() || !visible.insert(*id) {
                return Err(MessageListReconciliationError::DuplicateVisibleId);
            }
        }
        let mut messages = Vec::with_capacity(visible_ids.len());
        for id in visible_ids {
            let message = observed
                .get(id)
                .ok_or(MessageListReconciliationError::MissingVisibleMessage)?;
            messages.push((*message).clone());
        }
        Ok(Self { messages })
    }

    /// Returns reconciled metadata in the exact stable visible-row order.
    #[must_use]
    pub fn messages(&self) -> &[ObservedMessageMetadata] {
        &self.messages
    }
}

impl fmt::Debug for ReconciledVisibleMessageMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReconciledVisibleMessageMetadata")
            .field("message_count", &self.messages.len())
            .finish()
    }
}

/// Why observed list batches cannot prove metadata for stable visible rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageListReconciliationError {
    /// Stable visible evidence contains too many message IDs.
    TooManyVisibleMessages,
    /// Stable visible evidence repeats or contains an empty message ID.
    DuplicateVisibleId,
    /// Two observed provider batches overlap on the same message ID.
    DuplicateObservedId,
    /// A stable visible message ID has no observed machine metadata.
    MissingVisibleMessage,
    /// An explicitly empty stable page conflicts with observed message data.
    UnexpectedObservedMessage,
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
    /// CDP returned an encoded body instead of decoded JSON text.
    UnsupportedEncoding,
}

fn is_message_list_url(url: &str) -> bool {
    let Some(remainder) = url.strip_prefix(MESSAGE_LIST_URL_PREFIX) else {
        return false;
    };
    remainder.is_empty() || remainder.starts_with('?')
}
