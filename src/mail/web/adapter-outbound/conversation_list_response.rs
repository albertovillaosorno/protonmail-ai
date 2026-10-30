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
//   - Narrow projection of Proton Mail conversation-list response metadata.
// - Must-Not:
//   - Retain subjects, participants, search terms, request headers, or tokens.
// - Allows:
//   - Validate exact list GET lifecycles and project bounded thread metadata.
// - Split-When:
//   - Provider-neutral thread pagination gains independently proven semantics.
// - Merge-When:
//   - One reviewed thread-list adapter owns projection and cursor semantics.
// - Summary:
//   - Minimizes observed conversation-list responses before public mapping.
// - Description:
//   - Binds request/response URL privately and drops content-bearing fields.
// - Usage:
//   - Browser diagnostics may consume this after app-owned list/search GETs.
// - Defaults:
//   - No snapshot/cursor claim; stale, active-task, or malformed data fails.
//

//! Content-minimizing projection of Proton Mail conversation-list responses.

use crate::strict_json;
use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::hash::BuildHasher as _;

use crate::driver::safe_cdp_request_id;
use crate::opaque_read_id::safe_read_id;
use serde_json::Value;
use zeroize::Zeroize as _;

// jig-ignore-next-line: canonical rustfmt line.
const CONVERSATION_LIST_URL_PREFIX: &str = "https://mail.proton.me/api/mail/v4/conversations";
const MAX_CONVERSATION_LIST_ITEMS: usize = 100;
const MAX_CONVERSATION_LIST_PAGE_SIZE: u16 = 100;
const MAX_CONVERSATION_ID_BYTES: usize = 512;
const MAX_TRACKED_CONVERSATION_LIST_REQUESTS: usize = 128;
const MAX_CONVERSATION_LIST_URL_BYTES: usize = 16_384;
const MAX_VISIBLE_CONVERSATIONS: usize = 200;

/// Redacted CDP request identity plus sanitized pagination evidence.
#[expect(
    clippy::redundant_pub_crate,
    reason = "shared private CDP tuple belongs to sibling driver module"
)]
// jig-ignore-next-line: four sanitized internal tuple fields are indivisible.
pub(crate) type CapturedConversationListRequest = (String, Option<u32>, bool, bool);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConversationListRequestState {
    Requested,
    Responded,
    Finished,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TrackedConversationListRequest {
    state: ConversationListRequestState,
    url_fingerprint: [u64; 2],
    requested_page: Option<u32>,
    anchor_continuation: bool,
    initial_page_shape: bool,
}

/// Bounded CDP lifecycle state for exact conversation-list GET requests.
pub struct ConversationListNetworkCapture {
    session_id: String,
    requests: BTreeMap<String, TrackedConversationListRequest>,
    completed_ids: BTreeSet<String>,
    hashers: [RandomState; 2],
}

impl ConversationListNetworkCapture {
    /// Creates an empty capture scoped to one flattened CDP target session.
    #[must_use]
    pub fn new(session_id: &str) -> Self {
        Self {
            session_id: String::from(session_id),
            requests: BTreeMap::new(),
            completed_ids: BTreeSet::new(),
            hashers: [RandomState::new(), RandomState::new()],
        }
    }

    /// Consumes one unsolicited CDP event without retaining URL/header content.
    ///
    /// # Errors
    ///
    /// Exact list requests fail closed on redirect, response URL drift,
    /// lifecycle failure, invalid response metadata, or capacity exhaustion.
    // jig-ignore-next-line: canonical rustfmt line.
    pub fn observe(&mut self, event: &Value) -> Result<(), ConversationListNetworkError> {
        // jig-ignore-next-line: canonical rustfmt line.
        if event.get("sessionId").and_then(Value::as_str) != Some(self.session_id.as_str()) {
            return Ok(());
        }
        match event.get("method").and_then(Value::as_str) {
            Some("Network.requestWillBeSent") => self.observe_request(event),
            Some("Network.responseReceived") => self.observe_response(event),
            Some("Network.loadingFinished") => self.observe_finished(event),
            Some("Network.loadingFailed") => self.observe_failed(event),
            _ => Ok(()),
        }
    }

    /// Removes completed exact list requests as request IDs only.
    pub fn take_finished_request_ids(&mut self) -> Vec<String> {
        self.take_finished_requests()
            .into_iter()
            .map(|(request_id, _page, _anchor, _initial)| request_id)
            .collect()
    }

    /// Removes completed requests with sanitized page and continuation flags.
    ///
    /// No URL, search query, label, or request-header text is retained.
    // jig-ignore-next-line: canonical rustfmt line.
    pub(crate) fn take_finished_requests(&mut self) -> Vec<CapturedConversationListRequest> {
        let finished = self
            .requests
            .iter()
            // jig-ignore-next-line: canonical rustfmt line.
            .filter(|(_id, request)| request.state == ConversationListRequestState::Finished)
            .map(|(request_id, request)| {
                (
                    request_id.clone(),
                    request.requested_page,
                    request.anchor_continuation,
                    request.initial_page_shape,
                )
            })
            .collect::<Vec<_>>();
        self.requests
            // jig-ignore-next-line: canonical rustfmt line.
            .retain(|_id, request| request.state != ConversationListRequestState::Finished);
        for (request_id, _page, _anchor, _initial) in &finished {
            self.completed_ids.insert(request_id.clone());
        }
        finished
    }

    /// Returns the number of matching request lifecycles still retained.
    #[must_use]
    pub fn tracked_request_count(&self) -> usize {
        self.requests.len()
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_request(&mut self, event: &Value) -> Result<(), ConversationListNetworkError> {
        let params = event
            .get("params")
            .ok_or(ConversationListNetworkError::MalformedEvent)?;
        let request_id = params
            .get("requestId")
            .and_then(Value::as_str)
            .ok_or(ConversationListNetworkError::MalformedEvent)?;
        let request = params
            .get("request")
            .ok_or(ConversationListNetworkError::MalformedEvent)?;
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or(ConversationListNetworkError::MalformedEvent)?;
        let url = request
            .get("url")
            .and_then(Value::as_str)
            .ok_or(ConversationListNetworkError::MalformedEvent)?;
        let exact_get = method == "GET" && is_conversation_list_url(url);
        if self.completed_ids.contains(request_id) {
            return Err(ConversationListNetworkError::InvalidSequence);
        }
        if self.requests.contains_key(request_id) {
            return if exact_get {
                Err(ConversationListNetworkError::InvalidSequence)
            } else {
                Err(ConversationListNetworkError::RedirectedAway)
            };
        }
        if !exact_get {
            return Ok(());
        }
        // A redirect may enter the exact endpoint from an ignored request.
        if params.get("redirectResponse").is_some() {
            return Err(ConversationListNetworkError::RedirectedAway);
        }
        let oversized_url = url.len() > MAX_CONVERSATION_LIST_URL_BYTES;
        if !safe_cdp_request_id(request_id) || oversized_url {
            return Err(ConversationListNetworkError::MalformedEvent);
        }
        if self.requests.len().saturating_add(self.completed_ids.len())
            >= MAX_TRACKED_CONVERSATION_LIST_REQUESTS
        {
            return Err(ConversationListNetworkError::CapacityExceeded);
        }
        let url_fingerprint = url_fingerprint(url, &self.hashers);
        // jig-ignore-next-line: canonical rustfmt line.
        let (requested_page, anchor_continuation, initial_page_shape) = parse_request_page(url)?;
        self.requests.insert(
            String::from(request_id),
            TrackedConversationListRequest {
                state: ConversationListRequestState::Requested,
                url_fingerprint,
                requested_page,
                anchor_continuation,
                initial_page_shape,
            },
        );
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_response(&mut self, event: &Value) -> Result<(), ConversationListNetworkError> {
        let params = event
            .get("params")
            .ok_or(ConversationListNetworkError::MalformedEvent)?;
        let request_id = params
            .get("requestId")
            .and_then(Value::as_str)
            .ok_or(ConversationListNetworkError::MalformedEvent)?;
        if self.completed_ids.contains(request_id) {
            return Err(ConversationListNetworkError::InvalidSequence);
        }
        let Some(request) = self.requests.get_mut(request_id) else {
            return Ok(());
        };
        if request.state != ConversationListRequestState::Requested {
            return Err(ConversationListNetworkError::InvalidSequence);
        }
        let response = params
            .get("response")
            .ok_or(ConversationListNetworkError::MalformedEvent)?;
        let url = response
            .get("url")
            .and_then(Value::as_str)
            .ok_or(ConversationListNetworkError::MalformedEvent)?;
        if url.len() > MAX_CONVERSATION_LIST_URL_BYTES {
            return Err(ConversationListNetworkError::ResponseRejected);
        }
        let status = response.get("status").and_then(Value::as_u64);
        let mime = response.get("mimeType").and_then(Value::as_str);
        if !is_conversation_list_url(url)
            || request.url_fingerprint != url_fingerprint(url, &self.hashers)
            || status != Some(200)
            || mime != Some("application/json")
        {
            return Err(ConversationListNetworkError::ResponseRejected);
        }
        request.state = ConversationListRequestState::Responded;
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_finished(&mut self, event: &Value) -> Result<(), ConversationListNetworkError> {
        let request_id = network_request_id(event)?;
        if self.completed_ids.contains(request_id) {
            return Err(ConversationListNetworkError::InvalidSequence);
        }
        let Some(request) = self.requests.get_mut(request_id) else {
            return Ok(());
        };
        if request.state != ConversationListRequestState::Responded {
            return Err(ConversationListNetworkError::InvalidSequence);
        }
        request.state = ConversationListRequestState::Finished;
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_failed(&self, event: &Value) -> Result<(), ConversationListNetworkError> {
        let request_id = network_request_id(event)?;
        if self.completed_ids.contains(request_id) {
            return Err(ConversationListNetworkError::InvalidSequence);
        }
        if let Some(request) = self.requests.get(request_id) {
            if request.state == ConversationListRequestState::Finished {
                return Err(ConversationListNetworkError::InvalidSequence);
            }
            return Err(ConversationListNetworkError::RequestFailed);
        }
        Ok(())
    }
}

impl fmt::Debug for ConversationListNetworkCapture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConversationListNetworkCapture")
            .field("session_id", &"<redacted>")
            .field("tracked_request_count", &self.requests.len())
            .field("completed_request_count", &self.completed_ids.len())
            .field("url_fingerprints", &"<redacted>")
            .field("hashers", &"<redacted>")
            .finish()
    }
}

/// Why exact conversation-list Network evidence failed closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationListNetworkError {
    /// Required CDP event structure was missing or malformed.
    MalformedEvent,
    /// A tracked request redirected away from the conversation-list endpoint.
    RedirectedAway,
    /// A response changed URL identity or was not HTTP 200 JSON.
    ResponseRejected,
    /// A tracked request reported `Network.loadingFailed`.
    RequestFailed,
    /// A lifecycle event repeated or arrived out of sequence.
    InvalidSequence,
    /// Too many unfinished exact conversation-list requests are retained.
    CapacityExceeded,
    /// Page/anchor request selectors are malformed or contradictory.
    InvalidPagination,
}

/// One content-minimized provider conversation-list row.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedConversationListMetadata {
    id: String,
    time: u64,
    order: i64,
    message_count: u64,
}

#[expect(
    clippy::missing_trait_methods,
    reason = "Drop is the explicit scrub-on-drop contract"
)]
impl Drop for ObservedConversationListMetadata {
    fn drop(&mut self) {
        self.id.zeroize();
    }
}

impl ObservedConversationListMetadata {
    /// Returns the opaque provider conversation ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns provider numeric `Time` without assigning public semantics.
    #[must_use]
    pub const fn time(&self) -> u64 {
        self.time
    }

    /// Returns provider-private order used only as diagnostic evidence.
    #[must_use]
    pub const fn order(&self) -> i64 {
        self.order
    }

    /// Returns the provider-reported message count for this conversation.
    #[must_use]
    pub const fn message_count(&self) -> u64 {
        self.message_count
    }
}

impl fmt::Debug for ObservedConversationListMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedConversationListMetadata")
            .field("id", &"<redacted>")
            .field("time", &"<redacted>")
            .field("order", &"<redacted>")
            .field("message_count", &self.message_count)
            .finish()
    }
}

/// One safe projection of an exact conversation-list response body.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedConversationListResponse {
    total: u64,
    conversations: Vec<ObservedConversationListMetadata>,
}

impl ObservedConversationListResponse {
    /// Maximum decoded JSON response accepted by this boundary.
    pub const MAX_BODY_BYTES: usize = 262_144;

    /// Parses exact fresh conversation-list metadata only.
    ///
    /// # Errors
    ///
    /// Rejects endpoint drift, stale/task-running state, oversized or malformed
    /// bodies, more than 100 rows, missing metadata, or duplicate IDs.
    pub fn parse(
        method: &str,
        url: &str,
        body: &str,
    ) -> Result<Self, ConversationListResponseError> {
        if method != "GET"
            || url.len() > MAX_CONVERSATION_LIST_URL_BYTES
            || !is_conversation_list_url(url)
        {
            return Err(ConversationListResponseError::UnexpectedEndpoint);
        }
        if body.len() > Self::MAX_BODY_BYTES {
            return Err(ConversationListResponseError::BodyTooLarge);
        }
        let value = strict_json::from_sensitive_slice(body.as_bytes())
            .map_err(|_error| ConversationListResponseError::Malformed)?;
        if value.get("Code").and_then(Value::as_u64) != Some(1000) {
            return Err(ConversationListResponseError::ProviderRejected);
        }
        let stale = value
            .get("Stale")
            .and_then(Value::as_u64)
            .ok_or(ConversationListResponseError::Malformed)?;
        if stale != 0 {
            return Err(ConversationListResponseError::StaleResponse);
        }
        validate_no_tasks_running(&value)?;
        let total = value
            .get("Total")
            .and_then(Value::as_u64)
            .ok_or(ConversationListResponseError::Malformed)?;
        let conversations = value
            .get("Conversations")
            .and_then(Value::as_array)
            .ok_or(ConversationListResponseError::Malformed)?;
        if conversations.len() > MAX_CONVERSATION_LIST_ITEMS {
            return Err(ConversationListResponseError::TooManyConversations);
        }
        let count = u64::try_from(conversations.len())
            .map_err(|_error| ConversationListResponseError::Malformed)?;
        if total < count {
            return Err(ConversationListResponseError::Malformed);
        }
        let mut ids = BTreeSet::new();
        let mut projected = Vec::with_capacity(conversations.len());
        for conversation in conversations {
            let id = conversation
                .get("ID")
                .and_then(Value::as_str)
                .filter(|id| safe_read_id(id, MAX_CONVERSATION_ID_BYTES))
                .ok_or(ConversationListResponseError::Malformed)?;
            if !ids.insert(id) {
                // jig-ignore-next-line: canonical rustfmt line.
                return Err(ConversationListResponseError::DuplicateConversationId);
            }
            let time = conversation
                .get("Time")
                .and_then(Value::as_u64)
                .ok_or(ConversationListResponseError::Malformed)?;
            let order = conversation
                .get("Order")
                .and_then(Value::as_i64)
                .ok_or(ConversationListResponseError::Malformed)?;
            let message_count = conversation
                .get("NumMessages")
                .and_then(Value::as_u64)
                .ok_or(ConversationListResponseError::Malformed)?;
            projected.push(ObservedConversationListMetadata {
                id: String::from(id),
                time,
                order,
                message_count,
            });
        }
        Ok(Self {
            total,
            conversations: projected,
        })
    }

    /// Projects one decoded `Network.getResponseBody` envelope.
    ///
    /// # Errors
    ///
    /// Rejects encoded envelopes and every invalid list response accepted by
    /// [`Self::parse`].
    // jig-ignore-next-line: canonical rustfmt line.
    pub fn parse_cdp_body(result: &Value) -> Result<Self, ConversationListResponseError> {
        // Only accept the exact decoded CDP envelope owned by our request.
        if result.as_object().is_none_or(|fields| fields.len() != 2) {
            return Err(ConversationListResponseError::Malformed);
        }
        let encoded = result
            .get("base64Encoded")
            .and_then(Value::as_bool)
            .ok_or(ConversationListResponseError::Malformed)?;
        if encoded {
            return Err(ConversationListResponseError::UnsupportedEncoding);
        }
        let body = result
            .get("body")
            .and_then(Value::as_str)
            .ok_or(ConversationListResponseError::Malformed)?;
        Self::parse("GET", CONVERSATION_LIST_URL_PREFIX, body)
    }

    /// Returns the provider-reported total for this list response.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.total
    }

    /// Returns content-minimized rows in provider response order.
    #[must_use]
    pub fn conversations(&self) -> &[ObservedConversationListMetadata] {
        &self.conversations
    }
}

impl fmt::Debug for ObservedConversationListResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedConversationListResponse")
            .field("total", &"<redacted>")
            .field("conversation_count", &self.conversations.len())
            .finish()
    }
}

/// A bounded diagnostic match between rendered IDs and response metadata.
///
/// Matching alone does not prove conversation render mode, a stable snapshot,
/// request-to-page association, or provider-neutral thread ordering.
#[derive(Clone, Eq, PartialEq)]
pub struct ReconciledVisibleConversationMetadata {
    conversations: Vec<ObservedConversationListMetadata>,
}

impl ReconciledVisibleConversationMetadata {
    /// Matches already-stable rendered row IDs to one observed response.
    ///
    /// Preserves visible order and permits response-only prefetched rows. The
    /// caller must separately establish that the rows belong to the same page
    /// and remain settled across the observation; this is not a mode proof.
    ///
    /// # Errors
    ///
    /// Rejects oversized visible lists, empty/duplicate IDs, missing visible
    /// metadata, and an explicitly empty visible page with response rows.
    pub fn reconcile(
        visible_ids: &[&str],
        response: &ObservedConversationListResponse,
    ) -> Result<Self, ConversationListReconciliationError> {
        if visible_ids.len() > MAX_VISIBLE_CONVERSATIONS {
            // jig-ignore-next-line: canonical rustfmt line.
            return Err(ConversationListReconciliationError::TooManyVisibleConversations);
        }
        if visible_ids.is_empty() {
            if response.total() == 0 && response.conversations().is_empty() {
                return Ok(Self {
                    conversations: Vec::new(),
                });
            }
            // jig-ignore-next-line: canonical rustfmt line.
            return Err(ConversationListReconciliationError::UnexpectedObservedConversation);
        }
        let mut seen = BTreeSet::new();
        for id in visible_ids {
            // jig-ignore-next-line: canonical rustfmt line.
            if !safe_read_id(id, MAX_CONVERSATION_ID_BYTES) || !seen.insert(*id) {
                // jig-ignore-next-line: canonical rustfmt line.
                return Err(ConversationListReconciliationError::InvalidVisibleId);
            }
        }
        let observed = response
            .conversations()
            .iter()
            .map(|conversation| (conversation.id(), conversation))
            .collect::<BTreeMap<_, _>>();
        let mut conversations = Vec::with_capacity(visible_ids.len());
        for id in visible_ids {
            let metadata = observed
                .get(id)
                // jig-ignore-next-line: canonical rustfmt line.
                .ok_or(ConversationListReconciliationError::MissingVisibleConversation)?;
            conversations.push((*metadata).clone());
        }
        Ok(Self { conversations })
    }

    /// Returns matched provider metadata in rendered row order.
    #[must_use]
    pub fn conversations(&self) -> &[ObservedConversationListMetadata] {
        &self.conversations
    }
}

impl fmt::Debug for ReconciledVisibleConversationMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReconciledVisibleConversationMetadata")
            .field("conversation_count", &self.conversations.len())
            .finish()
    }
}

/// Why bounded conversation-list metadata does not cover rendered IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationListReconciliationError {
    /// More than 200 visible IDs were offered to this diagnostic boundary.
    TooManyVisibleConversations,
    /// A visible ID was empty, duplicated, or larger than the provider limit.
    InvalidVisibleId,
    /// The observed batch lacks at least one rendered conversation ID.
    MissingVisibleConversation,
    /// Response rows contradict an explicitly empty visible page.
    UnexpectedObservedConversation,
}

/// Why a captured response cannot be treated as conversation-list metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationListResponseError {
    /// HTTP method or URL is not the exact read-only list endpoint.
    UnexpectedEndpoint,
    /// Response body exceeds the bounded parser input size.
    BodyTooLarge,
    /// JSON shape or required metadata is malformed.
    Malformed,
    /// Provider success code was absent or not `1000`.
    ProviderRejected,
    /// Provider marks the response stale and `WebClients` would refetch it.
    StaleResponse,
    /// Provider reports active backend tasks for this response.
    TasksRunning,
    /// Response contains more than the maximum page-sized row count.
    TooManyConversations,
    /// Response repeats a provider conversation identifier.
    DuplicateConversationId,
    /// CDP returned an encoded body instead of decoded JSON text.
    UnsupportedEncoding,
}

fn is_conversation_list_url(url: &str) -> bool {
    let Some(remainder) = url.strip_prefix(CONVERSATION_LIST_URL_PREFIX) else {
        return false;
    };
    !url.contains('#') && (remainder.is_empty() || remainder.starts_with('?'))
}

fn parse_request_page(
    url: &str,
) -> Result<(Option<u32>, bool, bool), ConversationListNetworkError> {
    let Some((_endpoint, query)) = url.split_once('?') else {
        return Ok((None, false, false));
    };
    let mut page = None;
    let mut page_size = None;
    let mut limit = None;
    let mut has_anchor = false;
    let mut has_anchor_id = false;
    let mut has_non_visible_selector = false;
    let mut sort = None;
    let mut descending = None;
    for parameter in query.split('&') {
        let (key, value) = parameter.split_once('=').unwrap_or((parameter, ""));
        // Encoded keys can become provider pagination/sort aliases after
        // URL decoding even when this raw parser sees an unrelated selector.
        if key.contains('%') {
            return Err(ConversationListNetworkError::InvalidPagination);
        }
        match key {
            "Page" => {
                if page.is_some() {
                    return Err(ConversationListNetworkError::InvalidPagination);
                }
                if value.len() > 10
                    || (value.len() > 1 && value.starts_with('0'))
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(ConversationListNetworkError::InvalidPagination);
                }
                let parsed = value
                    .parse::<u32>()
                    // jig-ignore-next-line: canonical rustfmt line.
                    .map_err(|_error| ConversationListNetworkError::InvalidPagination)?;
                page = Some(parsed);
            }
            "PageSize" => {
                if page_size.replace(bounded_page_size(value)?).is_some() {
                    return Err(ConversationListNetworkError::InvalidPagination);
                }
            }
            "Limit" => {
                if limit.replace(bounded_page_size(value)?).is_some() {
                    return Err(ConversationListNetworkError::InvalidPagination);
                }
            }
            "Anchor" => {
                if has_anchor
                    || value.len() > 20
                    || (value.len() > 1 && value.starts_with('0'))
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                    || value.parse::<u64>().is_err()
                {
                    return Err(ConversationListNetworkError::InvalidPagination);
                }
                has_anchor = true;
            }
            "AnchorID" => {
                // jig-ignore-next-line: canonical rustfmt line.
                if !safe_read_id(value, MAX_CONVERSATION_ID_BYTES) || has_anchor_id {
                    return Err(ConversationListNetworkError::InvalidPagination);
                }
                has_anchor_id = true;
            }
            "BeginID" | "EndID" | "ID" => {
                has_non_visible_selector = true;
            }
            "Sort" => {
                // jig-ignore-next-line: Rustfmt sort keys.
                let recognized_sort = ["Time", "SnoozeTime", "Size"].contains(&value);
                if sort.replace(value).is_some() || !recognized_sort {
                    return Err(ConversationListNetworkError::InvalidPagination);
                }
            }
            "Desc" => {
                let recognized_desc = matches!(value, "0" | "1");
                if descending.replace(value).is_some() || !recognized_desc {
                    return Err(ConversationListNetworkError::InvalidPagination);
                }
            }
            _ => {
                // Critical selectors must use their canonical wire casing.
                // jig-ignore-next-line: Rustfmt selector set.
                let selectors = ["Page", "PageSize", "Limit", "Anchor", "AnchorID"];
                let other = ["BeginID", "EndID", "ID", "Sort", "Desc"];
                let reserved = selectors.iter().chain(&other);
                if reserved
                    .into_iter()
                    .any(|name| name.eq_ignore_ascii_case(key))
                {
                    return Err(ConversationListNetworkError::InvalidPagination);
                }
            }
        }
    }
    if has_anchor != has_anchor_id
        || (has_anchor && page.is_some())
        || (page_size.is_some() && limit.is_some() && page_size != limit)
    {
        return Err(ConversationListNetworkError::InvalidPagination);
    }
    let initial_page_shape = page.is_some()
        && page_size.is_some()
        && page_size == limit
        && !has_anchor
        && !has_non_visible_selector;
    Ok((page, has_anchor, initial_page_shape))
}

fn bounded_page_size(value: &str) -> Result<u16, ConversationListNetworkError> {
    if value.len() > 3
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ConversationListNetworkError::InvalidPagination);
    }
    let parsed = value
        .parse::<u16>()
        .map_err(|_error| ConversationListNetworkError::InvalidPagination)?;
    if parsed == 0 || parsed > MAX_CONVERSATION_LIST_PAGE_SIZE {
        return Err(ConversationListNetworkError::InvalidPagination);
    }
    Ok(parsed)
}

fn url_fingerprint(url: &str, hashers: &[RandomState; 2]) -> [u64; 2] {
    let mut result = [0u64; 2];
    for (slot, hasher) in result.iter_mut().zip(hashers) {
        *slot = hasher.hash_one(url.as_bytes());
    }
    result
}

// jig-ignore-next-line: canonical rustfmt line.
fn network_request_id(event: &Value) -> Result<&str, ConversationListNetworkError> {
    event
        .get("params")
        .and_then(|params| params.get("requestId"))
        .and_then(Value::as_str)
        .ok_or(ConversationListNetworkError::MalformedEvent)
}

// jig-ignore-next-line: canonical rustfmt line.
fn validate_no_tasks_running(value: &Value) -> Result<(), ConversationListResponseError> {
    match value.get("TasksRunning") {
        None | Some(Value::Null | Value::Bool(false)) => Ok(()),
        Some(Value::Array(tasks)) if tasks.is_empty() => Ok(()),
        Some(Value::Object(tasks)) if tasks.is_empty() => Ok(()),
        Some(Value::Bool(true) | Value::Array(_) | Value::Object(_)) => {
            Err(ConversationListResponseError::TasksRunning)
        }
        Some(_) => Err(ConversationListResponseError::Malformed),
    }
}
