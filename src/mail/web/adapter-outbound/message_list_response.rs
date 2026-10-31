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

use crate::request_id_custody::{retain_request_ids, scrub_all_request_ids};
use crate::response_provenance::ExtraStatusEvidence;
use crate::response_provenance::direct_extra_status_is_200;
use crate::response_provenance::uncached_provider_response;
use crate::strict_json;
use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::hash::BuildHasher as _;
use std::mem::replace;

use crate::driver::safe_cdp_request_id;
use crate::opaque_read_id::safe_read_id;
use serde_json::Value;
use zeroize::{Zeroize as _, Zeroizing};

// jig-ignore-next-line: canonical rustfmt line.
const MESSAGE_LIST_URL_PREFIX: &str = concat!("https://mail.proton.me/api/", "mail/v4/messages");
const MAX_MESSAGE_LIST_ITEMS: usize = 100;
const MAX_MESSAGE_LIST_ID_BYTES: usize = 512;
const MAX_TRACKED_MESSAGE_LIST_REQUESTS: usize = 128;
const MAX_MESSAGE_LIST_URL_BYTES: usize = 16_384;
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

/// Sanitized provider list sort key observed in the request query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MessageListSortKey {
    /// Provider message receive time.
    Time,
    /// Provider snooze ordering key.
    SnoozeTime,
    /// Provider message size.
    Size,
}

#[derive(Clone, Eq, PartialEq)]
struct TrackedMessageListRequest {
    state: NetworkRequestState,
    extra_status: ExtraStatusEvidence,
    kind: MessageListRequestKind,
    limit: usize,
    page: Option<u32>,
    sort_key: MessageListSortKey,
    descending: bool,
    anchor: Option<u64>,
    anchor_id: Option<Zeroizing<String>>,
}

impl fmt::Debug for TrackedMessageListRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrackedMessageListRequest")
            .field("state", &self.state)
            .field("extra_status", &self.extra_status)
            .field("kind", &self.kind)
            .field("limit", &self.limit)
            .field("page", &self.page)
            .field("sort_key", &self.sort_key)
            .field("descending", &self.descending)
            .field("anchor", &self.anchor.map(|_| "<redacted>"))
            .field("anchor_id", &self.anchor_id.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Bounded CDP Network event state for exact message-list GET requests.
#[derive(Clone)]
pub struct MessageListNetworkCapture {
    session_id: Zeroizing<String>,
    requests: BTreeMap<String, TrackedMessageListRequest>,
    completed_ids: BTreeSet<String>,
    context_fingerprint: Option<[u64; 2]>,
    fingerprint_hashers: [RandomState; 2],
}

#[expect(
    clippy::missing_trait_methods,
    reason = "default ne preserves the Eq contract for sanitized capture state"
)]
impl PartialEq for MessageListNetworkCapture {
    fn eq(&self, other: &Self) -> bool {
        let context_bound = self.context_fingerprint.is_some();
        let other_context_bound = other.context_fingerprint.is_some();
        self.session_id == other.session_id
            && self.requests == other.requests
            && self.completed_ids == other.completed_ids
            && context_bound == other_context_bound
    }
}

#[expect(
    clippy::missing_trait_methods,
    reason = "Eq marker defaults require no custom randomized-state behavior"
)]
impl Eq for MessageListNetworkCapture {}

#[expect(
    clippy::missing_trait_methods,
    reason = "Drop scrubs retained CDP request correlation identifiers"
)]
impl Drop for MessageListNetworkCapture {
    fn drop(&mut self) {
        scrub_all_request_ids(&mut self.requests, &mut self.completed_ids);
    }
}

impl MessageListNetworkCapture {
    /// Creates an empty capture scoped to one flattened CDP target session.
    #[must_use]
    pub fn new(session_id: &str) -> Self {
        Self {
            session_id: Zeroizing::new(String::from(session_id)),
            requests: BTreeMap::new(),
            completed_ids: BTreeSet::new(),
            context_fingerprint: None,
            fingerprint_hashers: [RandomState::new(), RandomState::new()],
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
            // jig-ignore-next-line: canonical extra-info CDP match guard.
            Some("Network.responseReceivedExtraInfo") if direct_extra_status_is_200(event) => {
                self.observe_extra_200(event)
            }
            // jig-ignore-next-line: combined CDP cache and extra-status match.
            Some("Network.responseReceivedExtraInfo" | "Network.requestServedFromCache") => {
                self.observe_cache_hit(event)
            }
            Some("Network.loadingFinished") => self.observe_finished(event),
            Some("Network.loadingFailed") => self.observe_failed(event),
            _ => Ok(()),
        }
    }

    /// Removes and returns request IDs whose safe response lifecycle completed.
    pub fn take_finished_request_ids(&mut self) -> Vec<String> {
        self.take_finished_requests()
            .into_iter()
            .map(
                |(
                    request_id,
                    _continuation,
                    _limit,
                    _page,
                    sort_key,
                    _descending,
                    _anchor,
                    anchor_id,
                )| {
                    // ID-only projections must still scrub discarded copies.
                    let _guarded_sort = Zeroizing::new(sort_key);
                    let _guarded_anchor = Zeroizing::new(anchor_id);
                    request_id
                },
            )
            .collect()
    }

    /// Returns the number of matching requests whose lifecycle is retained.
    #[must_use]
    pub(crate) fn tracked_request_count(&self) -> usize {
        self.requests.len()
    }

    /// Removes completed batches as sanitized request metadata tuples.
    ///
    /// The tuple contains request ID, batch kind, limit, page, sanitized sort,
    /// direction, numeric anchor, and bounded anchor ID. It excludes URL and
    /// headers.
    #[expect(
        clippy::type_complexity,
        reason = "internal tuple contains only sanitized request metadata"
    )]
    pub(crate) fn take_finished_requests(
        &mut self,
    ) -> Vec<(
        String,
        bool,
        usize,
        Option<u32>,
        String,
        bool,
        Option<u64>,
        Option<String>,
    )> {
        let finished = self
            .requests
            .iter()
            .filter(|(_id, request)| {
                // jig-ignore-next-line: rustfmt status guard.
                request.state == NetworkRequestState::Finished && request.extra_status.ready()
            })
            .map(|(id, request)| {
                (
                    id.clone(),
                    request.kind == MessageListRequestKind::Continuation,
                    request.limit,
                    request.page,
                    String::from(match request.sort_key {
                        MessageListSortKey::Time => "Time",
                        MessageListSortKey::SnoozeTime => "SnoozeTime",
                        MessageListSortKey::Size => "Size",
                    }),
                    request.descending,
                    request.anchor,
                    request
                        .anchor_id
                        .as_ref()
                        .map(|id| String::from(id.as_str())),
                )
            })
            .collect::<Vec<_>>();
        retain_request_ids(&mut self.requests, |request| {
            // jig-ignore-next-line: rustfmt status guard.
            request.state != NetworkRequestState::Finished || !request.extra_status.ready()
        });
        for (request_id, ..) in &finished {
            self.completed_ids.insert(request_id.clone());
        }
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
        if self.completed_ids.contains(request_id) {
            return Err(MessageListNetworkError::InvalidSequence);
        }
        let tracked = self.requests.contains_key(request_id);
        let message_list_get = method == "GET" && is_message_list_url(url);
        if tracked && !message_list_get {
            return Err(MessageListNetworkError::RedirectedAway);
        }
        if !message_list_get {
            return Ok(());
        }
        // CDP reuses requestId across redirects, including from untracked URLs.
        if params.get("redirectResponse").is_some() {
            return Err(MessageListNetworkError::RedirectedAway);
        }
        if tracked {
            return Err(MessageListNetworkError::InvalidSequence);
        }
        if url.len() > MAX_MESSAGE_LIST_URL_BYTES {
            return Err(MessageListNetworkError::MalformedEvent);
        }
        let Some((kind, limit, page, sort_key, descending, anchor, anchor_id)) =
            message_list_request_shape(url)?
        else {
            return Ok(());
        };
        if !safe_cdp_request_id(request_id) {
            return Err(MessageListNetworkError::MalformedEvent);
        }
        // jig-ignore-next-line: canonical rustfmt line.
        let context_fingerprint = query_context_fingerprint(url, &self.fingerprint_hashers)?;
        match self.context_fingerprint {
            Some(expected) if expected != context_fingerprint => {
                return Err(MessageListNetworkError::QueryContextChanged);
            }
            None => self.context_fingerprint = Some(context_fingerprint),
            Some(_) => {}
        }
        if self.requests.len().saturating_add(self.completed_ids.len())
            >= MAX_TRACKED_MESSAGE_LIST_REQUESTS
        {
            return Err(MessageListNetworkError::CapacityExceeded);
        }
        self.requests.insert(
            String::from(request_id),
            TrackedMessageListRequest {
                state: NetworkRequestState::Requested,
                extra_status: ExtraStatusEvidence::default(),
                kind,
                limit,
                page,
                sort_key,
                descending,
                anchor,
                // The validated selector was borrowed from the guarded CDP
                // event JSON until the request actually entered capture state.
                anchor_id: anchor_id.map(|id| Zeroizing::new(String::from(id))),
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
        if self.completed_ids.contains(request_id) {
            return Err(MessageListNetworkError::InvalidSequence);
        }
        if !self.requests.contains_key(request_id) {
            return Ok(());
        }
        let response = params
            .get("response")
            .ok_or(MessageListNetworkError::MalformedEvent)?;
        let url = response
            .get("url")
            .and_then(Value::as_str)
            .ok_or(MessageListNetworkError::MalformedEvent)?;
        if url.len() > MAX_MESSAGE_LIST_URL_BYTES {
            return Err(MessageListNetworkError::ResponseRejected);
        }
        // jig-ignore-next-line: canonical rustfmt line.
        let context_fingerprint = query_context_fingerprint(url, &self.fingerprint_hashers)
            .map_err(|_error| MessageListNetworkError::ResponseRejected)?;
        if self.completed_ids.contains(request_id) {
            return Err(MessageListNetworkError::InvalidSequence);
        }
        let Some(request) = self.requests.get_mut(request_id) else {
            return Ok(());
        };
        if request.state != NetworkRequestState::Requested {
            return Err(MessageListNetworkError::InvalidSequence);
        }
        let status = response.get("status").and_then(Value::as_u64);
        let mime = response.get("mimeType").and_then(Value::as_str);
        if !is_message_list_url(url)
            || !uncached_provider_response(response)
            || status != Some(200)
            || mime != Some("application/json")
        {
            return Err(MessageListNetworkError::ResponseRejected);
        }
        let shape = message_list_request_shape(url)
            .map_err(|_error| MessageListNetworkError::ResponseRejected)?
            .ok_or(MessageListNetworkError::ResponseRejected)?;
        // jig-ignore-next-line: canonical rustfmt line.
        let (kind, limit, page, sort_key, descending, anchor, anchor_id) = shape;
        let saved_anchor_id = request.anchor_id.as_ref().map(|id| id.as_str());
        if request.kind != kind
            || request.limit != limit
            || request.page != page
            || request.sort_key != sort_key
            || request.descending != descending
            || self.context_fingerprint != Some(context_fingerprint)
            || request.anchor != anchor
            || saved_anchor_id != anchor_id
        {
            return Err(MessageListNetworkError::ResponseRejected);
        }
        if !request.extra_status.note_response(params) {
            return Err(MessageListNetworkError::ResponseRejected);
        }
        request.state = NetworkRequestState::Responded;
        Ok(())
    }

    // The actual HTTP-200 status can arrive before or after loadingFinished.
    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_extra_200(&mut self, event: &Value) -> Result<(), MessageListNetworkError> {
        let request_id = network_request_id(event)?;
        if self.completed_ids.contains(request_id) {
            return Err(MessageListNetworkError::InvalidSequence);
        }
        if let Some(request) = self.requests.get_mut(request_id)
            && !request.extra_status.note_200()
        {
            return Err(MessageListNetworkError::InvalidSequence);
        }
        Ok(())
    }

    // Chrome reports cache hits separately from response metadata. A hit
    // disqualifies this exact provider GET regardless of notification order.
    // jig-ignore-next-line: rustfmt callback signature.
    fn observe_cache_hit(&self, event: &Value) -> Result<(), MessageListNetworkError> {
        let request_id = network_request_id(event)?;
        if self.completed_ids.contains(request_id) {
            return Err(MessageListNetworkError::InvalidSequence);
        }
        if self.requests.contains_key(request_id) {
            return Err(MessageListNetworkError::ResponseRejected);
        }
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_finished(&mut self, event: &Value) -> Result<(), MessageListNetworkError> {
        let request_id = network_request_id(event)?;
        if self.completed_ids.contains(request_id) {
            return Err(MessageListNetworkError::InvalidSequence);
        }
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
        if self.completed_ids.contains(request_id) {
            return Err(MessageListNetworkError::InvalidSequence);
        }
        if let Some(request) = self.requests.get(request_id) {
            if request.state == NetworkRequestState::Finished {
                return Err(MessageListNetworkError::InvalidSequence);
            }
            return Err(MessageListNetworkError::RequestFailed);
        }
        Ok(())
    }
}

impl fmt::Debug for MessageListNetworkCapture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageListNetworkCapture")
            .field("session_id", &"<redacted>")
            .field("requests", &self.requests.len())
            .field("completed_request_count", &self.completed_ids.len())
            .field("context_fingerprint", &"<redacted>")
            .field("fingerprint_hashers", &"<redacted>")
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
    /// Non-pagination query context changed during one capture.
    QueryContextChanged,
}

#[expect(
    clippy::type_complexity,
    reason = "internal tuple contains only sanitized request metadata"
)]
fn message_list_request_shape(
    url: &str,
) -> Result<
    Option<(
        MessageListRequestKind,
        usize,
        Option<u32>,
        MessageListSortKey,
        bool,
        Option<u64>,
        Option<&str>,
    )>,
    MessageListNetworkError,
> {
    if has_non_visible_list_selector(url)? {
        return Ok(None);
    }
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
    let raw_page = numeric_query_parameter(url, "Page")?;
    let page = raw_page
        .map(u32::try_from)
        .transpose()
        .map_err(|_error| MessageListNetworkError::MalformedEvent)?;
    let page_size = numeric_query_parameter(url, "PageSize")?;
    let Some(sort_key) = sort_query_parameter(url)? else {
        return Ok(None);
    };
    let Some(descending) = descending_query_parameter(url)? else {
        return Ok(None);
    };
    let anchor = numeric_query_parameter(url, "Anchor")?;
    // jig-ignore-next-line: canonical rustfmt line.
    let anchor_id = bounded_query_parameter(url, "AnchorID", MAX_MESSAGE_LIST_ID_BYTES)?;
    let kind = match (page, page_size, anchor, anchor_id) {
        (Some(_page), Some(size), None, None) if size == raw_limit => {
            MessageListRequestKind::Initial
        }
        // jig-ignore-next-line: canonical rustfmt line.
        (None, None, Some(_anchor), Some(_anchor_id)) => MessageListRequestKind::Continuation,
        _ => return Ok(None),
    };
    Ok(Some((
        kind, limit, page, sort_key, descending, anchor, anchor_id,
    )))
}

fn query_context_fingerprint(
    url: &str,
    hashers: &[RandomState; 2],
) -> Result<[u64; 2], MessageListNetworkError> {
    let Some((_path, query)) = url.split_once('?') else {
        return Err(MessageListNetworkError::MalformedEvent);
    };
    let query = query.split('#').next().unwrap_or(query);
    let mut pairs = query
        .split('&')
        .filter(|pair| {
            let key = pair.split_once('=').map_or(*pair, |(key, _value)| key);
            // jig-ignore-next-line: canonical rustfmt line.
            !matches!(key, "Page" | "PageSize" | "Limit" | "Anchor" | "AnchorID")
        })
        .collect::<Vec<_>>();
    // Different query keys may be reordered by the app, but the order of
    // repeated values for one key may affect which messages are selected.
    // A stable key-only sort retains that sequence without storing the query.
    pairs.sort_by(|left, right| {
        let left_key = left.split_once('=').map_or(*left, |(key, _value)| key);
        // jig-ignore-next-line: canonical rustfmt line.
        let right_key = right.split_once('=').map_or(*right, |(key, _value)| key);
        left_key.cmp(right_key)
    });
    let mut result = [0u64; 2];
    for (slot, state) in result.iter_mut().zip(hashers) {
        *slot = state.hash_one(&pairs);
    }
    Ok(result)
}

// jig-ignore-next-line: canonical rustfmt line.
fn has_non_visible_list_selector(url: &str) -> Result<bool, MessageListNetworkError> {
    // Only audited pagination, sort, and filter keys can prove a visible
    // provider batch. An unreviewed key might alter which messages were
    // selected even if the observed rows happen to match the current view.
    let Some((_path, query)) = url.split_once('?') else {
        return Ok(false);
    };
    let visible = [
        // Pagination and ordering keys.
        "Page", "PageSize", "Limit", "Anchor", "AnchorID", "Sort", "Desc",
        // Audited filters.
        "LabelID", "Keyword", "Unread",
    ];
    let non_visible_selectors = ["Begin", "End", "BeginID", "EndID", "ID"];
    let mut keyword_seen = false;
    let mut unread_seen = false;
    let mut non_visible = false;
    for pair in query.split('&') {
        let key = pair.split_once('=').map_or(pair, |(key, _value)| key);
        if key.contains('%') {
            return Err(MessageListNetworkError::MalformedEvent);
        }
        if visible
            .iter()
            .chain(&non_visible_selectors)
            .any(|known| known.eq_ignore_ascii_case(key) && *known != key)
        {
            return Err(MessageListNetworkError::MalformedEvent);
        }
        // LabelID intentionally permits repeated values. Keyword and Unread
        // are scalar selectors and must have a single canonical value.
        let repeated_scalar = match key {
            "Keyword" => replace(&mut keyword_seen, true),
            "Unread" => replace(&mut unread_seen, true),
            _ => false,
        };
        if repeated_scalar {
            return Err(MessageListNetworkError::MalformedEvent);
        }
        non_visible |= !visible.contains(&key);
    }
    Ok(non_visible)
}

// jig-ignore-next-line: canonical rustfmt line.
fn sort_query_parameter(url: &str) -> Result<Option<MessageListSortKey>, MessageListNetworkError> {
    let Some(value) = raw_query_parameter(url, "Sort")? else {
        return Ok(None);
    };
    match value {
        "Time" => Ok(Some(MessageListSortKey::Time)),
        "SnoozeTime" => Ok(Some(MessageListSortKey::SnoozeTime)),
        "Size" => Ok(Some(MessageListSortKey::Size)),
        _ => Err(MessageListNetworkError::MalformedEvent),
    }
}

// jig-ignore-next-line: canonical rustfmt line.
fn descending_query_parameter(url: &str) -> Result<Option<bool>, MessageListNetworkError> {
    let Some(value) = numeric_query_parameter(url, "Desc")? else {
        return Ok(None);
    };
    match value {
        0 => Ok(Some(false)),
        1 => Ok(Some(true)),
        _ => Err(MessageListNetworkError::MalformedEvent),
    }
}

// jig-ignore-next-line: canonical rustfmt line.
fn numeric_query_parameter(url: &str, name: &str) -> Result<Option<u64>, MessageListNetworkError> {
    let Some(value) = raw_query_parameter(url, name)? else {
        return Ok(None);
    };
    if value.len() > 20
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(MessageListNetworkError::MalformedEvent);
    }
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|_error| MessageListNetworkError::MalformedEvent)
}

fn bounded_query_parameter<'url>(
    url: &'url str,
    name: &str,
    max_bytes: usize,
) -> Result<Option<&'url str>, MessageListNetworkError> {
    let Some(value) = raw_query_parameter(url, name)? else {
        return Ok(None);
    };
    if !safe_read_id(value, max_bytes) {
        return Err(MessageListNetworkError::MalformedEvent);
    }
    // Borrow the original validated query field until accepted capture state.
    Ok(Some(value))
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
        if key.contains('%') {
            return Err(MessageListNetworkError::MalformedEvent);
        }
        if key != name {
            // A differently cased key can alias a canonical provider
            // selector after query decoding and alter list interpretation.
            if key.eq_ignore_ascii_case(name) {
                return Err(MessageListNetworkError::MalformedEvent);
            }
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

// jig-ignore-next-line: canonical rustfmt line.
fn validate_no_tasks_running(value: &Value) -> Result<(), MessageListResponseError> {
    match value.get("TasksRunning") {
        None | Some(Value::Null | Value::Bool(false)) => Ok(()),
        Some(Value::Array(tasks)) if tasks.is_empty() => Ok(()),
        Some(Value::Object(tasks)) if tasks.is_empty() => Ok(()),
        Some(Value::Bool(true) | Value::Array(_) | Value::Object(_)) => {
            Err(MessageListResponseError::TasksRunning)
        }
        Some(_) => Err(MessageListResponseError::Malformed),
    }
}

/// One metadata row projected from the provider's message-list response.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedMessageMetadata {
    id: String,
    time: u64,
    order: i64,
}

#[expect(
    clippy::missing_trait_methods,
    reason = "Drop is the explicit scrub-on-drop contract"
)]
impl Drop for ObservedMessageMetadata {
    fn drop(&mut self) {
        self.id.zeroize();
    }
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
    /// malformed JSON, stale/task-running state, more than 100 rows, missing
    /// numeric metadata, or duplicate message IDs.
    // jig-ignore-next-line: canonical rustfmt line.
    pub fn parse(method: &str, url: &str, body: &str) -> Result<Self, MessageListResponseError> {
        // jig-ignore-next-line: canonical rustfmt line.
        if method != "GET" || url.len() > MAX_MESSAGE_LIST_URL_BYTES || !is_message_list_url(url) {
            return Err(MessageListResponseError::UnexpectedEndpoint);
        }
        if body.len() > Self::MAX_BODY_BYTES {
            return Err(MessageListResponseError::BodyTooLarge);
        }
        let value =
    // jig-ignore-next-line: canonical rustfmt line.
            strict_json::from_sensitive_slice(body.as_bytes()).map_err(|_error| MessageListResponseError::Malformed)?;
        if value
            .get("Code")
            .is_some_and(|code| code.as_u64() != Some(1000))
        {
            return Err(MessageListResponseError::ProviderRejected);
        }
        let stale = value
            .get("Stale")
            .and_then(Value::as_u64)
            .ok_or(MessageListResponseError::Malformed)?;
        if stale != 0 {
            return Err(MessageListResponseError::StaleResponse);
        }
        validate_no_tasks_running(&value)?;
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
                .filter(|id| safe_read_id(id, MAX_MESSAGE_LIST_ID_BYTES))
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
        if result.as_object().is_none_or(|fields| fields.len() != 2) {
            return Err(MessageListResponseError::Malformed);
        }
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
        // This adapter observes at most the initial page and one anchored
        // continuation. A larger collection is not a proven page chain.
        if responses.len() > 2 {
            return Err(MessageListReconciliationError::TooManyObservedBatches);
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
            // jig-ignore-next-line: canonical rustfmt all-batch total check.
            let totals_are_zero = responses.iter().all(|response| response.total() == 0);
            if observed.is_empty() && totals_are_zero {
                return Ok(Self {
                    messages: Vec::new(),
                });
            }
            // jig-ignore-next-line: canonical rustfmt line.
            return Err(MessageListReconciliationError::UnexpectedObservedMessage);
        }

        let mut visible = BTreeSet::new();
        for id in visible_ids {
            if !safe_read_id(id, MAX_MESSAGE_LIST_ID_BYTES) {
                return Err(MessageListReconciliationError::InvalidVisibleId);
            }
            if !visible.insert(*id) {
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
    /// More than the two audited initial/continuation batches were supplied.
    TooManyObservedBatches,
    /// Stable visible evidence contains too many message IDs.
    TooManyVisibleMessages,
    /// Stable visible evidence repeats or contains an empty message ID.
    DuplicateVisibleId,
    /// One visible message ID cannot safely name an exact provider read.
    InvalidVisibleId,
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
    /// Provider explicitly returned a non-success result code.
    ProviderRejected,
    /// JSON shape or required metadata is malformed.
    Malformed,
    /// Provider marks the list stale and `WebClients` would refetch it.
    StaleResponse,
    /// Provider reports active backend tasks for the list response.
    TasksRunning,
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
    !url.contains('#') && (remainder.is_empty() || remainder.starts_with('?'))
}

#[cfg(test)]
#[path = "../../../../tests/mail/web/adapter-outbound/dbg_msg_list.rs"]
mod private_request_diagnostics_tests;
