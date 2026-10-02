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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use mail_capability_domain::{EventCursorScope, ScopedEventCursor};
use serde_json::Value;

// jig-ignore-next-line: canonical rustfmt line.
const CORE_EVENT_URL_PREFIX: &str = concat!("https://mail.proton.me/api/", "core/v5/events/");
// jig-ignore-next-line: canonical rustfmt line.
const LATEST_EVENT_URL: &str = "https://mail.proton.me/api/core/v4/events/latest";
const MAX_EVENT_BODY_BYTES: usize = 262_144;
const MAX_EVENT_ID_BYTES: usize = 512;
const MAX_TRACKED_EVENT_REQUESTS: usize = 32;
const MAX_PROJECTED_CHANGES: usize = 512;
const MAX_EVENT_SEQUENCE_PAGES: usize = 32;
const MAX_EVENT_SEQUENCE_CHANGES: usize = 4096;
const MAIL_REFRESH_BIT: u64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EventRequestState {
    Requested,
    Responded,
    Finished,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TrackedEventRequest {
    state: EventRequestState,
    event_id: String,
}

/// Bounded CDP lifecycle state for the exact legacy latest-event GET.
#[derive(Clone, Eq, PartialEq)]
pub struct LatestMailboxEventNetworkCapture {
    session_id: String,
    requests: BTreeMap<String, EventRequestState>,
}

impl LatestMailboxEventNetworkCapture {
    /// Creates an empty capture scoped to one flattened CDP target session.
    #[must_use]
    pub fn new(session_id: &str) -> Self {
        Self {
            session_id: String::from(session_id),
            requests: BTreeMap::new(),
        }
    }

    /// Consumes one unsolicited CDP event without retaining payload content.
    ///
    /// # Errors
    ///
    /// Fails closed for redirects, request failures, invalid ordering, unsafe
    /// responses, and capture-capacity exhaustion.
    // jig-ignore-next-line: canonical rustfmt line.
    pub fn observe(&mut self, event: &Value) -> Result<(), MailboxEventNetworkError> {
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

    /// Returns the number of tracked latest-event requests.
    #[must_use]
    pub(crate) fn tracked_request_count(&self) -> usize {
        self.requests.len()
    }

    /// Removes completed exact latest-event requests and returns request IDs.
    pub fn take_finished_request_ids(&mut self) -> Vec<String> {
        let finished = self
            .requests
            .iter()
            .filter(|(_id, state)| **state == EventRequestState::Finished)
            .map(|(id, _state)| id.clone())
            .collect::<Vec<_>>();
        self.requests
            .retain(|_id, state| *state != EventRequestState::Finished);
        finished
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_request(&mut self, event: &Value) -> Result<(), MailboxEventNetworkError> {
        let params = event
            .get("params")
            .ok_or(MailboxEventNetworkError::MalformedEvent)?;
        let request_id = params
            .get("requestId")
            .and_then(Value::as_str)
            .ok_or(MailboxEventNetworkError::MalformedEvent)?;
        let request = params
            .get("request")
            .ok_or(MailboxEventNetworkError::MalformedEvent)?;
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or(MailboxEventNetworkError::MalformedEvent)?;
        let url = request
            .get("url")
            .and_then(Value::as_str)
            .ok_or(MailboxEventNetworkError::MalformedEvent)?;
        let tracked = self.requests.contains_key(request_id);
        let candidate = method == "GET" && is_latest_event_url(url);
        if tracked && !candidate {
            return Err(MailboxEventNetworkError::RedirectedAway);
        }
        if !candidate {
            return Ok(());
        }
        if tracked {
            return Err(MailboxEventNetworkError::InvalidSequence);
        }
        if self.requests.len() >= MAX_TRACKED_EVENT_REQUESTS {
            return Err(MailboxEventNetworkError::CapacityExceeded);
        }
        self.requests
            .insert(String::from(request_id), EventRequestState::Requested);
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_response(&mut self, event: &Value) -> Result<(), MailboxEventNetworkError> {
        let params = event
            .get("params")
            .ok_or(MailboxEventNetworkError::MalformedEvent)?;
        let request_id = params
            .get("requestId")
            .and_then(Value::as_str)
            .ok_or(MailboxEventNetworkError::MalformedEvent)?;
        if !self.requests.contains_key(request_id) {
            return Ok(());
        }
        let response = params
            .get("response")
            .ok_or(MailboxEventNetworkError::MalformedEvent)?;
        let url = response
            .get("url")
            .and_then(Value::as_str)
            .ok_or(MailboxEventNetworkError::MalformedEvent)?;
        let status = response.get("status").and_then(Value::as_u64);
        let mime = response.get("mimeType").and_then(Value::as_str);
        let Some(state) = self.requests.get_mut(request_id) else {
            return Ok(());
        };
        if *state != EventRequestState::Requested {
            return Err(MailboxEventNetworkError::InvalidSequence);
        }
        // jig-ignore-next-line: canonical rustfmt line.
        if status != Some(200) || mime != Some("application/json") || !is_latest_event_url(url) {
            return Err(MailboxEventNetworkError::ResponseRejected);
        }
        *state = EventRequestState::Responded;
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_finished(&mut self, event: &Value) -> Result<(), MailboxEventNetworkError> {
        let request_id = network_request_id(event)?;
        let Some(state) = self.requests.get_mut(request_id) else {
            return Ok(());
        };
        if *state != EventRequestState::Responded {
            return Err(MailboxEventNetworkError::InvalidSequence);
        }
        *state = EventRequestState::Finished;
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_failed(&mut self, event: &Value) -> Result<(), MailboxEventNetworkError> {
        let request_id = network_request_id(event)?;
        self.requests.remove(request_id);
        Ok(())
    }
}

impl fmt::Debug for LatestMailboxEventNetworkCapture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LatestMailboxEventNetworkCapture")
            .field("session_id", &"<redacted>")
            .field("tracked_request_count", &self.requests.len())
            .finish()
    }
}

/// Bounded CDP lifecycle state for exact legacy Mail core-event GETs.
#[derive(Clone, Eq, PartialEq)]
pub struct MailboxEventNetworkCapture {
    session_id: String,
    requests: BTreeMap<String, TrackedEventRequest>,
}

impl MailboxEventNetworkCapture {
    /// Creates an empty capture scoped to one flattened CDP target session.
    #[must_use]
    pub fn new(session_id: &str) -> Self {
        Self {
            session_id: String::from(session_id),
            requests: BTreeMap::new(),
        }
    }

    /// Consumes one unsolicited CDP event without retaining event payload data.
    ///
    /// # Errors
    ///
    /// Fails closed for redirects, request failures, invalid ordering, unsafe
    /// responses, malformed exact-event URLs, and capture-capacity exhaustion.
    // jig-ignore-next-line: canonical rustfmt line.
    pub fn observe(&mut self, event: &Value) -> Result<(), MailboxEventNetworkError> {
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

    /// Returns the number of unfinished or completed tracked event requests.
    #[must_use]
    pub(crate) fn tracked_request_count(&self) -> usize {
        self.requests.len()
    }

    /// Removes completed event requests and returns only their CDP request IDs.
    pub fn take_finished_request_ids(&mut self) -> Vec<String> {
        self.take_finished_requests()
            .into_iter()
            .map(|(request_id, _event_id)| request_id)
            .collect()
    }

    pub(crate) fn take_finished_requests(&mut self) -> Vec<(String, String)> {
        let finished = self
            .requests
            .iter()
            // jig-ignore-next-line: canonical rustfmt line.
            .filter(|(_id, request)| request.state == EventRequestState::Finished)
            .map(|(id, request)| (id.clone(), request.event_id.clone()))
            .collect::<Vec<_>>();
        self.requests
            // jig-ignore-next-line: canonical rustfmt line.
            .retain(|_id, request| request.state != EventRequestState::Finished);
        finished
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_request(&mut self, event: &Value) -> Result<(), MailboxEventNetworkError> {
        let params = event
            .get("params")
            .ok_or(MailboxEventNetworkError::MalformedEvent)?;
        let request_id = params
            .get("requestId")
            .and_then(Value::as_str)
            .ok_or(MailboxEventNetworkError::MalformedEvent)?;
        let request = params
            .get("request")
            .ok_or(MailboxEventNetworkError::MalformedEvent)?;
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or(MailboxEventNetworkError::MalformedEvent)?;
        let url = request
            .get("url")
            .and_then(Value::as_str)
            .ok_or(MailboxEventNetworkError::MalformedEvent)?;
        let tracked = self.requests.contains_key(request_id);
        // jig-ignore-next-line: canonical rustfmt line.
        let candidate = method == "GET" && url.starts_with(CORE_EVENT_URL_PREFIX);
        if tracked && !candidate {
            return Err(MailboxEventNetworkError::RedirectedAway);
        }
        if !candidate {
            return Ok(());
        }
        if tracked {
            return Err(MailboxEventNetworkError::InvalidSequence);
        }
        let event_id =
            // jig-ignore-next-line: canonical rustfmt line.
            event_id_from_url(url).map_err(|_error| MailboxEventNetworkError::MalformedEvent)?;
        if self.requests.len() >= MAX_TRACKED_EVENT_REQUESTS {
            return Err(MailboxEventNetworkError::CapacityExceeded);
        }
        self.requests.insert(
            String::from(request_id),
            TrackedEventRequest {
                state: EventRequestState::Requested,
                event_id: String::from(event_id),
            },
        );
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_response(&mut self, event: &Value) -> Result<(), MailboxEventNetworkError> {
        let params = event
            .get("params")
            .ok_or(MailboxEventNetworkError::MalformedEvent)?;
        let request_id = params
            .get("requestId")
            .and_then(Value::as_str)
            .ok_or(MailboxEventNetworkError::MalformedEvent)?;
        if !self.requests.contains_key(request_id) {
            return Ok(());
        }
        let response = params
            .get("response")
            .ok_or(MailboxEventNetworkError::MalformedEvent)?;
        let url = response
            .get("url")
            .and_then(Value::as_str)
            .ok_or(MailboxEventNetworkError::MalformedEvent)?;
        let event_id =
            // jig-ignore-next-line: canonical rustfmt line.
            event_id_from_url(url).map_err(|_error| MailboxEventNetworkError::ResponseRejected)?;
        let status = response.get("status").and_then(Value::as_u64);
        let mime = response.get("mimeType").and_then(Value::as_str);
        let Some(request) = self.requests.get_mut(request_id) else {
            return Ok(());
        };
        if request.state != EventRequestState::Requested {
            return Err(MailboxEventNetworkError::InvalidSequence);
        }
        // jig-ignore-next-line: canonical rustfmt line.
        if status != Some(200) || mime != Some("application/json") || event_id != request.event_id {
            return Err(MailboxEventNetworkError::ResponseRejected);
        }
        request.state = EventRequestState::Responded;
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_finished(&mut self, event: &Value) -> Result<(), MailboxEventNetworkError> {
        let request_id = network_request_id(event)?;
        let Some(request) = self.requests.get_mut(request_id) else {
            return Ok(());
        };
        if request.state != EventRequestState::Responded {
            return Err(MailboxEventNetworkError::InvalidSequence);
        }
        request.state = EventRequestState::Finished;
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_failed(&mut self, event: &Value) -> Result<(), MailboxEventNetworkError> {
        let request_id = network_request_id(event)?;
        self.requests.remove(request_id);
        Ok(())
    }
}

impl fmt::Debug for MailboxEventNetworkCapture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailboxEventNetworkCapture")
            .field("session_id", &"<redacted>")
            .field("tracked_request_count", &self.requests.len())
            .finish()
    }
}

/// Fail-closed legacy Mail core-event Network lifecycle errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxEventNetworkError {
    /// Event shape did not contain required CDP lifecycle fields.
    MalformedEvent,
    /// A tracked request redirected away from the exact event endpoint.
    RedirectedAway,
    /// Response status, MIME type, URL, or event watermark was unsafe.
    ResponseRejected,
    /// A lifecycle event was repeated or arrived out of order.
    InvalidSequence,
    /// Too many exact event requests were retained simultaneously.
    CapacityExceeded,
}

/// Sanitized bootstrap watermark from the legacy core latest-event endpoint.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedLatestMailboxEventWatermark {
    event_id: String,
}

impl ObservedLatestMailboxEventWatermark {
    /// Projects one exact legacy latest-event response.
    ///
    /// # Errors
    ///
    /// Rejects non-GET traffic, any other endpoint, oversized or malformed
    /// bodies, and invalid event watermarks.
    // jig-ignore-next-line: canonical rustfmt line.
    pub fn parse(method: &str, url: &str, body: &str) -> Result<Self, MailboxEventWatermarkError> {
        if method != "GET" || !is_latest_event_url(url) {
            return Err(MailboxEventWatermarkError::UnexpectedEndpoint);
        }
        if body.len() > MAX_EVENT_BODY_BYTES {
            return Err(MailboxEventWatermarkError::BodyTooLarge);
        }
        let value: Value =
            // jig-ignore-next-line: canonical rustfmt line.
            serde_json::from_str(body).map_err(|_error| MailboxEventWatermarkError::Malformed)?;
        let event_id = value
            .get("EventID")
            .and_then(Value::as_str)
            .filter(|id| valid_event_id(id))
            .ok_or(MailboxEventWatermarkError::Malformed)?;
        Ok(Self {
            event_id: String::from(event_id),
        })
    }

    /// Projects one decoded `Network.getResponseBody` latest-event result.
    ///
    /// # Errors
    ///
    /// Rejects malformed CDP envelopes, encoded bodies, oversized bodies, and
    /// invalid bootstrap event watermarks.
    // jig-ignore-next-line: canonical rustfmt line.
    pub fn parse_cdp_body(result: &Value) -> Result<Self, MailboxEventWatermarkError> {
        let encoded = result
            .get("base64Encoded")
            .and_then(Value::as_bool)
            .ok_or(MailboxEventWatermarkError::Malformed)?;
        if encoded {
            return Err(MailboxEventWatermarkError::UnsupportedEncoding);
        }
        let body = result
            .get("body")
            .and_then(Value::as_str)
            .ok_or(MailboxEventWatermarkError::Malformed)?;
        Self::parse("GET", LATEST_EVENT_URL, body)
    }

    /// Returns the bounded opaque bootstrap event watermark.
    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    /// Binds this bootstrap watermark to one provider-neutral cursor scope.
    #[must_use]
    // jig-ignore-next-line: canonical rustfmt line.
    pub fn bind_cursor(&self, scope: EventCursorScope) -> ScopedEventCursor<String> {
        scope.bind(self.event_id.clone())
    }

    /// Checks local consistency with one later settled no-change event poll.
    ///
    /// This is only a necessary bracket shape for snapshot research. It does
    /// not establish provider snapshot semantics or clear list readiness.
    #[must_use]
    // jig-ignore-next-line: canonical rustfmt line.
    pub fn matches_quiet_poll(&self, poll: &ObservedMailboxEventWatermark) -> bool {
        poll.requested_event_id == self.event_id
            && poll.response_event_id == self.event_id
            && poll.settled()
            && !poll.mailbox_changes()
    }
}

impl fmt::Debug for ObservedLatestMailboxEventWatermark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedLatestMailboxEventWatermark")
            .field("event_id", &"<redacted>")
            .finish()
    }
}

/// Provider-neutral entity kind for one observed mailbox change.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MailboxChangeEntity {
    /// One opaque Proton message identifier changed.
    Message,
    /// One opaque Proton conversation identifier changed.
    Conversation,
}

/// Provider-neutral mutation class for one observed mailbox change.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MailboxChangeKind {
    /// Provider reports a newly created entity.
    Created,
    /// Provider reports an update, draft update, or flags update.
    Updated,
    /// Provider reports deletion of the entity.
    Deleted,
}

/// Content-free normalized change from one legacy Mail event response.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct ObservedMailboxChange {
    entity: MailboxChangeEntity,
    kind: MailboxChangeKind,
    id: String,
}

impl ObservedMailboxChange {
    /// Returns the provider-neutral entity kind.
    #[must_use]
    pub const fn entity(&self) -> MailboxChangeEntity {
        self.entity
    }

    /// Returns the provider-neutral mutation class.
    #[must_use]
    pub const fn kind(&self) -> MailboxChangeKind {
        self.kind
    }

    /// Returns the bounded opaque provider identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl fmt::Debug for ObservedMailboxChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedMailboxChange")
            .field("entity", &self.entity)
            .field("kind", &self.kind)
            .field("id", &"<redacted>")
            .finish()
    }
}

/// Sanitized evidence from one completed Mail core-event poll.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedMailboxEventWatermark {
    requested_event_id: String,
    response_event_id: String,
    more: bool,
    refresh: bool,
    changes: Vec<ObservedMailboxChange>,
    count_changes: bool,
}

impl ObservedMailboxEventWatermark {
    /// Maximum decoded event-response body retained for immediate projection.
    pub const MAX_BODY_BYTES: usize = MAX_EVENT_BODY_BYTES;

    // jig-ignore-next-line: canonical rustfmt line.
    pub(crate) fn validate_event_id(event_id: &str) -> Result<(), MailboxEventWatermarkError> {
        if valid_event_id(event_id) {
            return Ok(());
        }
        Err(MailboxEventWatermarkError::Malformed)
    }

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
        Self::parse_body(requested_event_id, body)
    }

    // jig-ignore-next-line: canonical rustfmt line.
    /// Projects one decoded `Network.getResponseBody` result for a proven event.
    ///
    /// # Errors
    ///
    /// Rejects invalid requested watermarks, malformed CDP envelopes, base64
    /// bodies, oversized bodies, and invalid event metadata.
    pub fn parse_cdp_body(
        requested_event_id: &str,
        result: &Value,
    ) -> Result<Self, MailboxEventWatermarkError> {
        if !valid_event_id(requested_event_id) {
            return Err(MailboxEventWatermarkError::Malformed);
        }
        let encoded = result
            .get("base64Encoded")
            .and_then(Value::as_bool)
            .ok_or(MailboxEventWatermarkError::Malformed)?;
        if encoded {
            return Err(MailboxEventWatermarkError::UnsupportedEncoding);
        }
        let body = result
            .get("body")
            .and_then(Value::as_str)
            .ok_or(MailboxEventWatermarkError::Malformed)?;
        Self::parse_body(requested_event_id, body)
    }

    fn parse_body(
        requested_event_id: &str,
        body: &str,
    ) -> Result<Self, MailboxEventWatermarkError> {
        if body.len() > MAX_EVENT_BODY_BYTES {
            return Err(MailboxEventWatermarkError::BodyTooLarge);
        }
        let value: Value =
            // jig-ignore-next-line: canonical rustfmt line.
            serde_json::from_str(body).map_err(|_error| MailboxEventWatermarkError::Malformed)?;
        let response_event_id = value
            .get("EventID")
            .and_then(Value::as_str)
            .filter(|id| valid_event_id(id))
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
                .map(|code| code & MAIL_REFRESH_BIT != 0)
                .ok_or(MailboxEventWatermarkError::Malformed)?,
        };
        let changes = project_mailbox_changes(&value)?;
        let count_changes = ["MessageCounts", "ConversationCounts"]
            .into_iter()
            .try_fold(false, |changed, key| {
                Ok(changed || event_collection_nonempty(&value, key)?)
            })?;
        Ok(Self {
            requested_event_id: String::from(requested_event_id),
            response_event_id: String::from(response_event_id),
            more,
            refresh,
            changes,
            count_changes,
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
        !self.changes.is_empty() || self.count_changes
    }

    /// Returns normalized message/conversation changes in response order.
    #[must_use]
    pub fn changes(&self) -> &[ObservedMailboxChange] {
        &self.changes
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
            .field("change_count", &self.changes.len())
            .field("count_changes", &self.count_changes)
            .finish()
    }
}

/// Bounded, exactly chained legacy Mail event sequence.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedMailboxEventSequence {
    start_event_id: String,
    next_event_id: String,
    changes: Vec<ObservedMailboxChange>,
    seen_changes: BTreeSet<ObservedMailboxChange>,
    count_changes: bool,
    page_count: usize,
    settled: bool,
}

impl ObservedMailboxEventSequence {
    /// Starts one event sequence from a validated provider response.
    ///
    /// # Errors
    ///
    /// Rejects refresh responses and non-advancing continuation pages.
    // jig-ignore-next-line: canonical rustfmt line.
    pub fn start(first: ObservedMailboxEventWatermark) -> Result<Self, MailboxEventSequenceError> {
        if first.refresh {
            return Err(MailboxEventSequenceError::RefreshRequired);
        }
        if first.more && first.requested_event_id == first.response_event_id {
            return Err(MailboxEventSequenceError::NonAdvancingContinuation);
        }
        let seen_changes = first.changes.iter().cloned().collect();
        Ok(Self {
            start_event_id: first.requested_event_id,
            next_event_id: first.response_event_id,
            changes: first.changes,
            seen_changes,
            count_changes: first.count_changes,
            page_count: 1,
            settled: !first.more,
        })
    }

    /// Appends the exact next provider event page.
    ///
    /// # Errors
    ///
    /// Rejects gaps, pages after settlement, refresh, non-advancing `More`, and
    /// bounded page/change capacity exhaustion.
    pub fn push(
        &mut self,
        page: ObservedMailboxEventWatermark,
    ) -> Result<(), MailboxEventSequenceError> {
        if self.settled {
            return Err(MailboxEventSequenceError::AlreadySettled);
        }
        if self.page_count >= MAX_EVENT_SEQUENCE_PAGES {
            return Err(MailboxEventSequenceError::TooManyPages);
        }
        if page.requested_event_id != self.next_event_id {
            return Err(MailboxEventSequenceError::CursorGap);
        }
        if page.refresh {
            return Err(MailboxEventSequenceError::RefreshRequired);
        }
        if page.more && page.requested_event_id == page.response_event_id {
            return Err(MailboxEventSequenceError::NonAdvancingContinuation);
        }
        for change in page.changes {
            if self.seen_changes.insert(change.clone()) {
                if self.changes.len() >= MAX_EVENT_SEQUENCE_CHANGES {
                    return Err(MailboxEventSequenceError::TooManyChanges);
                }
                self.changes.push(change);
            }
        }
        self.count_changes |= page.count_changes;
        self.next_event_id = page.response_event_id;
        self.page_count = self
            .page_count
            .checked_add(1)
            .ok_or(MailboxEventSequenceError::TooManyPages)?;
        self.settled = !page.more;
        Ok(())
    }

    /// Returns whether the provider sequence reached `More=0` without refresh.
    #[must_use]
    pub const fn settled(&self) -> bool {
        self.settled
    }

    /// Returns the bounded opaque cursor from which this sequence began.
    #[must_use]
    pub fn start_event_id(&self) -> &str {
        &self.start_event_id
    }

    /// Returns the bounded opaque cursor for the next observation.
    #[must_use]
    pub fn next_event_id(&self) -> &str {
        &self.next_event_id
    }

    /// Binds the settled next provider watermark to a public cursor scope.
    ///
    /// # Errors
    ///
    /// Rejects a cursor request before the provider sequence reaches `More=0`.
    pub fn bind_next_cursor(
        &self,
        scope: EventCursorScope,
    ) -> Result<ScopedEventCursor<String>, MailboxEventSequenceError> {
        if !self.settled {
            return Err(MailboxEventSequenceError::CursorBeforeSettlement);
        }
        Ok(scope.bind(self.next_event_id.clone()))
    }

    /// Returns normalized changes in stable provider sequence order.
    #[must_use]
    pub fn changes(&self) -> &[ObservedMailboxChange] {
        &self.changes
    }

    /// Returns whether mailbox-count-only signals were also observed.
    #[must_use]
    pub const fn count_changes(&self) -> bool {
        self.count_changes
    }

    /// Returns the number of exactly chained provider pages.
    #[must_use]
    pub const fn page_count(&self) -> usize {
        self.page_count
    }
}

impl fmt::Debug for ObservedMailboxEventSequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedMailboxEventSequence")
            .field("start_event_id", &"<redacted>")
            .field("next_event_id", &"<redacted>")
            .field("change_count", &self.changes.len())
            .field("seen_changes", &self.seen_changes.len())
            .field("count_changes", &self.count_changes)
            .field("page_count", &self.page_count)
            .field("settled", &self.settled)
            .finish()
    }
}

/// Provider-neutral bounded change page plus its resumable next cursor.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedMailboxChangePage {
    changes: Vec<ObservedMailboxChange>,
    count_changes: bool,
    next_cursor: ScopedEventCursor<String>,
}

impl ObservedMailboxChangePage {
    /// Creates an empty initial page from a captured bootstrap watermark.
    #[must_use]
    pub fn from_bootstrap(
        scope: EventCursorScope,
        bootstrap: &ObservedLatestMailboxEventWatermark,
    ) -> Self {
        Self {
            changes: Vec::new(),
            count_changes: false,
            next_cursor: bootstrap.bind_cursor(scope),
        }
    }

    // jig-ignore-next-line: canonical rustfmt line.
    /// Creates an empty timed-out page while preserving its acknowledged cursor.
    #[must_use]
    pub const fn from_timeout(next_cursor: ScopedEventCursor<String>) -> Self {
        Self {
            changes: Vec::new(),
            count_changes: false,
            next_cursor,
        }
    }

    /// Projects one settled provider sequence into a provider-neutral page.
    ///
    /// # Errors
    ///
    /// Rejects a sequence that has not reached provider `More=0` settlement.
    pub fn from_sequence(
        scope: EventCursorScope,
        sequence: ObservedMailboxEventSequence,
    ) -> Result<Self, MailboxEventSequenceError> {
        let next_cursor = sequence.bind_next_cursor(scope)?;
        Ok(Self {
            changes: sequence.changes,
            count_changes: sequence.count_changes,
            next_cursor,
        })
    }

    /// Returns ordered normalized mailbox changes.
    #[must_use]
    pub fn changes(&self) -> &[ObservedMailboxChange] {
        &self.changes
    }

    /// Returns whether count-only mailbox change signals were also observed.
    #[must_use]
    pub const fn count_changes(&self) -> bool {
        self.count_changes
    }

    /// Returns the account/adapter/generation-bound next cursor.
    #[must_use]
    pub const fn next_cursor(&self) -> &ScopedEventCursor<String> {
        &self.next_cursor
    }

    pub(crate) fn into_parts(
        self,
    ) -> (Vec<ObservedMailboxChange>, bool, ScopedEventCursor<String>) {
        (self.changes, self.count_changes, self.next_cursor)
    }
}

impl fmt::Debug for ObservedMailboxChangePage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedMailboxChangePage")
            .field("change_count", &self.changes.len())
            .field("count_changes", &self.count_changes)
            .field("next_cursor", &"<redacted>")
            .finish()
    }
}

/// Fail-closed errors for exact legacy Mail event sequence assembly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxEventSequenceError {
    /// A page did not request the previous page's response watermark.
    CursorGap,
    /// Provider requested another page without advancing its watermark.
    NonAdvancingContinuation,
    /// Provider requested a refresh that invalidates resumable event state.
    RefreshRequired,
    /// A page was supplied after the sequence had already settled.
    AlreadySettled,
    /// Too many provider event pages were chained in one bounded sequence.
    TooManyPages,
    /// Too many distinct normalized changes were retained in one sequence.
    TooManyChanges,
    /// A public next cursor was requested before `More=0` settlement.
    CursorBeforeSettlement,
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
    /// Chromium returned an encoded body instead of decoded JSON text.
    UnsupportedEncoding,
    /// Event response contained too many normalized mailbox changes.
    TooManyChanges,
}

fn network_request_id(event: &Value) -> Result<&str, MailboxEventNetworkError> {
    event
        .get("params")
        .and_then(|params| params.get("requestId"))
        .and_then(Value::as_str)
        .ok_or(MailboxEventNetworkError::MalformedEvent)
}

fn is_latest_event_url(url: &str) -> bool {
    if url.contains('#') {
        return false;
    }
    url.split_once('?').map_or(url, |(path, _query)| path) == LATEST_EVENT_URL
}

fn event_id_from_url(url: &str) -> Result<&str, MailboxEventWatermarkError> {
    if url.contains('#') {
        return Err(MailboxEventWatermarkError::UnexpectedEndpoint);
    }
    let path = url.split_once('?').map_or(url, |(path, _query)| path);
    let Some(event_id) = path.strip_prefix(CORE_EVENT_URL_PREFIX) else {
        return Err(MailboxEventWatermarkError::UnexpectedEndpoint);
    };
    if !valid_event_id(event_id) {
        return Err(MailboxEventWatermarkError::UnexpectedEndpoint);
    }
    Ok(event_id)
}

fn valid_event_id(event_id: &str) -> bool {
    !event_id.is_empty()
        && event_id.len() <= MAX_EVENT_ID_BYTES
        && !event_id.contains(['/', '?', '#'])
}

fn project_mailbox_changes(
    value: &Value,
) -> Result<Vec<ObservedMailboxChange>, MailboxEventWatermarkError> {
    let mut changes = Vec::new();
    let mut seen = BTreeSet::new();
    for (key, entity) in [
        ("Messages", MailboxChangeEntity::Message),
        ("Conversations", MailboxChangeEntity::Conversation),
    ] {
        let Some(collection) = value.get(key) else {
            continue;
        };
        if collection.is_null() {
            continue;
        }
        let items = collection
            .as_array()
            .ok_or(MailboxEventWatermarkError::Malformed)?;
        for item in items {
            let id = item
                .get("ID")
                .and_then(Value::as_str)
                .filter(|id| valid_event_id(id))
                .ok_or(MailboxEventWatermarkError::Malformed)?;
            let action = item
                .get("Action")
                .and_then(Value::as_u64)
                .ok_or(MailboxEventWatermarkError::Malformed)?;
            let kind = match action {
                0 => MailboxChangeKind::Deleted,
                1 => MailboxChangeKind::Created,
                2 | 3 => MailboxChangeKind::Updated,
                _ => return Err(MailboxEventWatermarkError::Malformed),
            };
            let key = (entity, kind, String::from(id));
            if seen.insert(key.clone()) {
                if changes.len() >= MAX_PROJECTED_CHANGES {
                    return Err(MailboxEventWatermarkError::TooManyChanges);
                }
                changes.push(ObservedMailboxChange {
                    entity,
                    kind,
                    id: key.2,
                });
            }
        }
    }
    Ok(changes)
}

// jig-ignore-next-line: canonical rustfmt line.
fn event_collection_nonempty(value: &Value, key: &str) -> Result<bool, MailboxEventWatermarkError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Array(items)) => Ok(!items.is_empty()),
        Some(_) => Err(MailboxEventWatermarkError::Malformed),
    }
}
