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
//   - Bounded projection of one complete Proton Mail conversation-detail GET.
// - Must-Not:
//   - Retain message bodies, headers, recipients, attachments, cryptographic
//     fields, cookies, tokens, or parameterized conversation slices.
// - Allows:
//   - Bind a conversation ID to its complete bounded member-message identity.
// - Split-When:
//   - Per-message plaintext content or public thread mapping is implemented.
// - Merge-When:
//   - One reviewed thread adapter owns membership plus message content.
// - Summary:
//   - Proves exact conversation membership without retaining message content.
// - Description:
//   - Tracks unparameterized mail-v4 conversation GETs and validates count.
// - Usage:
//   - Managed-browser diagnostics may consume this after app-owned fetches.
// - Defaults:
//   - Partial, parameterized, malformed, or oversized evidence fails closed.
//

//! Complete bounded membership projection for one Proton Mail conversation.

use crate::request_id_custody::discard_request_id;
use crate::request_id_custody::retain_request_ids;
use crate::request_id_custody::scrub_all_request_ids;
use crate::response_provenance::ExtraStatusEvidence;
use crate::response_provenance::direct_extra_status_is_200;
use crate::response_provenance::uncached_provider_response;
use crate::strict_json;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::driver::safe_cdp_request_id;
use crate::opaque_read_id::safe_read_id;
use serde_json::Value;
use zeroize::{Zeroize as _, Zeroizing};

// jig-ignore-next-line: canonical rustfmt line.
const CONVERSATION_DETAIL_URL_PREFIX: &str = "https://mail.proton.me/api/mail/v4/conversations/";
const MAX_CONVERSATION_DETAIL_BODY_BYTES: usize = 8 * 1_024 * 1_024;
const MAX_CONVERSATION_ID_BYTES: usize = 512;
const MAX_MESSAGE_ID_BYTES: usize = 512;
const MAX_CONVERSATION_MESSAGES: usize = 512;
const MAX_TRACKED_CONVERSATION_DETAIL_REQUESTS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConversationDetailRequestState {
    Requested,
    Responded,
    Finished,
}

#[derive(Clone, Eq, PartialEq)]
struct TrackedConversationDetailRequest {
    state: ConversationDetailRequestState,
    extra_status: ExtraStatusEvidence,
    conversation_id: Zeroizing<String>,
}

impl fmt::Debug for TrackedConversationDetailRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrackedConversationDetailRequest")
            .field("state", &self.state)
            .field("extra_status", &self.extra_status)
            .field("conversation_id", &"<redacted>")
            .finish()
    }
}

/// Bounded CDP lifecycle state for exact unparameterized conversation GETs.
#[derive(Clone, Eq, PartialEq)]
pub struct ConversationDetailNetworkCapture {
    session_id: Zeroizing<String>,
    requests: BTreeMap<String, TrackedConversationDetailRequest>,
    completed_ids: BTreeSet<String>,
}

#[expect(
    clippy::missing_trait_methods,
    reason = "Drop scrubs retained CDP request correlation identifiers"
)]
impl Drop for ConversationDetailNetworkCapture {
    fn drop(&mut self) {
        scrub_all_request_ids(&mut self.requests, &mut self.completed_ids);
    }
}

impl ConversationDetailNetworkCapture {
    /// Creates an empty capture scoped to one flattened CDP target session.
    #[must_use]
    pub fn new(session_id: &str) -> Self {
        Self {
            session_id: Zeroizing::new(String::from(session_id)),
            requests: BTreeMap::new(),
            completed_ids: BTreeSet::new(),
        }
    }

    /// Consumes one unsolicited CDP event without retaining headers or bodies.
    ///
    /// # Errors
    ///
    /// Exact matching requests fail closed on redirect, lifecycle drift,
    /// unsafe response metadata, or bounded-capacity exhaustion.
    // jig-ignore-next-line: canonical rustfmt line.
    pub fn observe(&mut self, event: &Value) -> Result<(), ConversationDetailNetworkError> {
        // jig-ignore-next-line: canonical rustfmt line.
        if event.get("sessionId").and_then(Value::as_str) != Some(self.session_id.as_str()) {
            return Ok(());
        }
        match event.get("method").and_then(Value::as_str) {
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

    /// Removes completed requests as request ID plus conversation ID.
    pub fn take_finished_requests(&mut self) -> Vec<(String, String)> {
        let finished = self
            .requests
            .iter()
            .filter(|(_id, request)| {
                request.state == ConversationDetailRequestState::Finished
                    && request.extra_status.ready()
            })
            .map(|(request_id, request)| {
                (
                    request_id.clone(),
                    String::from(request.conversation_id.as_str()),
                )
            })
            .collect::<Vec<_>>();
        retain_request_ids(&mut self.requests, |request| {
            request.state != ConversationDetailRequestState::Finished
                || !request.extra_status.ready()
        });
        for (request_id, _conversation_id) in &finished {
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
    fn observe_request(&mut self, event: &Value) -> Result<(), ConversationDetailNetworkError> {
        let params = event
            .get("params")
            .ok_or(ConversationDetailNetworkError::MalformedEvent)?;
        let request_id = params
            .get("requestId")
            .and_then(Value::as_str)
            .ok_or(ConversationDetailNetworkError::MalformedEvent)?;
        let request = params
            .get("request")
            .ok_or(ConversationDetailNetworkError::MalformedEvent)?;
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or(ConversationDetailNetworkError::MalformedEvent)?;
        let url = request
            .get("url")
            .and_then(Value::as_str)
            .ok_or(ConversationDetailNetworkError::MalformedEvent)?;
        let conversation_id = if method == "GET" {
            conversation_id_from_detail_url(url)
                // jig-ignore-next-line: canonical rustfmt line.
                .map_err(|_error| ConversationDetailNetworkError::MalformedEvent)?
        } else {
            None
        };
        if self.completed_ids.contains(request_id) {
            return Err(ConversationDetailNetworkError::InvalidSequence);
        }
        if let Some(existing) = self.requests.get(request_id) {
            if conversation_id != Some(existing.conversation_id.as_str()) {
                return Err(ConversationDetailNetworkError::RedirectedAway);
            }
            return Err(ConversationDetailNetworkError::InvalidSequence);
        }
        let Some(conversation_id) = conversation_id else {
            return Ok(());
        };
        // CDP reuses the request ID when an untracked URL redirects here.
        if params.get("redirectResponse").is_some() {
            return Err(ConversationDetailNetworkError::RedirectedAway);
        }
        if !safe_cdp_request_id(request_id) {
            return Err(ConversationDetailNetworkError::MalformedEvent);
        }
        if self.requests.len().saturating_add(self.completed_ids.len())
            >= MAX_TRACKED_CONVERSATION_DETAIL_REQUESTS
        {
            return Err(ConversationDetailNetworkError::CapacityExceeded);
        }
        self.requests.insert(
            String::from(request_id),
            TrackedConversationDetailRequest {
                state: ConversationDetailRequestState::Requested,
                extra_status: ExtraStatusEvidence::default(),
                conversation_id: Zeroizing::new(String::from(conversation_id)),
            },
        );
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_response(&mut self, event: &Value) -> Result<(), ConversationDetailNetworkError> {
        let params = event
            .get("params")
            .ok_or(ConversationDetailNetworkError::MalformedEvent)?;
        let request_id = params
            .get("requestId")
            .and_then(Value::as_str)
            .ok_or(ConversationDetailNetworkError::MalformedEvent)?;
        if self.completed_ids.contains(request_id) {
            return Err(ConversationDetailNetworkError::InvalidSequence);
        }
        let Some(request) = self.requests.get_mut(request_id) else {
            return Ok(());
        };
        if request.state != ConversationDetailRequestState::Requested {
            return Err(ConversationDetailNetworkError::InvalidSequence);
        }
        let response = params
            .get("response")
            .ok_or(ConversationDetailNetworkError::MalformedEvent)?;
        let url = response
            .get("url")
            .and_then(Value::as_str)
            .ok_or(ConversationDetailNetworkError::MalformedEvent)?;
        let response_conversation_id = conversation_id_from_detail_url(url)
            // jig-ignore-next-line: canonical rustfmt line.
            .map_err(|_error| ConversationDetailNetworkError::ResponseRejected)?;
        let status = response.get("status").and_then(Value::as_u64);
        let mime = response.get("mimeType").and_then(Value::as_str);
        if response_conversation_id != Some(request.conversation_id.as_str())
            || status != Some(200)
            || !uncached_provider_response(response)
            || mime != Some("application/json")
        {
            return Err(ConversationDetailNetworkError::ResponseRejected);
        }
        if !request.extra_status.note_response(params) {
            return Err(ConversationDetailNetworkError::ResponseRejected);
        }
        request.state = ConversationDetailRequestState::Responded;
        Ok(())
    }

    // The actual HTTP-200 status can arrive before or after loadingFinished.
    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_extra_200(&mut self, event: &Value) -> Result<(), ConversationDetailNetworkError> {
        let request_id = network_request_id(event)?;
        if self.completed_ids.contains(request_id) {
            return Err(ConversationDetailNetworkError::InvalidSequence);
        }
        if let Some(request) = self.requests.get_mut(request_id)
            && !request.extra_status.note_200()
        {
            return Err(ConversationDetailNetworkError::InvalidSequence);
        }
        Ok(())
    }

    // A cache hit can arrive before or after responseReceived. Either order
    // disqualifies this exact request from establishing fresh provider state.
    // jig-ignore-next-line: rustfmt callback signature.
    fn observe_cache_hit(&self, event: &Value) -> Result<(), ConversationDetailNetworkError> {
        let request_id = network_request_id(event)?;
        if self.completed_ids.contains(request_id) {
            return Err(ConversationDetailNetworkError::InvalidSequence);
        }
        if self.requests.contains_key(request_id) {
            return Err(ConversationDetailNetworkError::ResponseRejected);
        }
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_finished(&mut self, event: &Value) -> Result<(), ConversationDetailNetworkError> {
        let request_id = network_request_id(event)?;
        if self.completed_ids.contains(request_id) {
            return Err(ConversationDetailNetworkError::InvalidSequence);
        }
        let Some(request) = self.requests.get_mut(request_id) else {
            return Ok(());
        };
        if request.state != ConversationDetailRequestState::Responded {
            return Err(ConversationDetailNetworkError::InvalidSequence);
        }
        request.state = ConversationDetailRequestState::Finished;
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_failed(&mut self, event: &Value) -> Result<(), ConversationDetailNetworkError> {
        let request_id = network_request_id(event)?;
        if self.completed_ids.contains(request_id) {
            return Err(ConversationDetailNetworkError::InvalidSequence);
        }
        if self
            .requests
            .get(request_id)
            // jig-ignore-next-line: canonical rustfmt line.
            .is_some_and(|request| request.state == ConversationDetailRequestState::Finished)
        {
            return Err(ConversationDetailNetworkError::InvalidSequence);
        }
        discard_request_id(&mut self.requests, request_id);
        Ok(())
    }
}

impl fmt::Debug for ConversationDetailNetworkCapture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConversationDetailNetworkCapture")
            .field("session_id", &"<redacted>")
            .field("tracked_request_count", &self.requests.len())
            .field("completed_request_count", &self.completed_ids.len())
            .finish()
    }
}

/// Why exact conversation-detail Network evidence failed closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationDetailNetworkError {
    /// Required CDP event structure or endpoint shape was malformed.
    MalformedEvent,
    /// A tracked request redirected away from its exact conversation endpoint.
    RedirectedAway,
    /// A tracked response changed identity or was not HTTP 200 JSON.
    ResponseRejected,
    /// A lifecycle event repeated or arrived out of sequence.
    InvalidSequence,
    /// Too many unfinished exact conversation requests are retained.
    CapacityExceeded,
}

/// One bounded member identity from a complete conversation response.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedConversationMember {
    message_id: String,
    time: u64,
}

#[expect(
    clippy::missing_trait_methods,
    reason = "Drop is the explicit scrub-on-drop contract"
)]
impl Drop for ObservedConversationMember {
    fn drop(&mut self) {
        self.message_id.zeroize();
    }
}

impl ObservedConversationMember {
    /// Returns the opaque provider message identifier.
    #[must_use]
    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    /// Returns provider numeric `Time` without assigning public semantics.
    #[must_use]
    pub const fn time(&self) -> u64 {
        self.time
    }
}

impl fmt::Debug for ObservedConversationMember {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedConversationMember")
            .field("message_id", &"<redacted>")
            .field("time", &"<redacted>")
            .finish()
    }
}

/// Content-minimized complete membership of one provider conversation.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedConversationDetail {
    conversation_id: String,
    reported_message_count: usize,
    members: Vec<ObservedConversationMember>,
}

#[expect(
    clippy::missing_trait_methods,
    reason = "Drop is the explicit scrub-on-drop contract"
)]
impl Drop for ObservedConversationDetail {
    fn drop(&mut self) {
        self.conversation_id.zeroize();
        // Members own and scrub their message IDs.
    }
}

impl ObservedConversationDetail {
    /// Returns the provider conversation identifier.
    #[must_use]
    pub fn conversation_id(&self) -> &str {
        &self.conversation_id
    }

    /// Returns the provider-reported complete message count.
    #[must_use]
    pub const fn reported_message_count(&self) -> usize {
        self.reported_message_count
    }

    /// Returns complete bounded members in provider response order.
    #[must_use]
    pub fn members(&self) -> &[ObservedConversationMember] {
        &self.members
    }
}

impl fmt::Debug for ObservedConversationDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedConversationDetail")
            .field("conversation_id", &"<redacted>")
            .field("reported_message_count", &self.reported_message_count)
            .field("member_count", &self.members.len())
            .finish()
    }
}

/// One exact safe projection of a complete conversation-detail response.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedConversationDetailResponse {
    conversation: ObservedConversationDetail,
}

impl ObservedConversationDetailResponse {
    /// Maximum decoded JSON response accepted by this boundary.
    pub const MAX_BODY_BYTES: usize = MAX_CONVERSATION_DETAIL_BODY_BYTES;

    /// Parses one exact unparameterized conversation GET.
    ///
    /// # Errors
    ///
    /// Rejects endpoint/identity drift, malformed or oversized JSON, count
    /// mismatch, duplicate message IDs, parent mismatch, or excessive members.
    pub fn parse(
        method: &str,
        url: &str,
        body: &str,
    ) -> Result<Self, ConversationDetailResponseError> {
        let expected_id = if method == "GET" {
            conversation_id_from_detail_url(url)?
        } else {
            None
        }
        .ok_or(ConversationDetailResponseError::UnexpectedEndpoint)?;
        Self::parse_expected_id(expected_id, body)
    }

    // The CDP envelope already binds the validated exact conversation ID.
    // Project its body without a temporary unguarded URL string.
    fn parse_expected_id(
        expected_id: &str,
        body: &str,
    ) -> Result<Self, ConversationDetailResponseError> {
        if body.len() > Self::MAX_BODY_BYTES {
            return Err(ConversationDetailResponseError::BodyTooLarge);
        }
        let value = strict_json::from_sensitive_slice(body.as_bytes())
            .map_err(|_error| ConversationDetailResponseError::Malformed)?;
        if value.get("Code").and_then(Value::as_u64) != Some(1000) {
            return Err(ConversationDetailResponseError::ProviderRejected);
        }
        let conversation = value
            .get("Conversation")
            .and_then(Value::as_object)
            .ok_or(ConversationDetailResponseError::Malformed)?;
        // Borrow the ID from guarded provider JSON until all validation ends.
        let conversation_id =
            // jig-ignore-next-line: canonical rustfmt line.
            bounded_required_str(conversation, "ID", MAX_CONVERSATION_ID_BYTES)?;
        if conversation_id != expected_id {
            return Err(ConversationDetailResponseError::IdentityMismatch);
        }
        let reported_u64 = conversation
            .get("NumMessages")
            .and_then(Value::as_u64)
            .ok_or(ConversationDetailResponseError::Malformed)?;
        let reported_message_count = usize::try_from(reported_u64)
            // jig-ignore-next-line: canonical rustfmt line.
            .map_err(|_error| ConversationDetailResponseError::TooManyMessages)?;
        if reported_message_count > MAX_CONVERSATION_MESSAGES {
            return Err(ConversationDetailResponseError::TooManyMessages);
        }
        let messages = value
            .get("Messages")
            .and_then(Value::as_array)
            .ok_or(ConversationDetailResponseError::IncompleteConversation)?;
        if messages.len() != reported_message_count {
            return Err(ConversationDetailResponseError::IncompleteConversation);
        }
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut members = Vec::with_capacity(messages.len());
        for message in messages {
            let object = message
                .as_object()
                .ok_or(ConversationDetailResponseError::Malformed)?;
            // The guarded source ID is also the duplicate-detection key;
            // allocate owned metadata only after parent and time validation.
            // jig-ignore-next-line: rustfmt keeps the borrowed ID check flat.
            let message_id = bounded_required_str(object, "ID", MAX_MESSAGE_ID_BYTES)?;
            if !seen.insert(message_id) {
                return Err(ConversationDetailResponseError::DuplicateMessageId);
            }
            let parent =
                // jig-ignore-next-line: canonical rustfmt line.
                bounded_required_str(object, "ConversationID", MAX_CONVERSATION_ID_BYTES)?;
            if parent != conversation_id {
                return Err(ConversationDetailResponseError::ParentMismatch);
            }
            let time = object
                .get("Time")
                .and_then(Value::as_u64)
                .ok_or(ConversationDetailResponseError::Malformed)?;
            members.push(ObservedConversationMember {
                message_id: String::from(message_id),
                time,
            });
        }
        Ok(Self {
            conversation: ObservedConversationDetail {
                conversation_id: String::from(conversation_id),
                reported_message_count,
                members,
            },
        })
    }

    /// Projects one decoded `Network.getResponseBody` envelope.
    ///
    /// # Errors
    ///
    /// Rejects encoded envelopes and every invalid response rejected by parse.
    pub fn parse_cdp_body(
        conversation_id: &str,
        result: &Value,
    ) -> Result<Self, ConversationDetailResponseError> {
        if !safe_read_id(conversation_id, MAX_CONVERSATION_ID_BYTES) {
            return Err(ConversationDetailResponseError::UnexpectedEndpoint);
        }
        // Only accept the exact decoded CDP envelope owned by our request.
        if result.as_object().is_none_or(|fields| fields.len() != 2) {
            return Err(ConversationDetailResponseError::Malformed);
        }
        let encoded = result
            .get("base64Encoded")
            .and_then(Value::as_bool)
            .ok_or(ConversationDetailResponseError::Malformed)?;
        if encoded {
            return Err(ConversationDetailResponseError::UnsupportedEncoding);
        }
        let body = result
            .get("body")
            .and_then(Value::as_str)
            .ok_or(ConversationDetailResponseError::Malformed)?;
        Self::parse_expected_id(conversation_id, body)
    }

    /// Returns the content-minimized complete membership.
    #[must_use]
    pub const fn conversation(&self) -> &ObservedConversationDetail {
        &self.conversation
    }
}

impl fmt::Debug for ObservedConversationDetailResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedConversationDetailResponse")
            .field("conversation", &self.conversation)
            .finish()
    }
}

/// Why one conversation-detail body failed bounded projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationDetailResponseError {
    /// Method or URL was not an exact unparameterized conversation GET.
    UnexpectedEndpoint,
    /// Decoded JSON exceeded the boundary cap.
    BodyTooLarge,
    /// Provider JSON was malformed or required fields had invalid types.
    Malformed,
    /// Provider success code was absent or not `1000`.
    ProviderRejected,
    /// Response conversation ID did not equal the requested opaque ID.
    IdentityMismatch,
    /// `Messages` is missing or disagrees with `Conversation.NumMessages`.
    IncompleteConversation,
    /// Message count exceeds the bounded complete-thread membership ceiling.
    TooManyMessages,
    /// Two member entries reused the same message ID.
    DuplicateMessageId,
    /// A member claimed a different parent conversation ID.
    ParentMismatch,
    /// `Network.getResponseBody` returned an encoded envelope.
    UnsupportedEncoding,
}

fn conversation_id_from_detail_url(
    url: &str,
) -> Result<Option<&str>, ConversationDetailResponseError> {
    // jig-ignore-next-line: canonical rustfmt line.
    let Some(conversation_id) = url.strip_prefix(CONVERSATION_DETAIL_URL_PREFIX) else {
        return Ok(None);
    };
    if !safe_read_id(conversation_id, MAX_CONVERSATION_ID_BYTES) {
        return Err(ConversationDetailResponseError::UnexpectedEndpoint);
    }
    Ok(Some(conversation_id))
}

// jig-ignore-next-line: canonical rustfmt line.
fn network_request_id(event: &Value) -> Result<&str, ConversationDetailNetworkError> {
    event
        .get("params")
        .and_then(|params| params.get("requestId"))
        .and_then(Value::as_str)
        .ok_or(ConversationDetailNetworkError::MalformedEvent)
}

fn bounded_required_str<'source>(
    object: &'source serde_json::Map<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<&'source str, ConversationDetailResponseError> {
    let value = object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(ConversationDetailResponseError::Malformed)?;
    if !safe_read_id(value, max_bytes) {
        return Err(ConversationDetailResponseError::Malformed);
    }
    Ok(value)
}

#[cfg(test)]
#[path = "../../../../tests/mail/web/adapter-outbound/dbg_convo.rs"]
mod private_request_diagnostics_tests;
