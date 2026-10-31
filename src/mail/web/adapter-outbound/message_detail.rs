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
//   - Bounded projection of one browser-owned Proton Mail message-detail GET.
// - Must-Not:
//   - Retain message body, raw headers, parsed headers, password material,
//     cryptographic packets/signatures, attachment bytes, cookies, or tokens.
// - Allows:
//   - Retain opaque identity, envelope metadata, provider time/read state,
//     label IDs, MIME type, and bounded attachment descriptors.
// - Split-When:
//   - Plaintext body/header extraction or attachment decryption is implemented.
// - Merge-When:
//   - One reviewed read adapter owns detail metadata plus plaintext projection.
// - Summary:
//   - Reduces exact single-message responses before any public message mapping.
// - Description:
//   - Tracks exact mail-v4 message GET lifecycles and projects safe metadata.
// - Usage:
//   - A managed-browser read flow may consume this only after app-owned
//     fetches.
// - Defaults:
//   - Unrelated traffic is ignored; malformed or oversized evidence fails
//     closed.
//

//! Bounded metadata projection for one Proton Mail message-detail response.

use crate::request_id_custody::discard_request_id;
use crate::request_id_custody::retain_request_ids;
use crate::request_id_custody::scrub_all_request_ids;
use crate::response_provenance::ExtraStatusEvidence;
use crate::response_provenance::bodyless_cdp_get;
use crate::response_provenance::direct_extra_status_is_200;
use crate::response_provenance::non_speculative_cdp_get;
use crate::response_provenance::uncached_provider_response;
use crate::strict_json;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::attachment_metadata::safe_metadata_mime_type;
use crate::display_text_safety::unsafe_display_character;
use crate::driver::safe_cdp_request_id;
use crate::opaque_read_id::safe_read_id;
use mail_capability_domain::SanitizedAttachmentFilename;
use serde_json::Value;
use zeroize::{Zeroize as _, Zeroizing};

// jig-ignore-next-line: canonical rustfmt line.
const MESSAGE_DETAIL_URL_PREFIX: &str = "https://mail.proton.me/api/mail/v4/messages/";
const MAX_MESSAGE_DETAIL_BODY_BYTES: usize = 8 * 1_024 * 1_024;
const MAX_MESSAGE_ID_BYTES: usize = 512;
const MAX_CONVERSATION_ID_BYTES: usize = 512;
const MAX_SUBJECT_BYTES: usize = 16_384;
const MAX_RECIPIENTS_PER_FIELD: usize = 512;
const MAX_RECIPIENT_NAME_BYTES: usize = 4_096;
const MAX_RECIPIENT_ADDRESS_BYTES: usize = 4_096;
const MAX_LABEL_IDS: usize = 2_048;
const MAX_LABEL_ID_BYTES: usize = 512;
const MAX_ATTACHMENTS: usize = 512;
const MAX_ATTACHMENT_ID_BYTES: usize = 512;
const MAX_ATTACHMENT_NAME_BYTES: usize = 4_096;
const MAX_MIME_TYPE_BYTES: usize = 512;
const MAX_TRACKED_MESSAGE_DETAIL_REQUESTS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MessageDetailRequestState {
    Requested,
    Responded,
    Finished,
}

#[derive(Clone, Eq, PartialEq)]
struct TrackedMessageDetailRequest {
    state: MessageDetailRequestState,
    extra_status: ExtraStatusEvidence,
    message_id: Zeroizing<String>,
}

impl fmt::Debug for TrackedMessageDetailRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrackedMessageDetailRequest")
            .field("state", &self.state)
            .field("extra_status", &self.extra_status)
            .field("message_id", &"<redacted>")
            .finish()
    }
}

/// Bounded CDP Network lifecycle state for exact single-message GETs.
#[derive(Clone, Eq, PartialEq)]
pub struct MessageDetailNetworkCapture {
    session_id: Zeroizing<String>,
    requests: BTreeMap<String, TrackedMessageDetailRequest>,
    completed_ids: BTreeSet<String>,
}

#[expect(
    clippy::missing_trait_methods,
    reason = "Drop scrubs retained CDP request correlation identifiers"
)]
impl Drop for MessageDetailNetworkCapture {
    fn drop(&mut self) {
        scrub_all_request_ids(&mut self.requests, &mut self.completed_ids);
    }
}

impl MessageDetailNetworkCapture {
    /// Creates an empty capture scoped to one flattened CDP target session.
    #[must_use]
    pub fn new(session_id: &str) -> Self {
        Self {
            session_id: Zeroizing::new(String::from(session_id)),
            requests: BTreeMap::new(),
            completed_ids: BTreeSet::new(),
        }
    }

    /// Consumes one unsolicited CDP event without retaining URL/header content.
    ///
    /// # Errors
    ///
    /// Exact tracked requests fail closed on redirect, malformed lifecycle,
    /// unsafe response metadata, or capacity exhaustion. A failed app-owned
    /// attempt is discarded so a later app-owned retry may be observed.
    // jig-ignore-next-line: canonical rustfmt line.
    pub fn observe(&mut self, event: &Value) -> Result<(), MessageDetailNetworkError> {
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

    /// Removes completed exact detail requests as request ID plus message ID.
    pub fn take_finished_requests(&mut self) -> Vec<(String, String)> {
        let finished = self
            .requests
            .iter()
            .filter(|(_id, request)| {
                // jig-ignore-next-line: rustfmt status guard.
                request.state == MessageDetailRequestState::Finished && request.extra_status.ready()
            })
            .map(|(request_id, request)| {
                (
                    request_id.clone(),
                    String::from(request.message_id.as_str()),
                )
            })
            .collect::<Vec<_>>();
        retain_request_ids(&mut self.requests, |request| {
            // jig-ignore-next-line: rustfmt status guard.
            request.state != MessageDetailRequestState::Finished || !request.extra_status.ready()
        });
        for (request_id, _message_id) in &finished {
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
    fn observe_request(&mut self, event: &Value) -> Result<(), MessageDetailNetworkError> {
        let params = event
            .get("params")
            .ok_or(MessageDetailNetworkError::MalformedEvent)?;
        let request_id = params
            .get("requestId")
            .and_then(Value::as_str)
            .ok_or(MessageDetailNetworkError::MalformedEvent)?;
        let request = params
            .get("request")
            .ok_or(MessageDetailNetworkError::MalformedEvent)?;
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or(MessageDetailNetworkError::MalformedEvent)?;
        let url = request
            .get("url")
            .and_then(Value::as_str)
            .ok_or(MessageDetailNetworkError::MalformedEvent)?;
        let message_id = if method == "GET" {
            message_id_from_detail_url(url)?
        } else {
            None
        };
        if self.completed_ids.contains(request_id) {
            return Err(MessageDetailNetworkError::InvalidSequence);
        }
        if let Some(existing) = self.requests.get(request_id) {
            if message_id != Some(existing.message_id.as_str()) {
                return Err(MessageDetailNetworkError::RedirectedAway);
            }
            return Err(MessageDetailNetworkError::InvalidSequence);
        }
        let Some(message_id) = message_id else {
            return Ok(());
        };
        // A GET URL alone cannot prove body-free read semantics.
        if !bodyless_cdp_get(request) || !non_speculative_cdp_get(event) {
            return Err(MessageDetailNetworkError::MalformedEvent);
        }
        // A redirect from an ignored URL cannot establish fresh GET evidence.
        if params.get("redirectResponse").is_some() {
            return Err(MessageDetailNetworkError::RedirectedAway);
        }
        if !safe_cdp_request_id(request_id) {
            return Err(MessageDetailNetworkError::MalformedEvent);
        }
        if self.requests.len().saturating_add(self.completed_ids.len())
            >= MAX_TRACKED_MESSAGE_DETAIL_REQUESTS
        {
            return Err(MessageDetailNetworkError::CapacityExceeded);
        }
        self.requests.insert(
            String::from(request_id),
            TrackedMessageDetailRequest {
                state: MessageDetailRequestState::Requested,
                extra_status: ExtraStatusEvidence::default(),
                message_id: Zeroizing::new(String::from(message_id)),
            },
        );
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_response(&mut self, event: &Value) -> Result<(), MessageDetailNetworkError> {
        let params = event
            .get("params")
            .ok_or(MessageDetailNetworkError::MalformedEvent)?;
        let request_id = params
            .get("requestId")
            .and_then(Value::as_str)
            .ok_or(MessageDetailNetworkError::MalformedEvent)?;
        if self.completed_ids.contains(request_id) {
            return Err(MessageDetailNetworkError::InvalidSequence);
        }
        let Some(request) = self.requests.get_mut(request_id) else {
            return Ok(());
        };
        if request.state != MessageDetailRequestState::Requested {
            return Err(MessageDetailNetworkError::InvalidSequence);
        }
        let response = params
            .get("response")
            .ok_or(MessageDetailNetworkError::MalformedEvent)?;
        let url = response
            .get("url")
            .and_then(Value::as_str)
            .ok_or(MessageDetailNetworkError::MalformedEvent)?;
        let response_message_id = message_id_from_detail_url(url)
            .map_err(|_error| MessageDetailNetworkError::ResponseRejected)?;
        let status = response.get("status").and_then(Value::as_u64);
        let mime = response.get("mimeType").and_then(Value::as_str);
        if response_message_id != Some(request.message_id.as_str())
            || status != Some(200)
            || !uncached_provider_response(response)
            || mime != Some("application/json")
        {
            return Err(MessageDetailNetworkError::ResponseRejected);
        }
        if !request.extra_status.note_response(params) {
            return Err(MessageDetailNetworkError::ResponseRejected);
        }
        request.state = MessageDetailRequestState::Responded;
        Ok(())
    }

    // jig-ignore-next-line: rustfmt status guard.
    fn observe_extra_200(&mut self, event: &Value) -> Result<(), MessageDetailNetworkError> {
        let request_id = network_request_id(event)?;
        if self.completed_ids.contains(request_id) {
            return Err(MessageDetailNetworkError::InvalidSequence);
        }
        if let Some(request) = self.requests.get_mut(request_id)
            && !request.extra_status.note_200()
        {
            return Err(MessageDetailNetworkError::InvalidSequence);
        }
        Ok(())
    }

    // A cache hit can arrive before or after responseReceived. Either order
    // disqualifies this exact request from establishing fresh provider state.
    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_cache_hit(&self, event: &Value) -> Result<(), MessageDetailNetworkError> {
        let request_id = network_request_id(event)?;
        if self.completed_ids.contains(request_id) {
            return Err(MessageDetailNetworkError::InvalidSequence);
        }
        if self.requests.contains_key(request_id) {
            return Err(MessageDetailNetworkError::ResponseRejected);
        }
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_finished(&mut self, event: &Value) -> Result<(), MessageDetailNetworkError> {
        let request_id = network_request_id(event)?;
        if self.completed_ids.contains(request_id) {
            return Err(MessageDetailNetworkError::InvalidSequence);
        }
        let Some(request) = self.requests.get_mut(request_id) else {
            return Ok(());
        };
        if request.state != MessageDetailRequestState::Responded {
            return Err(MessageDetailNetworkError::InvalidSequence);
        }
        request.state = MessageDetailRequestState::Finished;
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_failed(&mut self, event: &Value) -> Result<(), MessageDetailNetworkError> {
        let request_id = network_request_id(event)?;
        if self.completed_ids.contains(request_id) {
            return Err(MessageDetailNetworkError::InvalidSequence);
        }
        if self
            .requests
            .get(request_id)
            // jig-ignore-next-line: canonical rustfmt line.
            .is_some_and(|request| request.state == MessageDetailRequestState::Finished)
        {
            return Err(MessageDetailNetworkError::InvalidSequence);
        }
        discard_request_id(&mut self.requests, request_id);
        Ok(())
    }
}

impl fmt::Debug for MessageDetailNetworkCapture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageDetailNetworkCapture")
            .field("session_id", &"<redacted>")
            .field("tracked_request_count", &self.requests.len())
            .field("completed_request_count", &self.completed_ids.len())
            .finish()
    }
}

/// Why exact single-message Network evidence failed closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageDetailNetworkError {
    /// Required CDP event structure is missing or malformed.
    MalformedEvent,
    /// A tracked request redirected away from its exact message endpoint.
    RedirectedAway,
    /// A tracked response changed identity or was not HTTP 200 JSON.
    ResponseRejected,
    /// A lifecycle event repeated or arrived out of sequence.
    InvalidSequence,
    /// Too many unfinished exact message-detail requests are already tracked.
    CapacityExceeded,
}

/// One bounded sender/recipient entry from provider message metadata.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedMessageRecipient {
    name: String,
    address: String,
}

#[expect(
    clippy::missing_trait_methods,
    reason = "Drop is the explicit scrub-on-drop contract"
)]
impl Drop for ObservedMessageRecipient {
    fn drop(&mut self) {
        self.name.zeroize();
        self.address.zeroize();
    }
}

impl ObservedMessageRecipient {
    /// Returns the provider-supplied recipient display name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the provider-supplied mailbox address.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }
}

impl fmt::Debug for ObservedMessageRecipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedMessageRecipient")
            .field("name", &"<redacted>")
            .field("address", &"<redacted>")
            .finish()
    }
}

/// One bounded attachment descriptor, excluding encrypted or plaintext bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedAttachmentDescriptor {
    id: Option<String>,
    name: Option<String>,
    sanitized_name: Option<SanitizedAttachmentFilename>,
    size: Option<u64>,
    mime_type: Option<String>,
}

#[expect(
    clippy::missing_trait_methods,
    reason = "Drop is the explicit scrub-on-drop contract"
)]
impl Drop for ObservedAttachmentDescriptor {
    fn drop(&mut self) {
        for field in [&mut self.id, &mut self.name, &mut self.mime_type] {
            if let Some(value) = field.as_mut() {
                value.zeroize();
            }
        }
        // SanitizedAttachmentFilename erases its own leaf on drop.
    }
}

impl ObservedAttachmentDescriptor {
    /// Returns the provider attachment identifier when addressable.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    /// Returns the provider filename metadata when present.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns a portable sanitized filename when provider metadata names one.
    #[must_use]
    pub const fn sanitized_name(&self) -> Option<&SanitizedAttachmentFilename> {
        self.sanitized_name.as_ref()
    }

    /// Returns the provider-declared byte size when present.
    #[must_use]
    pub const fn size(&self) -> Option<u64> {
        self.size
    }

    /// Returns the provider-declared MIME type when present.
    #[must_use]
    pub fn mime_type(&self) -> Option<&str> {
        self.mime_type.as_deref()
    }
}

impl fmt::Debug for ObservedAttachmentDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedAttachmentDescriptor")
            .field("id", &"<redacted>")
            .field("name", &self.name.as_ref().map(|_| "<redacted>"))
            .field(
                "sanitized_name",
                &self.sanitized_name.as_ref().map(|_| "<redacted>"),
            )
            .field("size", &self.size.map(|_| "<redacted>"))
            .field("mime_type", &self.mime_type.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Content-minimized metadata from one exact provider message response.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedMessageDetail {
    id: String,
    conversation_id: String,
    subject: String,
    sender: ObservedMessageRecipient,
    to: Vec<ObservedMessageRecipient>,
    cc: Vec<ObservedMessageRecipient>,
    bcc: Vec<ObservedMessageRecipient>,
    time: u64,
    unread: bool,
    label_ids: Vec<String>,
    mime_type: String,
    attachments: Vec<ObservedAttachmentDescriptor>,
}

#[expect(
    clippy::missing_trait_methods,
    reason = "Drop is the explicit scrub-on-drop contract"
)]
impl Drop for ObservedMessageDetail {
    fn drop(&mut self) {
        self.id.zeroize();
        self.conversation_id.zeroize();
        self.subject.zeroize();
        self.mime_type.zeroize();
        for id in &mut self.label_ids {
            id.zeroize();
        }
        // Recipient and attachment descriptors scrub their nested values.
    }
}

impl ObservedMessageDetail {
    /// Returns the provider message identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the provider conversation identifier.
    #[must_use]
    pub fn conversation_id(&self) -> &str {
        &self.conversation_id
    }

    /// Returns the provider subject metadata.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the provider sender metadata.
    #[must_use]
    pub const fn sender(&self) -> &ObservedMessageRecipient {
        &self.sender
    }

    /// Returns provider To recipients in response order.
    #[must_use]
    pub fn to(&self) -> &[ObservedMessageRecipient] {
        &self.to
    }

    /// Returns provider Cc recipients in response order.
    #[must_use]
    pub fn cc(&self) -> &[ObservedMessageRecipient] {
        &self.cc
    }

    /// Returns provider Bcc recipients in response order.
    #[must_use]
    pub fn bcc(&self) -> &[ObservedMessageRecipient] {
        &self.bcc
    }

    /// Returns provider numeric `Time` without assigning public semantics.
    #[must_use]
    pub const fn time(&self) -> u64 {
        self.time
    }

    /// Returns provider unread state normalized from exact numeric 0/1.
    #[must_use]
    pub const fn unread(&self) -> bool {
        self.unread
    }

    /// Returns provider label identifiers in response order.
    #[must_use]
    pub fn label_ids(&self) -> &[String] {
        &self.label_ids
    }

    /// Returns the provider MIME type metadata.
    #[must_use]
    pub fn mime_type(&self) -> &str {
        &self.mime_type
    }

    /// Returns bounded attachment descriptors without packet or byte content.
    #[must_use]
    pub fn attachments(&self) -> &[ObservedAttachmentDescriptor] {
        &self.attachments
    }
}

impl fmt::Debug for ObservedMessageDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedMessageDetail")
            .field("id", &"<redacted>")
            .field("conversation_id", &"<redacted>")
            .field("subject", &"<redacted>")
            .field("sender", &"<redacted>")
            .field("to_count", &self.to.len())
            .field("cc_count", &self.cc.len())
            .field("bcc_count", &self.bcc.len())
            .field("time", &"<redacted>")
            .field("unread", &self.unread)
            .field("label_count", &self.label_ids.len())
            .field("mime_type", &"<redacted>")
            .field("attachment_count", &self.attachments.len())
            .finish()
    }
}

/// One exact safe projection of a Proton Mail message-detail HTTP response.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedMessageDetailResponse {
    message: ObservedMessageDetail,
}

impl ObservedMessageDetailResponse {
    /// Maximum decoded JSON response accepted by this metadata-only boundary.
    pub const MAX_BODY_BYTES: usize = MAX_MESSAGE_DETAIL_BODY_BYTES;

    /// Parses one exact detail GET and drops encrypted/content-bearing fields.
    ///
    /// # Errors
    ///
    /// Rejects endpoint/identity drift, oversized or malformed JSON, provider
    /// errors, invalid bounds/types, duplicate labels, or duplicate
    /// attachments.
    // jig-ignore-next-line: canonical rustfmt line.
    pub fn parse(method: &str, url: &str, body: &str) -> Result<Self, MessageDetailResponseError> {
        let expected_id = if method == "GET" {
            message_id_from_detail_url(url)
                // jig-ignore-next-line: canonical rustfmt line.
                .map_err(|_error| MessageDetailResponseError::UnexpectedEndpoint)?
        } else {
            None
        }
        .ok_or(MessageDetailResponseError::UnexpectedEndpoint)?;
        Self::parse_expected_id(expected_id, body)
    }

    // The CDP envelope already carries an exact validated entity selector.
    // Reusing this projector avoids allocating a second secret-bearing URL.
    fn parse_expected_id(
        expected_id: &str,
        body: &str,
    ) -> Result<Self, MessageDetailResponseError> {
        if body.len() > Self::MAX_BODY_BYTES {
            return Err(MessageDetailResponseError::BodyTooLarge);
        }
        let value =
            // jig-ignore-next-line: canonical rustfmt line.
            strict_json::from_sensitive_slice(body.as_bytes()).map_err(|_error| MessageDetailResponseError::Malformed)?;
        if value.get("Code").and_then(Value::as_u64) != Some(1000) {
            return Err(MessageDetailResponseError::ProviderRejected);
        }
        let message = value
            .get("Message")
            .and_then(Value::as_object)
            .ok_or(MessageDetailResponseError::Malformed)?;
        // Borrow from the scrub-on-drop provider JSON until validation ends.
        // jig-ignore-next-line: canonical rustfmt line.
        let id = bounded_required_str(message, "ID", MAX_MESSAGE_ID_BYTES, false)?;
        if !safe_read_id(id, MAX_MESSAGE_ID_BYTES) {
            return Err(MessageDetailResponseError::Malformed);
        }
        if id != expected_id {
            return Err(MessageDetailResponseError::IdentityMismatch);
        }
        let conversation_id =
            // jig-ignore-next-line: canonical rustfmt line.
            bounded_required_str(message, "ConversationID", MAX_CONVERSATION_ID_BYTES, false)?;
        if !safe_read_id(conversation_id, MAX_CONVERSATION_ID_BYTES) {
            return Err(MessageDetailResponseError::Malformed);
        }
        // jig-ignore-next-line: canonical rustfmt line.
        let subject = bounded_required_str(message, "Subject", MAX_SUBJECT_BYTES, true)?;
        if subject.chars().any(unsafe_display_character) {
            return Err(MessageDetailResponseError::Malformed);
        }
        let sender_value = message
            .get("Sender")
            .ok_or(MessageDetailResponseError::Malformed)?;
        let sender = parse_recipient(sender_value)?;
        let to = parse_recipients(message.get("ToList"))?;
        let cc = parse_recipients(message.get("CCList"))?;
        let bcc = parse_recipients(message.get("BCCList"))?;
        let time = message
            .get("Time")
            .and_then(Value::as_u64)
            .ok_or(MessageDetailResponseError::Malformed)?;
        let unread = match message.get("Unread").and_then(Value::as_u64) {
            Some(0) => false,
            Some(1) => true,
            _ => return Err(MessageDetailResponseError::Malformed),
        };
        let label_ids = parse_label_ids(message.get("LabelIDs"))?;
        // jig-ignore-next-line: canonical rustfmt line.
        let mime_type = bounded_required_str(message, "MIMEType", MAX_MIME_TYPE_BYTES, false)?;
        if !safe_metadata_mime_type(mime_type) {
            return Err(MessageDetailResponseError::Malformed);
        }
        let attachments = parse_attachments(message.get("Attachments"), id)?;
        Ok(Self {
            message: ObservedMessageDetail {
                id: String::from(id),
                conversation_id: String::from(conversation_id),
                subject: String::from(subject),
                sender,
                to,
                cc,
                bcc,
                time,
                unread,
                label_ids: label_ids.into_iter().map(String::from).collect(),
                mime_type: String::from(mime_type),
                attachments,
            },
        })
    }

    /// Projects one decoded `Network.getResponseBody` envelope.
    ///
    /// # Errors
    ///
    /// Rejects base64 envelopes and every invalid provider response accepted by
    /// [`Self::parse`].
    pub fn parse_cdp_body(
        message_id: &str,
        result: &Value,
    ) -> Result<Self, MessageDetailResponseError> {
        if !safe_read_id(message_id, MAX_MESSAGE_ID_BYTES) {
            return Err(MessageDetailResponseError::UnexpectedEndpoint);
        }
        if result.as_object().is_none_or(|fields| fields.len() != 2) {
            return Err(MessageDetailResponseError::Malformed);
        }
        let encoded = result
            .get("base64Encoded")
            .and_then(Value::as_bool)
            .ok_or(MessageDetailResponseError::Malformed)?;
        if encoded {
            return Err(MessageDetailResponseError::UnsupportedEncoding);
        }
        let body = result
            .get("body")
            .and_then(Value::as_str)
            .ok_or(MessageDetailResponseError::Malformed)?;
        Self::parse_expected_id(message_id, body)
    }

    /// Returns the content-minimized provider metadata.
    #[must_use]
    pub const fn message(&self) -> &ObservedMessageDetail {
        &self.message
    }
}

impl fmt::Debug for ObservedMessageDetailResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedMessageDetailResponse")
            .field("message", &self.message)
            .finish()
    }
}

/// Why one message-detail body failed bounded projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageDetailResponseError {
    /// Method or URL was not the exact single-message GET endpoint.
    UnexpectedEndpoint,
    /// Decoded response body exceeded the metadata-projection cap.
    BodyTooLarge,
    /// Provider JSON was malformed or required fields had invalid types/bounds.
    Malformed,
    /// Provider success code was absent or not `1000`.
    ProviderRejected,
    /// Message ID inside the body did not equal the requested opaque ID.
    IdentityMismatch,
    /// `Network.getResponseBody` returned an encoded envelope.
    UnsupportedEncoding,
    /// A nested attachment claimed a different parent message identity.
    AttachmentParentMismatch,
    /// A label or attachment identifier was duplicated.
    DuplicateIdentifier,
    /// A bounded list exceeded its maximum safe item count.
    TooManyItems,
}

// jig-ignore-next-line: canonical rustfmt line.
fn parse_recipient(value: &Value) -> Result<ObservedMessageRecipient, MessageDetailResponseError> {
    let object = value
        .as_object()
        .ok_or(MessageDetailResponseError::Malformed)?;
    // jig-ignore-next-line: canonical rustfmt line.
    let name = bounded_required_str(object, "Name", MAX_RECIPIENT_NAME_BYTES, true)?;
    // jig-ignore-next-line: canonical rustfmt line.
    let address = bounded_required_str(object, "Address", MAX_RECIPIENT_ADDRESS_BYTES, false)?;
    // Names and addresses may eventually be reused in a reply composer.
    // Reject raw header controls before exposing provider recipient values.
    if name.chars().any(unsafe_display_character)
        || address.chars().any(unsafe_address_character)
        || address.trim() != address
    {
        return Err(MessageDetailResponseError::Malformed);
    }
    Ok(ObservedMessageRecipient {
        name: String::from(name),
        address: String::from(address),
    })
}

// Literal addresses must not contain invisible grapheme-joining controls:
// only human-language subjects and display names may contain them.
const fn unsafe_address_character(character: char) -> bool {
    character.is_whitespace()
        || character == '\u{fffd}'
        || matches!(character, '<' | '>' | ',' | ';' | ':')
        || unsafe_display_character(character)
        || matches!(
            character,
            '\u{180b}'..='\u{180d}' | '\u{200c}'..='\u{200d}'
                | '\u{fe00}'..='\u{fe0f}' | '\u{e0100}'..='\u{e01ef}'
        )
}

fn parse_recipients(
    value: Option<&Value>,
) -> Result<Vec<ObservedMessageRecipient>, MessageDetailResponseError> {
    let values = value
        .and_then(Value::as_array)
        .ok_or(MessageDetailResponseError::Malformed)?;
    if values.len() > MAX_RECIPIENTS_PER_FIELD {
        return Err(MessageDetailResponseError::TooManyItems);
    }
    values.iter().map(parse_recipient).collect()
}

// jig-ignore-next-line: canonical rustfmt line.
fn parse_label_ids(value: Option<&Value>) -> Result<Vec<&str>, MessageDetailResponseError> {
    let values = value
        .and_then(Value::as_array)
        .ok_or(MessageDetailResponseError::Malformed)?;
    if values.len() > MAX_LABEL_IDS {
        return Err(MessageDetailResponseError::TooManyItems);
    }
    let mut seen = BTreeSet::new();
    let mut labels = Vec::with_capacity(values.len());
    for value in values {
        let label = value
            .as_str()
            .filter(|value| safe_read_id(value, MAX_LABEL_ID_BYTES))
            .ok_or(MessageDetailResponseError::Malformed)?;
        if !seen.insert(label) {
            return Err(MessageDetailResponseError::DuplicateIdentifier);
        }
        labels.push(label);
    }
    Ok(labels)
}

fn parse_attachments(
    value: Option<&Value>,
    expected_message_id: &str,
) -> Result<Vec<ObservedAttachmentDescriptor>, MessageDetailResponseError> {
    let values = value
        .and_then(Value::as_array)
        .ok_or(MessageDetailResponseError::Malformed)?;
    if values.len() > MAX_ATTACHMENTS {
        return Err(MessageDetailResponseError::TooManyItems);
    }
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut attachments = Vec::with_capacity(values.len());
    for value in values {
        let object = value
            .as_object()
            .ok_or(MessageDetailResponseError::Malformed)?;
        // A detail response is already bound to its requested message. When
        // the provider also declares an attachment parent, it must agree;
        // missing or null optional metadata is not a contradictory assertion.
        match object.get("MessageID") {
            None | Some(Value::Null) => {}
            Some(Value::String(parent)) => {
                if !safe_read_id(parent, MAX_MESSAGE_ID_BYTES) {
                    return Err(MessageDetailResponseError::Malformed);
                }
                if parent != expected_message_id {
                    // jig-ignore-next-line: rustfmt long error variant.
                    return Err(MessageDetailResponseError::AttachmentParentMismatch);
                }
            }
            Some(_) => return Err(MessageDetailResponseError::Malformed),
        }
        // jig-ignore-next-line: canonical rustfmt line.
        let id = bounded_optional_nonempty_str(object, "ID", MAX_ATTACHMENT_ID_BYTES)?;
        if id.is_some_and(|id| !safe_read_id(id, MAX_ATTACHMENT_ID_BYTES)) {
            return Err(MessageDetailResponseError::Malformed);
        }
        if let Some(source_id) = id {
            // Deduplicate borrowed IDs before a descriptor owns its copy.
            if !seen.insert(source_id) {
                return Err(MessageDetailResponseError::DuplicateIdentifier);
            }
        }
        // jig-ignore-next-line: canonical rustfmt line.
        let name = bounded_optional_str(object, "Name", MAX_ATTACHMENT_NAME_BYTES)?;
        let sanitized_name = name.map(SanitizedAttachmentFilename::new);
        // jig-ignore-next-line: canonical rustfmt line.
        let mime_type = bounded_optional_str(object, "MIMEType", MAX_MIME_TYPE_BYTES)?;
        if mime_type.is_some_and(|mime| !safe_metadata_mime_type(mime)) {
            return Err(MessageDetailResponseError::Malformed);
        }
        let size = match object.get("Size") {
            None | Some(Value::Null) => None,
            Some(value) => Some(
                value
                    .as_u64()
                    .ok_or(MessageDetailResponseError::Malformed)?,
            ),
        };
        attachments.push(ObservedAttachmentDescriptor {
            id: id.map(String::from),
            name: name.map(String::from),
            sanitized_name,
            size,
            mime_type: mime_type.map(String::from),
        });
    }
    Ok(attachments)
}

fn bounded_required_str<'source>(
    object: &'source serde_json::Map<String, Value>,
    key: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<&'source str, MessageDetailResponseError> {
    let value = object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(MessageDetailResponseError::Malformed)?;
    if value.len() > max_bytes || (!allow_empty && value.is_empty()) {
        return Err(MessageDetailResponseError::Malformed);
    }
    Ok(value)
}

fn bounded_optional_nonempty_str<'source>(
    object: &'source serde_json::Map<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<Option<&'source str>, MessageDetailResponseError> {
    let value = bounded_optional_str(object, key, max_bytes)?;
    if value.is_some_and(str::is_empty) {
        return Err(MessageDetailResponseError::Malformed);
    }
    Ok(value)
}

fn bounded_optional_str<'source>(
    object: &'source serde_json::Map<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<Option<&'source str>, MessageDetailResponseError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let value = value
                .as_str()
                .ok_or(MessageDetailResponseError::Malformed)?;
            if value.len() > max_bytes {
                return Err(MessageDetailResponseError::Malformed);
            }
            Ok(Some(value))
        }
    }
}

// jig-ignore-next-line: canonical rustfmt line.
fn message_id_from_detail_url(url: &str) -> Result<Option<&str>, MessageDetailNetworkError> {
    let Some(message_id) = url.strip_prefix(MESSAGE_DETAIL_URL_PREFIX) else {
        return Ok(None);
    };
    // Browser-serialized URL paths encode non-ASCII characters. A raw
    // Unicode identifier cannot prove the exact route even when a provider
    // metadata ID may legitimately contain Unicode.
    if !url.bytes().all(|byte| byte.is_ascii_graphic())
        || !safe_read_id(message_id, MAX_MESSAGE_ID_BYTES)
    {
        return Err(MessageDetailNetworkError::MalformedEvent);
    }
    Ok(Some(message_id))
}

// jig-ignore-next-line: canonical rustfmt line.
fn network_request_id(event: &Value) -> Result<&str, MessageDetailNetworkError> {
    event
        .get("params")
        .and_then(|params| params.get("requestId"))
        .and_then(Value::as_str)
        .ok_or(MessageDetailNetworkError::MalformedEvent)
}

#[cfg(test)]
#[path = "../../../../tests/mail/web/adapter-outbound/dbg_message.rs"]
mod private_request_diagnostics_tests;
