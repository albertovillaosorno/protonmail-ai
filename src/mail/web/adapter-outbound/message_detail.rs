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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use mail_capability_domain::SanitizedAttachmentFilename;
use serde_json::Value;

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

#[derive(Clone, Debug, Eq, PartialEq)]
struct TrackedMessageDetailRequest {
    state: MessageDetailRequestState,
    message_id: String,
}

/// Bounded CDP Network lifecycle state for exact single-message GETs.
#[derive(Clone, Eq, PartialEq)]
pub struct MessageDetailNetworkCapture {
    session_id: String,
    requests: BTreeMap<String, TrackedMessageDetailRequest>,
}

impl MessageDetailNetworkCapture {
    /// Creates an empty capture scoped to one flattened CDP target session.
    #[must_use]
    pub fn new(session_id: &str) -> Self {
        Self {
            session_id: String::from(session_id),
            requests: BTreeMap::new(),
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
            // jig-ignore-next-line: canonical rustfmt line.
            .filter(|(_id, request)| request.state == MessageDetailRequestState::Finished)
            // jig-ignore-next-line: canonical rustfmt line.
            .map(|(request_id, request)| (request_id.clone(), request.message_id.clone()))
            .collect::<Vec<_>>();
        self.requests
            // jig-ignore-next-line: canonical rustfmt line.
            .retain(|_id, request| request.state != MessageDetailRequestState::Finished);
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
        if let Some(existing) = self.requests.get(request_id) {
            if message_id != Some(existing.message_id.as_str()) {
                return Err(MessageDetailNetworkError::RedirectedAway);
            }
            return Err(MessageDetailNetworkError::InvalidSequence);
        }
        let Some(message_id) = message_id else {
            return Ok(());
        };
        if self.requests.len() >= MAX_TRACKED_MESSAGE_DETAIL_REQUESTS {
            return Err(MessageDetailNetworkError::CapacityExceeded);
        }
        self.requests.insert(
            String::from(request_id),
            TrackedMessageDetailRequest {
                state: MessageDetailRequestState::Requested,
                message_id: String::from(message_id),
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
            || mime != Some("application/json")
        {
            return Err(MessageDetailNetworkError::ResponseRejected);
        }
        request.state = MessageDetailRequestState::Responded;
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_finished(&mut self, event: &Value) -> Result<(), MessageDetailNetworkError> {
        let request_id = network_request_id(event)?;
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
        self.requests.remove(request_id);
        Ok(())
    }
}

impl fmt::Debug for MessageDetailNetworkCapture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageDetailNetworkCapture")
            .field("session_id", &"<redacted>")
            .field("tracked_request_count", &self.requests.len())
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
        if body.len() > Self::MAX_BODY_BYTES {
            return Err(MessageDetailResponseError::BodyTooLarge);
        }
        let value: Value =
            // jig-ignore-next-line: canonical rustfmt line.
            serde_json::from_str(body).map_err(|_error| MessageDetailResponseError::Malformed)?;
        if value.get("Code").and_then(Value::as_u64) != Some(1000) {
            return Err(MessageDetailResponseError::ProviderRejected);
        }
        let message = value
            .get("Message")
            .and_then(Value::as_object)
            .ok_or(MessageDetailResponseError::Malformed)?;
        // jig-ignore-next-line: canonical rustfmt line.
        let id = bounded_required_string(message, "ID", MAX_MESSAGE_ID_BYTES, false)?;
        if id != expected_id {
            return Err(MessageDetailResponseError::IdentityMismatch);
        }
        let conversation_id =
            // jig-ignore-next-line: canonical rustfmt line.
            bounded_required_string(message, "ConversationID", MAX_CONVERSATION_ID_BYTES, false)?;
        // jig-ignore-next-line: canonical rustfmt line.
        let subject = bounded_required_string(message, "Subject", MAX_SUBJECT_BYTES, true)?;
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
        let mime_type = bounded_required_string(message, "MIMEType", MAX_MIME_TYPE_BYTES, false)?;
        let attachments = parse_attachments(message.get("Attachments"))?;
        Ok(Self {
            message: ObservedMessageDetail {
                id,
                conversation_id,
                subject,
                sender,
                to,
                cc,
                bcc,
                time,
                unread,
                label_ids,
                mime_type,
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
        if message_id.is_empty() || message_id.len() > MAX_MESSAGE_ID_BYTES {
            return Err(MessageDetailResponseError::UnexpectedEndpoint);
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
        let url = format!("{MESSAGE_DETAIL_URL_PREFIX}{message_id}");
        Self::parse("GET", &url, body)
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
    let name = bounded_required_string(object, "Name", MAX_RECIPIENT_NAME_BYTES, true)?;
    // jig-ignore-next-line: canonical rustfmt line.
    let address = bounded_required_string(object, "Address", MAX_RECIPIENT_ADDRESS_BYTES, false)?;
    Ok(ObservedMessageRecipient { name, address })
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
fn parse_label_ids(value: Option<&Value>) -> Result<Vec<String>, MessageDetailResponseError> {
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
            // jig-ignore-next-line: canonical rustfmt line.
            .filter(|value| !value.is_empty() && value.len() <= MAX_LABEL_ID_BYTES)
            .ok_or(MessageDetailResponseError::Malformed)?;
        if !seen.insert(label) {
            return Err(MessageDetailResponseError::DuplicateIdentifier);
        }
        labels.push(String::from(label));
    }
    Ok(labels)
}

fn parse_attachments(
    value: Option<&Value>,
) -> Result<Vec<ObservedAttachmentDescriptor>, MessageDetailResponseError> {
    let values = value
        .and_then(Value::as_array)
        .ok_or(MessageDetailResponseError::Malformed)?;
    if values.len() > MAX_ATTACHMENTS {
        return Err(MessageDetailResponseError::TooManyItems);
    }
    let mut seen = BTreeSet::new();
    let mut attachments = Vec::with_capacity(values.len());
    for value in values {
        let object = value
            .as_object()
            .ok_or(MessageDetailResponseError::Malformed)?;
        // jig-ignore-next-line: canonical rustfmt line.
        let id = bounded_optional_nonempty_string(object, "ID", MAX_ATTACHMENT_ID_BYTES)?;
        if let Some(id) = id.as_ref()
            && !seen.insert(id.clone())
        {
            return Err(MessageDetailResponseError::DuplicateIdentifier);
        }
        // jig-ignore-next-line: canonical rustfmt line.
        let name = bounded_optional_string(object, "Name", MAX_ATTACHMENT_NAME_BYTES)?;
        // jig-ignore-next-line: canonical rustfmt line.
        let sanitized_name = name.as_deref().map(SanitizedAttachmentFilename::new);
        // jig-ignore-next-line: canonical rustfmt line.
        let mime_type = bounded_optional_string(object, "MIMEType", MAX_MIME_TYPE_BYTES)?;
        let size = match object.get("Size") {
            None | Some(Value::Null) => None,
            Some(value) => Some(
                value
                    .as_u64()
                    .ok_or(MessageDetailResponseError::Malformed)?,
            ),
        };
        attachments.push(ObservedAttachmentDescriptor {
            id,
            name,
            sanitized_name,
            size,
            mime_type,
        });
    }
    Ok(attachments)
}

fn bounded_required_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<String, MessageDetailResponseError> {
    let value = object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(MessageDetailResponseError::Malformed)?;
    if value.len() > max_bytes || (!allow_empty && value.is_empty()) {
        return Err(MessageDetailResponseError::Malformed);
    }
    Ok(String::from(value))
}

fn bounded_optional_nonempty_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<Option<String>, MessageDetailResponseError> {
    let value = bounded_optional_string(object, key, max_bytes)?;
    if value.as_ref().is_some_and(String::is_empty) {
        return Err(MessageDetailResponseError::Malformed);
    }
    Ok(value)
}

fn bounded_optional_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<Option<String>, MessageDetailResponseError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let value = value
                .as_str()
                .ok_or(MessageDetailResponseError::Malformed)?;
            if value.len() > max_bytes {
                return Err(MessageDetailResponseError::Malformed);
            }
            Ok(Some(String::from(value)))
        }
    }
}

// jig-ignore-next-line: canonical rustfmt line.
fn message_id_from_detail_url(url: &str) -> Result<Option<&str>, MessageDetailNetworkError> {
    let Some(message_id) = url.strip_prefix(MESSAGE_DETAIL_URL_PREFIX) else {
        return Ok(None);
    };
    if message_id.is_empty()
        || message_id.len() > MAX_MESSAGE_ID_BYTES
        || message_id
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'?' | b'#'))
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
