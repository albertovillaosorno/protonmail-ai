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
//   - Bounded projection of one Proton attachment-metadata response.
// - Must-Not:
//   - Retain key packets, signatures, sender data, address IDs, or attachment
//     bytes.
// - Allows:
//   - Bind attachment identity to its expected parent message and safe
//     metadata.
// - Split-When:
//   - Encrypted-byte lifecycle or plaintext decryption becomes independently
//     owned.
// - Merge-When:
//   - A reviewed attachment read adapter owns metadata plus plaintext output.
// - Summary:
//   - Proves provider attachment/message identity before future attachment
//     output.
// - Description:
//   - Accepts only exact metadata GETs and content-minimizes provider JSON.
// - Usage:
//   - Browser attachment observation may consume this after an app-owned fetch.
// - Defaults:
//   - No attachment bytes, keys, provider request injection, or filesystem
//     access.
//

//! Bounded Proton attachment metadata projection with parent-message binding.

use crate::request_id_custody::discard_request_id;
use crate::request_id_custody::retain_request_ids;
use crate::request_id_custody::scrub_all_request_ids;
use crate::response_provenance::ExtraStatusEvidence;
use crate::response_provenance::RequestExtraInfoEvidence;
use crate::response_provenance::bodyless_cdp_get;
use crate::response_provenance::direct_cdp_read_response;
use crate::response_provenance::direct_extra_status_is_200;
use crate::response_provenance::non_speculative_cdp_get;
use crate::strict_json;
use core::fmt::{Debug, Formatter, Result as FmtResult};
use std::collections::{BTreeMap, BTreeSet};

use crate::driver::safe_cdp_request_id;
use crate::opaque_read_id::safe_read_id;
use mail_capability_domain::SanitizedAttachmentFilename;
use serde_json::Value;
use zeroize::{Zeroize as _, Zeroizing};

// jig-ignore-next-line: canonical rustfmt line.
const ATTACHMENT_URL_PREFIX: &str = "https://mail.proton.me/api/mail/v4/attachments/";
const MAX_ATTACHMENT_METADATA_BODY_BYTES: usize = 256 * 1_024;
const MAX_ATTACHMENT_ID_BYTES: usize = 512;
const MAX_MESSAGE_ID_BYTES: usize = 512;
const MAX_ATTACHMENT_NAME_BYTES: usize = 4_096;
const MAX_MIME_TYPE_BYTES: usize = 512;
const MAX_TRACKED_ATTACHMENT_METADATA_REQUESTS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttachmentMetadataRequestState {
    Requested,
    Responded,
    Finished,
}

#[derive(Clone, Eq, PartialEq)]
struct TrackedAttachmentMetadataRequest {
    state: AttachmentMetadataRequestState,
    extra_status: ExtraStatusEvidence,
    attachment_id: Zeroizing<String>,
}

impl Debug for TrackedAttachmentMetadataRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("TrackedAttachmentMetadataRequest")
            .field("state", &self.state)
            .field("extra_status", &self.extra_status)
            .field("attachment_id", &"<redacted>")
            .finish()
    }
}

/// Bounded CDP Network lifecycle state for exact attachment-metadata GETs.
#[derive(Clone, Eq, PartialEq)]
pub struct AttachmentMetadataNetworkCapture {
    session_id: Zeroizing<String>,
    requests: BTreeMap<String, TrackedAttachmentMetadataRequest>,
    completed_ids: BTreeSet<String>,
    extra_request_headers: RequestExtraInfoEvidence,
}

#[expect(
    clippy::missing_trait_methods,
    reason = "Drop scrubs retained CDP request correlation identifiers"
)]
impl Drop for AttachmentMetadataNetworkCapture {
    fn drop(&mut self) {
        scrub_all_request_ids(&mut self.requests, &mut self.completed_ids);
    }
}

impl AttachmentMetadataNetworkCapture {
    /// Creates an empty capture scoped to one flattened CDP target session.
    #[must_use]
    pub fn new(session_id: &str) -> Self {
        Self {
            session_id: Zeroizing::new(String::from(session_id)),
            requests: BTreeMap::new(),
            completed_ids: BTreeSet::new(),
            extra_request_headers: RequestExtraInfoEvidence::default(),
        }
    }

    /// Consumes one unsolicited CDP event without retaining headers or bodies.
    ///
    /// # Errors
    ///
    /// Exact matching requests fail closed on redirects, malformed lifecycle,
    /// unsafe response metadata, or capacity exhaustion. Failed app-owned
    /// attempts are discarded so an app-owned retry may be observed.
    // jig-ignore-next-line: canonical rustfmt line.
    pub fn observe(&mut self, event: &Value) -> Result<(), AttachmentMetadataNetworkError> {
        // jig-ignore-next-line: canonical rustfmt line.
        if event.get("sessionId").and_then(Value::as_str) != Some(self.session_id.as_str()) {
            return Ok(());
        }
        match event.get("method").and_then(Value::as_str) {
            Some("Network.requestWillBeSent") => self.observe_request(event),
            Some("Network.requestWillBeSentExtraInfo") => {
                let request_id = self
                    .extra_request_headers
                    .note_event(event)
                    .ok_or(AttachmentMetadataNetworkError::MalformedEvent)?;
                if self.completed_ids.contains(request_id) {
                    return Err(AttachmentMetadataNetworkError::InvalidSequence);
                }
                if self.requests.contains_key(request_id)
                    && self.extra_request_headers.rejects(request_id)
                {
                    // jig-ignore-next-line: canonical rustfmt error variant.
                    return Err(AttachmentMetadataNetworkError::ResponseRejected);
                }
                Ok(())
            }
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

    // jig-ignore-next-line: canonical rustfmt line.
    /// Removes completed exact metadata requests as request ID plus attachment ID.
    pub fn take_finished_requests(&mut self) -> Vec<(String, String)> {
        let finished = self
            .requests
            .iter()
            .filter(|(_id, request)| {
                request.state == AttachmentMetadataRequestState::Finished
                    && request.extra_status.ready()
            })
            .map(|(request_id, request)| {
                (
                    request_id.clone(),
                    String::from(request.attachment_id.as_str()),
                )
            })
            .collect::<Vec<_>>();
        retain_request_ids(&mut self.requests, |request| {
            request.state != AttachmentMetadataRequestState::Finished
                || !request.extra_status.ready()
        });
        for (request_id, _attachment_id) in &finished {
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
    fn observe_request(&mut self, event: &Value) -> Result<(), AttachmentMetadataNetworkError> {
        let params = event
            .get("params")
            .ok_or(AttachmentMetadataNetworkError::MalformedEvent)?;
        let request_id = params
            .get("requestId")
            .and_then(Value::as_str)
            .ok_or(AttachmentMetadataNetworkError::MalformedEvent)?;
        let request = params
            .get("request")
            .ok_or(AttachmentMetadataNetworkError::MalformedEvent)?;
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or(AttachmentMetadataNetworkError::MalformedEvent)?;
        let url = request
            .get("url")
            .and_then(Value::as_str)
            .ok_or(AttachmentMetadataNetworkError::MalformedEvent)?;
        let attachment_id = if method == "GET" {
            attachment_id_from_metadata_url(url)
                // jig-ignore-next-line: canonical rustfmt line.
                .map_err(|_error| AttachmentMetadataNetworkError::MalformedEvent)?
        } else {
            None
        };
        if self.completed_ids.contains(request_id) {
            return Err(AttachmentMetadataNetworkError::InvalidSequence);
        }
        if let Some(existing) = self.requests.get(request_id) {
            if attachment_id != Some(existing.attachment_id.as_str()) {
                return Err(AttachmentMetadataNetworkError::RedirectedAway);
            }
            return Err(AttachmentMetadataNetworkError::InvalidSequence);
        }
        let Some(attachment_id) = attachment_id else {
            return Ok(());
        };
        // A GET URL alone cannot prove body-free read semantics.
        if !bodyless_cdp_get(request)
            || !non_speculative_cdp_get(event)
            || self.extra_request_headers.rejects(request_id)
        {
            return Err(AttachmentMetadataNetworkError::MalformedEvent);
        }
        // A redirect from an ignored URL cannot establish fresh GET evidence.
        if params.get("redirectResponse").is_some() {
            return Err(AttachmentMetadataNetworkError::RedirectedAway);
        }
        if !safe_cdp_request_id(request_id) {
            return Err(AttachmentMetadataNetworkError::MalformedEvent);
        }
        if self.requests.len().saturating_add(self.completed_ids.len())
            >= MAX_TRACKED_ATTACHMENT_METADATA_REQUESTS
        {
            return Err(AttachmentMetadataNetworkError::CapacityExceeded);
        }
        self.requests.insert(
            String::from(request_id),
            TrackedAttachmentMetadataRequest {
                state: AttachmentMetadataRequestState::Requested,
                extra_status: ExtraStatusEvidence::default(),
                attachment_id: Zeroizing::new(String::from(attachment_id)),
            },
        );
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_response(&mut self, event: &Value) -> Result<(), AttachmentMetadataNetworkError> {
        let params = event
            .get("params")
            .ok_or(AttachmentMetadataNetworkError::MalformedEvent)?;
        let request_id = params
            .get("requestId")
            .and_then(Value::as_str)
            .ok_or(AttachmentMetadataNetworkError::MalformedEvent)?;
        if self.completed_ids.contains(request_id) {
            return Err(AttachmentMetadataNetworkError::InvalidSequence);
        }
        let Some(request) = self.requests.get_mut(request_id) else {
            return Ok(());
        };
        if request.state != AttachmentMetadataRequestState::Requested {
            return Err(AttachmentMetadataNetworkError::InvalidSequence);
        }
        let response = params
            .get("response")
            .ok_or(AttachmentMetadataNetworkError::MalformedEvent)?;
        let url = response
            .get("url")
            .and_then(Value::as_str)
            .ok_or(AttachmentMetadataNetworkError::MalformedEvent)?;
        let response_attachment_id = attachment_id_from_metadata_url(url)
            // jig-ignore-next-line: canonical rustfmt line.
            .map_err(|_error| AttachmentMetadataNetworkError::ResponseRejected)?;
        let status = response.get("status").and_then(Value::as_u64);
        let mime = response.get("mimeType").and_then(Value::as_str);
        if response_attachment_id != Some(request.attachment_id.as_str())
            || status != Some(200)
            || !direct_cdp_read_response(event)
            || mime != Some("application/json")
        {
            return Err(AttachmentMetadataNetworkError::ResponseRejected);
        }
        if !request.extra_status.note_response(params) {
            return Err(AttachmentMetadataNetworkError::ResponseRejected);
        }
        request.state = AttachmentMetadataRequestState::Responded;
        Ok(())
    }

    // The actual HTTP-200 status can arrive before or after loadingFinished.
    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_extra_200(&mut self, event: &Value) -> Result<(), AttachmentMetadataNetworkError> {
        let request_id = network_request_id(event)?;
        if self.completed_ids.contains(request_id) {
            return Err(AttachmentMetadataNetworkError::InvalidSequence);
        }
        if let Some(request) = self.requests.get_mut(request_id)
            && !request.extra_status.note_200()
        {
            return Err(AttachmentMetadataNetworkError::InvalidSequence);
        }
        Ok(())
    }

    // A cache hit can arrive before or after responseReceived. Either order
    // disqualifies this exact request from establishing fresh provider state.
    // jig-ignore-next-line: rustfmt callback signature.
    fn observe_cache_hit(&self, event: &Value) -> Result<(), AttachmentMetadataNetworkError> {
        let request_id = network_request_id(event)?;
        if self.completed_ids.contains(request_id) {
            return Err(AttachmentMetadataNetworkError::InvalidSequence);
        }
        if self.requests.contains_key(request_id) {
            return Err(AttachmentMetadataNetworkError::ResponseRejected);
        }
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_finished(&mut self, event: &Value) -> Result<(), AttachmentMetadataNetworkError> {
        let request_id = network_request_id(event)?;
        if self.completed_ids.contains(request_id) {
            return Err(AttachmentMetadataNetworkError::InvalidSequence);
        }
        let Some(request) = self.requests.get_mut(request_id) else {
            return Ok(());
        };
        if request.state != AttachmentMetadataRequestState::Responded {
            return Err(AttachmentMetadataNetworkError::InvalidSequence);
        }
        request.state = AttachmentMetadataRequestState::Finished;
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_failed(&mut self, event: &Value) -> Result<(), AttachmentMetadataNetworkError> {
        let request_id = network_request_id(event)?;
        if self.completed_ids.contains(request_id) {
            return Err(AttachmentMetadataNetworkError::InvalidSequence);
        }
        if self
            .requests
            .get(request_id)
            // jig-ignore-next-line: canonical rustfmt line.
            .is_some_and(|request| request.state == AttachmentMetadataRequestState::Finished)
        {
            return Err(AttachmentMetadataNetworkError::InvalidSequence);
        }
        discard_request_id(&mut self.requests, request_id);
        Ok(())
    }
}

impl Debug for AttachmentMetadataNetworkCapture {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("AttachmentMetadataNetworkCapture")
            .field("session_id", &"<redacted>")
            .field("tracked_request_count", &self.requests.len())
            .field("completed_request_count", &self.completed_ids.len())
            .field("extra_request_headers", &"<redacted>")
            .finish()
    }
}

/// Why exact attachment-metadata Network evidence failed closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentMetadataNetworkError {
    /// Required CDP event structure or exact endpoint shape was malformed.
    MalformedEvent,
    /// A tracked request redirected away from its exact metadata endpoint.
    RedirectedAway,
    /// A tracked response changed identity or was not HTTP 200 JSON.
    ResponseRejected,
    /// A lifecycle event repeated or arrived out of sequence.
    InvalidSequence,
    /// Too many unfinished exact attachment-metadata requests are retained.
    CapacityExceeded,
}

/// Content-minimized attachment metadata bound to one parent message.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedAttachmentMetadata {
    attachment_id: String,
    message_id: String,
    sanitized_name: Option<SanitizedAttachmentFilename>,
    declared_size: u64,
    mime_type: String,
}

#[expect(
    clippy::missing_trait_methods,
    reason = "Drop is the explicit scrub-on-drop contract"
)]
impl Drop for ObservedAttachmentMetadata {
    fn drop(&mut self) {
        self.attachment_id.zeroize();
        self.message_id.zeroize();
        self.mime_type.zeroize();
        // Sanitized filename scrubs its own private string.
    }
}

impl ObservedAttachmentMetadata {
    /// Returns the provider attachment ID bound by the request and body.
    #[must_use]
    pub fn attachment_id(&self) -> &str {
        &self.attachment_id
    }

    /// Returns the provider parent message ID proven by response metadata.
    #[must_use]
    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    /// Returns a portable filename when provider metadata includes a name.
    #[must_use]
    pub const fn sanitized_name(&self) -> Option<&SanitizedAttachmentFilename> {
        self.sanitized_name.as_ref()
    }

    /// Returns the provider-declared attachment size.
    #[must_use]
    pub const fn declared_size(&self) -> u64 {
        self.declared_size
    }

    /// Returns the provider-declared MIME type.
    #[must_use]
    pub fn mime_type(&self) -> &str {
        &self.mime_type
    }
}

impl Debug for ObservedAttachmentMetadata {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("ObservedAttachmentMetadata")
            .field("attachment_id", &"<redacted>")
            .field("message_id", &"<redacted>")
            .field(
                "sanitized_name",
                &self.sanitized_name.as_ref().map(|_| "<redacted>"),
            )
            .field("declared_size", &"<redacted>")
            .field("mime_type", &"<redacted>")
            .finish()
    }
}

/// One exact safe projection of the attachment metadata HTTP response.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedAttachmentMetadataResponse {
    metadata: ObservedAttachmentMetadata,
}

impl ObservedAttachmentMetadataResponse {
    /// Maximum decoded JSON body accepted by this metadata-only boundary.
    pub const MAX_BODY_BYTES: usize = MAX_ATTACHMENT_METADATA_BODY_BYTES;

    /// Parses exact attachment metadata and binds it to its expected message.
    ///
    /// # Errors
    ///
    /// Rejects endpoint, attachment ID, parent message ID, provider status,
    /// field type, or size-bound drift.
    pub fn parse(
        method: &str,
        url: &str,
        expected_message_id: &str,
        body: &str,
    ) -> Result<Self, AttachmentMetadataResponseError> {
        let requested_attachment_id = if method == "GET" {
            attachment_id_from_metadata_url(url)?
        } else {
            None
        }
        .ok_or(AttachmentMetadataResponseError::UnexpectedEndpoint)?;
        // jig-ignore-next-line: rustfmt keeps this private parser call flat.
        Self::parse_expected_id(requested_attachment_id, expected_message_id, body)
    }

    // Both selectors are already validated at the CDP projection boundary.
    // Avoid a second copied private attachment ID inside a formatted URL.
    fn parse_expected_id(
        requested_attachment_id: &str,
        expected_message_id: &str,
        body: &str,
    ) -> Result<Self, AttachmentMetadataResponseError> {
        validate_expected_message_id(expected_message_id)?;
        if body.len() > Self::MAX_BODY_BYTES {
            return Err(AttachmentMetadataResponseError::BodyTooLarge);
        }
        let value = strict_json::from_sensitive_slice(body.as_bytes())
            .map_err(|_error| AttachmentMetadataResponseError::Malformed)?;
        if value.get("Code").and_then(Value::as_u64) != Some(1000) {
            return Err(AttachmentMetadataResponseError::ProviderRejected);
        }
        let attachment = value
            .get("Attachment")
            .and_then(Value::as_object)
            .ok_or(AttachmentMetadataResponseError::Malformed)?;
        // Copy identity only into the final scrub-on-drop metadata after
        // every body and parent validation has succeeded.
        let attachment_id =
            // jig-ignore-next-line: canonical rustfmt line.
            bounded_required_str(attachment, "ID", MAX_ATTACHMENT_ID_BYTES, false)?;
        if !safe_read_id(attachment_id, MAX_ATTACHMENT_ID_BYTES) {
            return Err(AttachmentMetadataResponseError::Malformed);
        }
        if attachment_id != requested_attachment_id {
            // jig-ignore-next-line: canonical rustfmt line.
            return Err(AttachmentMetadataResponseError::AttachmentIdentityMismatch);
        }
        let message_id =
            // jig-ignore-next-line: canonical rustfmt line.
            bounded_required_str(attachment, "MessageID", MAX_MESSAGE_ID_BYTES, false)?;
        if !safe_read_id(message_id, MAX_MESSAGE_ID_BYTES) {
            return Err(AttachmentMetadataResponseError::Malformed);
        }
        if message_id != expected_message_id {
            return Err(AttachmentMetadataResponseError::ParentMessageMismatch);
        }
        // jig-ignore-next-line: rustfmt keeps the bounded filename read flat.
        let name = bounded_optional_str(attachment, "Name", MAX_ATTACHMENT_NAME_BYTES)?;
        let sanitized_name = name.map(SanitizedAttachmentFilename::new);
        let declared_size = attachment
            .get("Size")
            .and_then(Value::as_u64)
            .ok_or(AttachmentMetadataResponseError::Malformed)?;
        let mime_type =
            // jig-ignore-next-line: canonical rustfmt line.
            bounded_required_str(attachment, "MIMEType", MAX_MIME_TYPE_BYTES, false)?;
        if !safe_metadata_mime_type(mime_type) {
            return Err(AttachmentMetadataResponseError::Malformed);
        }
        Ok(Self {
            metadata: ObservedAttachmentMetadata {
                attachment_id: String::from(attachment_id),
                message_id: String::from(message_id),
                sanitized_name,
                declared_size,
                mime_type: String::from(mime_type),
            },
        })
    }

    /// Projects one decoded `Network.getResponseBody` envelope.
    ///
    /// # Errors
    ///
    /// Rejects encoded envelopes and every invalid response rejected by
    /// [`Self::parse`].
    pub fn parse_cdp_body(
        attachment_id: &str,
        expected_message_id: &str,
        result: &Value,
    ) -> Result<Self, AttachmentMetadataResponseError> {
        if !safe_read_id(attachment_id, MAX_ATTACHMENT_ID_BYTES) {
            return Err(AttachmentMetadataResponseError::UnexpectedEndpoint);
        }
        if result.as_object().is_none_or(|fields| fields.len() != 2) {
            return Err(AttachmentMetadataResponseError::Malformed);
        }
        let encoded = result
            .get("base64Encoded")
            .and_then(Value::as_bool)
            .ok_or(AttachmentMetadataResponseError::Malformed)?;
        if encoded {
            return Err(AttachmentMetadataResponseError::UnsupportedEncoding);
        }
        let body = result
            .get("body")
            .and_then(Value::as_str)
            .ok_or(AttachmentMetadataResponseError::Malformed)?;
        Self::parse_expected_id(attachment_id, expected_message_id, body)
    }

    /// Returns the content-minimized bound metadata.
    #[must_use]
    pub const fn metadata(&self) -> &ObservedAttachmentMetadata {
        &self.metadata
    }
}

impl Debug for ObservedAttachmentMetadataResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("ObservedAttachmentMetadataResponse")
            .field("metadata", &self.metadata)
            .finish()
    }
}

// Reject non-MIME media names and any raw header control characters.
// Parameters are permitted only as printable ASCII without line breaks.
#[expect(
    clippy::redundant_pub_crate,
    reason = "message detail also validates media types"
)]
pub(crate) fn safe_metadata_mime_type(value: &str) -> bool {
    let printable = value.bytes().all(|byte| (32..=126).contains(&byte));
    if value.trim() != value || !printable {
        return false;
    }
    let essence = value.split(';').next().unwrap_or_default();
    let Some((kind, subtype)) = essence.split_once('/') else {
        return false;
    };
    let valid_token_byte =
        // jig-ignore-next-line: canonical rustfmt token validation closure.
        |byte: u8| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte);
    // jig-ignore-next-line: canonical rustfmt MIME token validator.
    let token = |part: &str| !part.is_empty() && part.bytes().all(valid_token_byte);
    if !token(kind) || !token(subtype) {
        return false;
    }
    let Some(mut rest) = value.get(essence.len()..) else {
        return false;
    };
    // Keep names as borrowed slices of the scrub-on-drop JSON rather than
    // allocating ordinary lowercase copies of private provider metadata.
    // The entire MIME field is bounded to 512 bytes by every caller.
    let mut keys: Vec<&str> = Vec::new();
    while !rest.is_empty() {
        let Some(after_separator) = rest.strip_prefix(';') else {
            return false;
        };
        let parameter = after_separator.trim_start_matches(' ');
        let key_len = parameter
            .bytes()
            .take_while(|byte| valid_token_byte(*byte))
            .count();
        if key_len == 0 || parameter.as_bytes().get(key_len) != Some(&b'=') {
            return false;
        }
        let Some(key) = parameter.get(..key_len) else {
            return false;
        };
        if keys.iter().any(|prior| key.eq_ignore_ascii_case(prior)) {
            return false;
        }
        keys.push(key);
        let Some(after_key) = parameter.get(key_len..) else {
            return false;
        };
        let Some(after_equal) = after_key.strip_prefix('=') else {
            return false;
        };
        rest = after_equal;
        if let Some(quoted) = rest.strip_prefix('"') {
            let mut escaped = false;
            let mut closing = None;
            for (offset, byte) in quoted.bytes().enumerate() {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    closing = Some(offset);
                    break;
                }
            }
            let Some(end_quote) = closing else {
                return false;
            };
            let Some(after_value) = quoted.get(end_quote..) else {
                return false;
            };
            let Some(after_quote) = after_value.strip_prefix('"') else {
                return false;
            };
            rest = after_quote;
        } else {
            let value_len = rest
                .bytes()
                .take_while(|byte| valid_token_byte(*byte))
                .count();
            if value_len == 0 {
                return false;
            }
            let Some(after_value) = rest.get(value_len..) else {
                return false;
            };
            rest = after_value;
        }
        rest = rest.trim_start_matches(' ');
    }
    true
}

/// Why attachment metadata failed exact bounded projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentMetadataResponseError {
    /// Method or URL was not an exact attachment metadata GET.
    UnexpectedEndpoint,
    /// The caller supplied an invalid expected parent message ID.
    InvalidExpectedMessageId,
    /// Decoded metadata JSON exceeded the boundary cap.
    BodyTooLarge,
    /// Provider JSON was malformed or required fields had invalid types/bounds.
    Malformed,
    /// Provider success code was absent or not `1000`.
    ProviderRejected,
    /// Body attachment ID did not match the requested attachment ID.
    AttachmentIdentityMismatch,
    /// Body parent message ID did not match the caller-bound message ID.
    ParentMessageMismatch,
    /// `Network.getResponseBody` returned an encoded envelope.
    UnsupportedEncoding,
}

#[expect(
    clippy::redundant_pub_crate,
    reason = "sibling driver module shares this private-module validator"
)]
pub(crate) fn validate_expected_message_id(
    expected_message_id: &str,
) -> Result<(), AttachmentMetadataResponseError> {
    if !safe_read_id(expected_message_id, MAX_MESSAGE_ID_BYTES) {
        return Err(AttachmentMetadataResponseError::InvalidExpectedMessageId);
    }
    Ok(())
}

fn attachment_id_from_metadata_url(
    url: &str,
) -> Result<Option<&str>, AttachmentMetadataResponseError> {
    let Some(suffix) = url.strip_prefix(ATTACHMENT_URL_PREFIX) else {
        return Ok(None);
    };
    let Some(attachment_id) = suffix.strip_suffix("/metadata") else {
        return Ok(None);
    };
    // Browser-serialized attachment paths percent-encode Unicode text.
    // A raw Unicode route cannot prove which attachment the browser fetched.
    if !url.bytes().all(|byte| byte.is_ascii_graphic())
        || !safe_read_id(attachment_id, MAX_ATTACHMENT_ID_BYTES)
    {
        return Err(AttachmentMetadataResponseError::UnexpectedEndpoint);
    }
    Ok(Some(attachment_id))
}

// jig-ignore-next-line: canonical rustfmt line.
fn network_request_id(event: &Value) -> Result<&str, AttachmentMetadataNetworkError> {
    event
        .get("params")
        .and_then(|params| params.get("requestId"))
        .and_then(Value::as_str)
        .ok_or(AttachmentMetadataNetworkError::MalformedEvent)
}

fn bounded_required_str<'source>(
    object: &'source serde_json::Map<String, Value>,
    key: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<&'source str, AttachmentMetadataResponseError> {
    let value = object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(AttachmentMetadataResponseError::Malformed)?;
    if value.len() > max_bytes || (!allow_empty && value.is_empty()) {
        return Err(AttachmentMetadataResponseError::Malformed);
    }
    Ok(value)
}

fn bounded_optional_str<'source>(
    object: &'source serde_json::Map<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<Option<&'source str>, AttachmentMetadataResponseError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let value = value
                .as_str()
                .ok_or(AttachmentMetadataResponseError::Malformed)?;
            if value.len() > max_bytes {
                return Err(AttachmentMetadataResponseError::Malformed);
            }
            Ok(Some(value))
        }
    }
}

#[cfg(test)]
#[path = "../../../../tests/mail/web/adapter-outbound/dbg_attach.rs"]
mod private_request_diagnostics_tests;
