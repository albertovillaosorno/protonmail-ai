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

use core::fmt::{Debug, Formatter, Result as FmtResult};

use mail_capability_domain::SanitizedAttachmentFilename;
use serde_json::Value;

// jig-ignore-next-line: canonical rustfmt line.
const ATTACHMENT_URL_PREFIX: &str = "https://mail.proton.me/api/mail/v4/attachments/";
const MAX_ATTACHMENT_METADATA_BODY_BYTES: usize = 256 * 1_024;
const MAX_ATTACHMENT_ID_BYTES: usize = 512;
const MAX_MESSAGE_ID_BYTES: usize = 512;
const MAX_ATTACHMENT_NAME_BYTES: usize = 4_096;
const MAX_MIME_TYPE_BYTES: usize = 512;

/// Content-minimized attachment metadata bound to one parent message.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedAttachmentMetadata {
    attachment_id: String,
    message_id: String,
    sanitized_name: Option<SanitizedAttachmentFilename>,
    declared_size: u64,
    mime_type: String,
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
        // jig-ignore-next-line: canonical rustfmt line.
        if expected_message_id.is_empty() || expected_message_id.len() > MAX_MESSAGE_ID_BYTES {
            // jig-ignore-next-line: canonical rustfmt line.
            return Err(AttachmentMetadataResponseError::InvalidExpectedMessageId);
        }
        if body.len() > Self::MAX_BODY_BYTES {
            return Err(AttachmentMetadataResponseError::BodyTooLarge);
        }
        let value: Value = serde_json::from_str(body)
            .map_err(|_error| AttachmentMetadataResponseError::Malformed)?;
        if value.get("Code").and_then(Value::as_u64) != Some(1000) {
            return Err(AttachmentMetadataResponseError::ProviderRejected);
        }
        let attachment = value
            .get("Attachment")
            .and_then(Value::as_object)
            .ok_or(AttachmentMetadataResponseError::Malformed)?;
        let attachment_id =
            // jig-ignore-next-line: canonical rustfmt line.
            bounded_required_string(attachment, "ID", MAX_ATTACHMENT_ID_BYTES, false)?;
        if attachment_id != requested_attachment_id {
            // jig-ignore-next-line: canonical rustfmt line.
            return Err(AttachmentMetadataResponseError::AttachmentIdentityMismatch);
        }
        let message_id =
            // jig-ignore-next-line: canonical rustfmt line.
            bounded_required_string(attachment, "MessageID", MAX_MESSAGE_ID_BYTES, false)?;
        if message_id != expected_message_id {
            return Err(AttachmentMetadataResponseError::ParentMessageMismatch);
        }
        // jig-ignore-next-line: canonical rustfmt line.
        let name = bounded_optional_string(attachment, "Name", MAX_ATTACHMENT_NAME_BYTES)?;
        // jig-ignore-next-line: canonical rustfmt line.
        let sanitized_name = name.as_deref().map(SanitizedAttachmentFilename::new);
        let declared_size = attachment
            .get("Size")
            .and_then(Value::as_u64)
            .ok_or(AttachmentMetadataResponseError::Malformed)?;
        let mime_type =
            // jig-ignore-next-line: canonical rustfmt line.
            bounded_required_string(attachment, "MIMEType", MAX_MIME_TYPE_BYTES, false)?;
        Ok(Self {
            metadata: ObservedAttachmentMetadata {
                attachment_id,
                message_id,
                sanitized_name,
                declared_size,
                mime_type,
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
        // jig-ignore-next-line: canonical rustfmt line.
        if attachment_id.is_empty() || attachment_id.len() > MAX_ATTACHMENT_ID_BYTES {
            return Err(AttachmentMetadataResponseError::UnexpectedEndpoint);
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
        let url = format!("{ATTACHMENT_URL_PREFIX}{attachment_id}/metadata");
        Self::parse("GET", &url, expected_message_id, body)
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

fn attachment_id_from_metadata_url(
    url: &str,
) -> Result<Option<&str>, AttachmentMetadataResponseError> {
    let Some(suffix) = url.strip_prefix(ATTACHMENT_URL_PREFIX) else {
        return Ok(None);
    };
    let Some(attachment_id) = suffix.strip_suffix("/metadata") else {
        return Ok(None);
    };
    if attachment_id.is_empty()
        || attachment_id.len() > MAX_ATTACHMENT_ID_BYTES
        || attachment_id
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'?' | b'#'))
    {
        return Err(AttachmentMetadataResponseError::UnexpectedEndpoint);
    }
    Ok(Some(attachment_id))
}

fn bounded_required_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<String, AttachmentMetadataResponseError> {
    let value = object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(AttachmentMetadataResponseError::Malformed)?;
    if value.len() > max_bytes || (!allow_empty && value.is_empty()) {
        return Err(AttachmentMetadataResponseError::Malformed);
    }
    Ok(String::from(value))
}

fn bounded_optional_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<Option<String>, AttachmentMetadataResponseError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let value = value
                .as_str()
                .ok_or(AttachmentMetadataResponseError::Malformed)?;
            if value.len() > max_bytes {
                return Err(AttachmentMetadataResponseError::Malformed);
            }
            Ok(Some(String::from(value)))
        }
    }
}
