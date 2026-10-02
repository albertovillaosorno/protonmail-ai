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
//   - Authenticated opaque event-cursor serialization for the web adapter.
// - Must-Not:
//   - Persist cursor keys, expose scope/provider state, or own account
//     identity.
// - Allows:
//   - Encrypt scoped provider watermarks for one managed-browser generation.
// - Split-When:
//   - Cursor key persistence or rotation outlives one managed browser process.
// - Merge-When:
//   - Web event observation and cursor framing become one reviewed boundary.
// - Summary:
//   - Produces confidential tamper-evident version-one web event cursors.
// - Description:
//   - Uses AES-256-GCM, random nonces, URL-safe base64, and scope validation.
// - Usage:
//   - ManagedBrowser owns one codec for exactly one adapter generation.
// - Defaults:
//   - Keys, scope components, and provider watermarks are redacted.
//

//! Authenticated opaque serialization for web-adapter event cursors.

use std::fmt;

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
// jig-ignore-next-line: canonical rustfmt line.
use mail_capability_domain::{EventCursorResumeFailure, EventCursorScope, ScopedEventCursor};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::mailbox_event_watermark::ObservedMailboxEventWatermark;

const CURSOR_VERSION: &str = "ev1";
const CURSOR_AAD_PREFIX: &[u8] = b"protonmail-ai:web-event-cursor:v1:";
const CURSOR_KEY_BYTES: usize = 32;
const CURSOR_NONCE_BYTES: usize = 12;
const MAX_ENCODED_CURSOR_BYTES: usize = 4096;

/// Per-generation authenticated cursor codec owned by the managed web adapter.
#[expect(
    clippy::redundant_pub_crate,
    reason = "sibling driver access while the codec module remains private"
)]
pub(crate) struct WebEventCursorCodec {
    key: Zeroizing<[u8; CURSOR_KEY_BYTES]>,
}

impl WebEventCursorCodec {
    /// Creates one fresh in-memory cursor key.
    ///
    /// # Errors
    ///
    /// Returns `EntropyUnavailable` when the operating system cannot supply
    /// cryptographic random bytes.
    pub(crate) fn fresh() -> Result<Self, WebEventCursorCodecError> {
        let mut key = Zeroizing::new([0u8; CURSOR_KEY_BYTES]);
        getrandom::fill(key.as_mut())
            .map_err(|_error| WebEventCursorCodecError::EntropyUnavailable)?;
        Ok(Self { key })
    }

    /// Encrypts one cursor already bound to the exact current scope.
    ///
    /// # Errors
    ///
    /// Rejects scope drift, invalid provider state, serialization failure, or
    /// unexpected encryption failure.
    pub(crate) fn encode(
        &self,
        generation: &str,
        cursor: &ScopedEventCursor<String>,
        current_scope: &EventCursorScope,
    ) -> Result<String, WebEventCursorCodecError> {
        let state = cursor
            .state_for(current_scope)
            // jig-ignore-next-line: canonical rustfmt line.
            .map_err(|error| WebEventCursorCodecError::from_resume(error.resume_failure()))?;
        ObservedMailboxEventWatermark::validate_event_id(state)
            .map_err(|_error| WebEventCursorCodecError::InvalidCursor)?;
        // jig-ignore-next-line: canonical rustfmt line.
        let (account, adapter, scope_generation) = current_scope.binding_components();
        if scope_generation != generation {
            return Err(WebEventCursorCodecError::CursorExpired);
        }
        let payload = json!({
            "account": account,
            "adapter": adapter,
            "generation": scope_generation,
            "state": state,
        });
        let plaintext = serde_json::to_vec(&payload)
            .map(Zeroizing::new)
            .map_err(|_error| WebEventCursorCodecError::EncodingFailed)?;
        let mut nonce_bytes = [0u8; CURSOR_NONCE_BYTES];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|_error| WebEventCursorCodecError::EntropyUnavailable)?;
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_error| WebEventCursorCodecError::EncodingFailed)?;
        let nonce = Nonce::<U12>::try_from(nonce_bytes.as_slice())
            .map_err(|_error| WebEventCursorCodecError::EncodingFailed)?;
        let aad = cursor_aad(generation)?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_error| WebEventCursorCodecError::EncodingFailed)?;
        let capacity = CURSOR_NONCE_BYTES
            .checked_add(ciphertext.len())
            .ok_or(WebEventCursorCodecError::EncodingFailed)?;
        let mut body = Vec::with_capacity(capacity);
        body.extend_from_slice(&nonce_bytes);
        body.extend_from_slice(&ciphertext);
        let token = format!(
            "{CURSOR_VERSION}.{generation}.{}",
            URL_SAFE_NO_PAD.encode(body)
        );
        if token.len() > MAX_ENCODED_CURSOR_BYTES {
            return Err(WebEventCursorCodecError::EncodingFailed);
        }
        Ok(token)
    }

    /// Authenticates one token and restores its exact scoped provider state.
    ///
    /// # Errors
    ///
    /// Malformed, tampered, or wrong-scope cursors are `InvalidCursor`; a
    /// syntactically valid cursor from another adapter generation is expired.
    pub(crate) fn decode(
        &self,
        generation: &str,
        token: &str,
        current_scope: &EventCursorScope,
    ) -> Result<ScopedEventCursor<String>, WebEventCursorCodecError> {
        if token.is_empty() || token.len() > MAX_ENCODED_CURSOR_BYTES {
            return Err(WebEventCursorCodecError::InvalidCursor);
        }
        let mut parts = token.split('.');
        let version = parts.next();
        let token_generation = parts.next();
        let encoded = parts.next();
        // jig-ignore-next-line: canonical rustfmt line.
        if version != Some(CURSOR_VERSION) || encoded.is_none() || parts.next().is_some() {
            return Err(WebEventCursorCodecError::InvalidCursor);
        }
        let token_generation = token_generation
            .filter(|value| valid_generation_tag(value))
            .ok_or(WebEventCursorCodecError::InvalidCursor)?;
        if token_generation != generation {
            return Err(WebEventCursorCodecError::CursorExpired);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded.unwrap_or_default())
            .map_err(|_error| WebEventCursorCodecError::InvalidCursor)?;
        if decoded.len() <= CURSOR_NONCE_BYTES {
            return Err(WebEventCursorCodecError::InvalidCursor);
        }
        let (nonce_bytes, ciphertext) = decoded.split_at(CURSOR_NONCE_BYTES);
        let nonce = Nonce::<U12>::try_from(nonce_bytes)
            .map_err(|_error| WebEventCursorCodecError::InvalidCursor)?;
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_error| WebEventCursorCodecError::InvalidCursor)?;
        let aad = cursor_aad(generation)?;
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_error| WebEventCursorCodecError::InvalidCursor)?;
        let value: Value = serde_json::from_slice(plaintext.as_slice())
            .map_err(|_error| WebEventCursorCodecError::InvalidCursor)?;
        let object = value
            .as_object()
            .filter(|object| object.len() == 4)
            .ok_or(WebEventCursorCodecError::InvalidCursor)?;
        let account = object_string(object, "account")?;
        let adapter = object_string(object, "adapter")?;
        let payload_generation = object_string(object, "generation")?;
        let state = object_string(object, "state")?;
        ObservedMailboxEventWatermark::validate_event_id(state)
            .map_err(|_error| WebEventCursorCodecError::InvalidCursor)?;
        // jig-ignore-next-line: canonical rustfmt line.
        let payload_scope = EventCursorScope::new(account, adapter, payload_generation)
            .map_err(|_error| WebEventCursorCodecError::InvalidCursor)?;
        let restored = payload_scope.bind(String::from(state));
        restored
            .state_for(current_scope)
            // jig-ignore-next-line: canonical rustfmt line.
            .map_err(|error| WebEventCursorCodecError::from_resume(error.resume_failure()))?;
        Ok(restored)
    }
}

impl fmt::Debug for WebEventCursorCodec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WebEventCursorCodec([REDACTED])")
    }
}

/// Fail-closed web event-cursor serialization failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebEventCursorCodecError {
    /// Operating-system cryptographic entropy was unavailable.
    EntropyUnavailable,
    /// Cursor could not be serialized or encrypted safely.
    EncodingFailed,
    /// Cursor framing, authentication, state, account, or adapter is invalid.
    InvalidCursor,
    /// Cursor belongs to another managed web-adapter generation.
    CursorExpired,
}

impl WebEventCursorCodecError {
    const fn from_resume(failure: EventCursorResumeFailure) -> Self {
        match failure {
            EventCursorResumeFailure::InvalidCursor => Self::InvalidCursor,
            EventCursorResumeFailure::CursorExpired => Self::CursorExpired,
        }
    }

    /// Maps public resume failures into the frozen provider-neutral classes.
    #[must_use]
    pub const fn resume_failure(self) -> Option<EventCursorResumeFailure> {
        match self {
            // jig-ignore-next-line: canonical rustfmt line.
            Self::InvalidCursor => Some(EventCursorResumeFailure::InvalidCursor),
            // jig-ignore-next-line: canonical rustfmt line.
            Self::CursorExpired => Some(EventCursorResumeFailure::CursorExpired),
            Self::EntropyUnavailable | Self::EncodingFailed => None,
        }
    }
}

fn valid_generation_tag(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn cursor_aad(generation: &str) -> Result<Vec<u8>, WebEventCursorCodecError> {
    let capacity = CURSOR_AAD_PREFIX
        .len()
        .checked_add(generation.len())
        .ok_or(WebEventCursorCodecError::EncodingFailed)?;
    let mut aad = Vec::with_capacity(capacity);
    aad.extend_from_slice(CURSOR_AAD_PREFIX);
    aad.extend_from_slice(generation.as_bytes());
    Ok(aad)
}

fn object_string<'value>(
    object: &'value serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'value str, WebEventCursorCodecError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(WebEventCursorCodecError::InvalidCursor)
}
