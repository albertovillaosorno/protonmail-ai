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

use crate::strict_json;
use std::fmt;
use std::mem::take;

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{AeadInOut as _, KeyInit as _};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
// jig-ignore-next-line: canonical rustfmt line.
use mail_capability_domain::{EventCursorResumeFailure, EventCursorScope, ScopedEventCursor};
use serde_json::Value;
use zeroize::{Zeroize as _, Zeroizing};

use crate::mailbox_event_watermark::ObservedMailboxEventWatermark;

const CURSOR_VERSION: &str = "ev1";
const CURSOR_AAD_PREFIX: &[u8] = b"protonmail-ai:web-event-cursor:v1:";
const CURSOR_KEY_BYTES: usize = 32;
const CURSOR_NONCE_BYTES: usize = 12;
const MAX_ENCODED_CURSOR_BYTES: usize = 4096;

// Decode directly into scrub-on-drop storage. Engine::decode may leave a
// partially decoded token prefix in an ordinary Vec if decoding fails.
// jig-ignore-next-line: rustfmt requires the canonical short private signature.
fn decode_guarded_token(encoded: &str) -> Result<Zeroizing<Vec<u8>>, WebEventCursorCodecError> {
    if encoded.len() > MAX_ENCODED_CURSOR_BYTES {
        return Err(WebEventCursorCodecError::InvalidCursor);
    }
    let estimate = base64::decoded_len_estimate(encoded.len());
    let mut decoded = Zeroizing::new(vec![0u8; estimate]);
    let written = URL_SAFE_NO_PAD
        .decode_slice(encoded, &mut decoded)
        .map_err(|_error| WebEventCursorCodecError::InvalidCursor)?;
    // The decoder writes only the used prefix. Scrub any unused bytes before
    // truncate changes the Vec length and therefore drop-time wipe range.
    decoded[written..].zeroize();
    decoded.truncate(written);
    Ok(decoded)
}

// Nonce plus sealed continuation state forms a replayable capability even
// before base64 encoding. Keep that temporary token body scrub-on-drop on
// success and on any later encoding failure.
fn frame_guarded_cursor_body(
    nonce: &[u8; CURSOR_NONCE_BYTES],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, WebEventCursorCodecError> {
    let capacity = nonce
        .len()
        .checked_add(ciphertext.len())
        .ok_or(WebEventCursorCodecError::EncodingFailed)?;
    let mut body = Zeroizing::new(Vec::with_capacity(capacity));
    body.extend_from_slice(nonce);
    body.extend_from_slice(ciphertext);
    Ok(body)
}

// Preflight the complete public cursor length before allocating an encoded
// bearer token. Base64 appends directly into exactly pre-sized guarded text.
fn encode_guarded_token(
    generation: &str,
    body: &[u8],
) -> Result<Zeroizing<String>, WebEventCursorCodecError> {
    if !valid_generation_tag(generation) {
        return Err(WebEventCursorCodecError::EncodingFailed);
    }
    let error = WebEventCursorCodecError::EncodingFailed;
    let encoded_len = base64::encoded_len(body.len(), false).ok_or(error)?;
    let capacity = CURSOR_VERSION
        .len()
        .checked_add(generation.len())
        .and_then(|len| len.checked_add(2))
        .and_then(|len| len.checked_add(encoded_len))
        .filter(|len| *len <= MAX_ENCODED_CURSOR_BYTES)
        .ok_or(error)?;
    let mut token = Zeroizing::new(String::with_capacity(capacity));
    token.push_str(CURSOR_VERSION);
    token.push('.');
    token.push_str(generation);
    token.push('.');
    URL_SAFE_NO_PAD.encode_string(body, &mut token);
    Ok(token)
}

#[derive(serde::Serialize)]
struct BorrowedEventCursorPayload<'scope> {
    account: &'scope str,
    adapter: &'scope str,
    generation: &'scope str,
    state: &'scope str,
}

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
        if !valid_generation_tag(generation) {
            return Err(WebEventCursorCodecError::EncodingFailed);
        }
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
        // Borrow private identifiers rather than cloning them into an
        // unzeroized serde_json::Value before encryption. Write directly
        // into a zeroizing buffer, including on serialization errors.
        let payload = BorrowedEventCursorPayload {
            account,
            adapter,
            generation: scope_generation,
            state,
        };
        let mut writer = strict_json::SensitiveJsonWriteBuffer::new();
        serde_json::to_writer(&mut writer, &payload)
            .map_err(|_error| WebEventCursorCodecError::EncodingFailed)?;
        // AES-GCM appends a 16-byte authentication tag in place. Reserve
        // without releasing an earlier plaintext allocation first.
        writer
            .reserve_additional(16)
            .map_err(|_error| WebEventCursorCodecError::EncodingFailed)?;
        let mut payload_bytes = writer.into_guarded();
        let mut nonce_bytes = [0u8; CURSOR_NONCE_BYTES];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|_error| WebEventCursorCodecError::EntropyUnavailable)?;
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_error| WebEventCursorCodecError::EncodingFailed)?;
        let nonce = Nonce::<U12>::try_from(nonce_bytes.as_slice())
            .map_err(|_error| WebEventCursorCodecError::EncodingFailed)?;
        let aad = cursor_aad(generation)?;
        encrypt_into_guarded(&cipher, &nonce, &aad, &mut payload_bytes)
            .map_err(|_error| WebEventCursorCodecError::EncodingFailed)?;
        let body = frame_guarded_cursor_body(&nonce_bytes, &payload_bytes)?;
        // The token itself is a resumable capability. Avoid an unguarded
        // intermediate base64 String and keep rejected output scrub-on-drop.
        // The successful allocation transfers directly to the caller.
        let mut token = encode_guarded_token(generation, &body)?;
        Ok(take(&mut *token))
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
        let decoded = decode_guarded_token(encoded.unwrap_or_default())?;
        if decoded.len() <= CURSOR_NONCE_BYTES {
            return Err(WebEventCursorCodecError::InvalidCursor);
        }
        let (nonce_bytes, ciphertext) = decoded.split_at(CURSOR_NONCE_BYTES);
        let nonce = Nonce::<U12>::try_from(nonce_bytes)
            .map_err(|_error| WebEventCursorCodecError::InvalidCursor)?;
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_error| WebEventCursorCodecError::InvalidCursor)?;
        let aad = cursor_aad(generation)?;
        let plaintext = decrypt_into_guarded(&cipher, &nonce, &aad, ciphertext)
            .map_err(|_error| WebEventCursorCodecError::InvalidCursor)?;
        // Keep validated decoded strings zeroizing, including early-return
        // error paths after authenticated decryption.
        let value = strict_json::from_sensitive_slice(plaintext.as_slice())
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

// Keep serialized plaintext in one zeroizing allocation throughout AEAD
// encryption. The convenience Aead::encrypt API may copy plaintext into an
// ordinary Vec that is dropped without scrubbing if encryption fails.
fn encrypt_into_guarded(
    cipher: &Aes256Gcm,
    nonce: &Nonce<U12>,
    aad: &[u8],
    payload: &mut Zeroizing<Vec<u8>>,
) -> Result<(), aes_gcm::Error> {
    cipher.encrypt_in_place(nonce, aad, &mut **payload)
}

// AEAD must never own decrypted cursor bytes in an ordinary Vec, including
// on authentication failure. Decrypt directly into scrub-on-drop storage.
fn decrypt_into_guarded(
    cipher: &Aes256Gcm,
    nonce: &Nonce<U12>,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, aes_gcm::Error> {
    let mut plaintext = Zeroizing::new(ciphertext.to_vec());
    cipher.decrypt_in_place(nonce, aad, &mut *plaintext)?;
    Ok(plaintext)
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

#[cfg(test)]
#[path = "../../../../tests/mail/web/adapter-outbound/event_cursor_codec.rs"]
mod authenticated_decryption_tests;
