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
//   - Confidential authenticated mailbox/label snapshot cursor serialization.
// - Must-Not:
//   - Persist keys, retain catalog contents, or perform browser/provider I/O.
// - Allows:
//   - Bind account, adapter generation, kind, size, snapshot, and next offset.
// - Split-When:
//   - Cursor keys need persistence or cross-process rotation.
// - Merge-When:
//   - All web-adapter cursor codecs share one reviewed generic framing layer.
// - Summary:
//   - Produces opaque tamper-evident cursors for in-memory catalog snapshots.
// - Description:
//   - AES-256-GCM protects exact catalog resume state with per-generation keys.
// - Usage:
//   - ManagedBrowser encodes only a next offset from a retained exact snapshot.
// - Defaults:
//   - Wrong account/query/generation is invalid or expired; diagnostics redact.
//

//! Opaque authenticated web-adapter cursors for mailbox and label snapshots.

use crate::strict_json;
use std::fmt;
use std::mem::take;

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{AeadInOut as _, KeyInit as _};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use zeroize::{Zeroize as _, Zeroizing};

// jig-ignore-next-line: canonical rustfmt line.
use crate::mailbox_catalog_page::{MailboxCatalogCursorState, MailboxCatalogPageKind};

const CURSOR_VERSION: &str = "cat1";
const CURSOR_AAD_PREFIX: &[u8] = b"protonmail-ai:web-catalog-cursor:v1:";
const CURSOR_KEY_BYTES: usize = 32;
const CURSOR_NONCE_BYTES: usize = 12;
const MAX_ENCODED_CURSOR_BYTES: usize = 4_096;
const MAX_ACCOUNT_BYTES: usize = 512;
const GENERATION_TAG_CHARS: usize = 32;
const SNAPSHOT_TAG_CHARS: usize = 32;
const WEB_ADAPTER_ID: &str = "proton-mail-web-v1";

// Decode directly into scrub-on-drop storage. Engine::decode may leave a
// partially decoded token prefix in an ordinary Vec if decoding fails.
// jig-ignore-next-line: rustfmt requires the canonical short private signature.
fn decode_guarded_token(encoded: &str) -> Result<Zeroizing<Vec<u8>>, WebCatalogCursorCodecError> {
    if encoded.len() > MAX_ENCODED_CURSOR_BYTES {
        return Err(WebCatalogCursorCodecError::InvalidCursor);
    }
    let estimate = base64::decoded_len_estimate(encoded.len());
    let mut decoded = Zeroizing::new(vec![0u8; estimate]);
    let written = URL_SAFE_NO_PAD
        .decode_slice(encoded, &mut decoded)
        .map_err(|_error| WebCatalogCursorCodecError::InvalidCursor)?;
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
) -> Result<Zeroizing<Vec<u8>>, WebCatalogCursorCodecError> {
    let capacity = nonce
        .len()
        .checked_add(ciphertext.len())
        .ok_or(WebCatalogCursorCodecError::EncodingFailed)?;
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
) -> Result<Zeroizing<String>, WebCatalogCursorCodecError> {
    let error = WebCatalogCursorCodecError::EncodingFailed;
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
struct BorrowedCatalogCursorPayload<'scope> {
    account: &'scope str,
    adapter: &'scope str,
    generation: &'scope str,
    kind: &'scope str,
    offset: u64,
    page_size: u16,
    snapshot: &'scope str,
}

/// Per-generation authenticated codec for catalog continuation state.
#[expect(
    clippy::redundant_pub_crate,
    reason = "sibling driver access while the codec module remains private"
)]
#[derive(Eq, PartialEq)]
pub(crate) struct WebCatalogCursorCodec {
    key: Zeroizing<[u8; CURSOR_KEY_BYTES]>,
}

impl WebCatalogCursorCodec {
    pub(super) fn fresh() -> Result<Self, WebCatalogCursorCodecError> {
        let mut key = Zeroizing::new([0u8; CURSOR_KEY_BYTES]);
        getrandom::fill(key.as_mut())
            .map_err(|_error| WebCatalogCursorCodecError::EntropyUnavailable)?;
        Ok(Self { key })
    }

    pub(super) fn encode(
        &self,
        generation: &str,
        account: &str,
        state: &MailboxCatalogCursorState,
    ) -> Result<String, WebCatalogCursorCodecError> {
        validate_generation(generation)?;
        validate_catalog_account(account)?;
        let offset = u64::try_from(state.offset())
            .map_err(|_error| WebCatalogCursorCodecError::EncodingFailed)?;
        // Borrow account/snapshot identity rather than leaving duplicate
        // private strings in an unzeroized JSON Value on heap. Serialize
        // directly into memory that zeroizes even after a write failure.
        let payload = BorrowedCatalogCursorPayload {
            account,
            adapter: WEB_ADAPTER_ID,
            generation,
            kind: state.kind().token_name(),
            offset,
            page_size: state.page_size(),
            snapshot: state.snapshot_boundary(),
        };
        let mut writer = strict_json::SensitiveJsonWriteBuffer::new();
        serde_json::to_writer(&mut writer, &payload)
            .map_err(|_error| WebCatalogCursorCodecError::EncodingFailed)?;
        // AES-GCM appends a 16-byte authentication tag in place. Reserve
        // without releasing an earlier plaintext allocation first.
        writer
            .reserve_additional(16)
            .map_err(|_error| WebCatalogCursorCodecError::EncodingFailed)?;
        let mut payload_bytes = writer.into_guarded();
        let mut nonce_bytes = [0u8; CURSOR_NONCE_BYTES];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|_error| WebCatalogCursorCodecError::EntropyUnavailable)?;
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_error| WebCatalogCursorCodecError::EncodingFailed)?;
        let nonce = Nonce::<U12>::try_from(nonce_bytes.as_slice())
            .map_err(|_error| WebCatalogCursorCodecError::EncodingFailed)?;
        let aad = cursor_aad(generation)?;
        encrypt_into_guarded(&cipher, &nonce, &aad, &mut payload_bytes)
            .map_err(|_error| WebCatalogCursorCodecError::EncodingFailed)?;
        let body = frame_guarded_cursor_body(&nonce_bytes, &payload_bytes)?;
        // The token itself is a resumable capability. Avoid an unguarded
        // intermediate base64 String and keep rejected output scrub-on-drop.
        // The successful allocation transfers directly to the caller.
        let mut token = encode_guarded_token(generation, &body)?;
        Ok(take(&mut *token))
    }

    pub(super) fn decode(
        &self,
        generation: &str,
        account: &str,
        expected_kind: MailboxCatalogPageKind,
        expected_page_size: u16,
        token: &str,
    ) -> Result<MailboxCatalogCursorState, WebCatalogCursorCodecError> {
        validate_generation(generation)?;
        validate_catalog_account(account)?;
        if token.is_empty() || token.len() > MAX_ENCODED_CURSOR_BYTES {
            return Err(WebCatalogCursorCodecError::InvalidCursor);
        }
        let mut parts = token.split('.');
        let version = parts.next();
        let token_generation = parts.next();
        let encoded = parts.next();
        // jig-ignore-next-line: canonical rustfmt line.
        if version != Some(CURSOR_VERSION) || encoded.is_none() || parts.next().is_some() {
            return Err(WebCatalogCursorCodecError::InvalidCursor);
        }
        let token_generation = token_generation
            .filter(|value| valid_hex_tag(value, GENERATION_TAG_CHARS))
            .ok_or(WebCatalogCursorCodecError::InvalidCursor)?;
        if token_generation != generation {
            return Err(WebCatalogCursorCodecError::CursorExpired);
        }
        let decoded = decode_guarded_token(encoded.unwrap_or_default())?;
        if decoded.len() <= CURSOR_NONCE_BYTES {
            return Err(WebCatalogCursorCodecError::InvalidCursor);
        }
        let (nonce_bytes, ciphertext) = decoded.split_at(CURSOR_NONCE_BYTES);
        let nonce = Nonce::<U12>::try_from(nonce_bytes)
            .map_err(|_error| WebCatalogCursorCodecError::InvalidCursor)?;
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_error| WebCatalogCursorCodecError::InvalidCursor)?;
        let aad = cursor_aad(generation)?;
        let plaintext = decrypt_into_guarded(&cipher, &nonce, &aad, ciphertext)
            .map_err(|_error| WebCatalogCursorCodecError::InvalidCursor)?;
        // Keep validated decoded strings zeroizing, including early-return
        // error paths after authenticated decryption.
        let value = strict_json::from_sensitive_slice(plaintext.as_slice())
            .map_err(|_error| WebCatalogCursorCodecError::InvalidCursor)?;
        let object = value
            .as_object()
            .filter(|object| object.len() == 7)
            .ok_or(WebCatalogCursorCodecError::InvalidCursor)?;
        if object_string(object, "account")? != account
            || object_string(object, "adapter")? != WEB_ADAPTER_ID
            || object_string(object, "generation")? != generation
        {
            return Err(WebCatalogCursorCodecError::InvalidCursor);
        }
        // jig-ignore-next-line: canonical rustfmt line.
        let kind = MailboxCatalogPageKind::from_token_name(object_string(object, "kind")?)
            .ok_or(WebCatalogCursorCodecError::InvalidCursor)?;
        let page_size = object_u64(object, "page_size").and_then(|value| {
            // jig-ignore-next-line: canonical rustfmt line.
            u16::try_from(value).map_err(|_error| WebCatalogCursorCodecError::InvalidCursor)
        })?;
        if kind != expected_kind || page_size != expected_page_size {
            return Err(WebCatalogCursorCodecError::InvalidCursor);
        }
        let snapshot = object_string(object, "snapshot")?;
        if !valid_hex_tag(snapshot, SNAPSHOT_TAG_CHARS) {
            return Err(WebCatalogCursorCodecError::InvalidCursor);
        }
        let offset = usize::try_from(object_u64(object, "offset")?)
            .map_err(|_error| WebCatalogCursorCodecError::InvalidCursor)?;
        MailboxCatalogCursorState::new(snapshot, kind, page_size, offset)
            .map_err(|_error| WebCatalogCursorCodecError::InvalidCursor)
    }
}

impl fmt::Debug for WebCatalogCursorCodec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WebCatalogCursorCodec([REDACTED])")
    }
}

/// Fail-closed opaque mailbox/label cursor serialization failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebCatalogCursorCodecError {
    /// Operating-system entropy was unavailable for key or cursor nonce.
    EntropyUnavailable,
    /// Cursor serialization or authenticated encryption failed unexpectedly.
    EncodingFailed,
    /// Cursor is malformed, tampered, or bound to a different request/account.
    InvalidCursor,
    /// Cursor belongs to another managed web-adapter generation or snapshot.
    CursorExpired,
}

fn validate_generation(value: &str) -> Result<(), WebCatalogCursorCodecError> {
    if !valid_hex_tag(value, GENERATION_TAG_CHARS) {
        return Err(WebCatalogCursorCodecError::EncodingFailed);
    }
    Ok(())
}

#[expect(
    clippy::redundant_pub_crate,
    reason = "sibling driver validates account before provider observation"
)]
pub(crate) const fn validate_catalog_account(
    value: &str,
) -> Result<(), WebCatalogCursorCodecError> {
    if value.is_empty() || value.len() > MAX_ACCOUNT_BYTES {
        return Err(WebCatalogCursorCodecError::InvalidCursor);
    }
    Ok(())
}

fn valid_hex_tag(value: &str, expected_chars: usize) -> bool {
    value.len() == expected_chars
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

fn cursor_aad(generation: &str) -> Result<Vec<u8>, WebCatalogCursorCodecError> {
    let capacity = CURSOR_AAD_PREFIX
        .len()
        .checked_add(generation.len())
        .ok_or(WebCatalogCursorCodecError::EncodingFailed)?;
    let mut aad = Vec::with_capacity(capacity);
    aad.extend_from_slice(CURSOR_AAD_PREFIX);
    aad.extend_from_slice(generation.as_bytes());
    Ok(aad)
}

fn object_string<'value>(
    object: &'value serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'value str, WebCatalogCursorCodecError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(WebCatalogCursorCodecError::InvalidCursor)
}

fn object_u64(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<u64, WebCatalogCursorCodecError> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(WebCatalogCursorCodecError::InvalidCursor)
}

#[cfg(test)]
#[path = "../../../../tests/mail/web/adapter-outbound/catalog_cursor_codec.rs"]
mod authenticated_decryption_tests;
