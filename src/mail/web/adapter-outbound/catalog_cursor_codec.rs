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

use std::fmt;

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use zeroize::Zeroizing;

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
        let payload = json!({
            "account": account,
            "adapter": WEB_ADAPTER_ID,
            "generation": generation,
            "kind": state.kind().token_name(),
            "offset": offset,
            "page_size": state.page_size(),
            "snapshot": state.snapshot_boundary(),
        });
        let plaintext = serde_json::to_vec(&payload)
            .map(Zeroizing::new)
            .map_err(|_error| WebCatalogCursorCodecError::EncodingFailed)?;
        let mut nonce_bytes = [0u8; CURSOR_NONCE_BYTES];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|_error| WebCatalogCursorCodecError::EntropyUnavailable)?;
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_error| WebCatalogCursorCodecError::EncodingFailed)?;
        let nonce = Nonce::<U12>::try_from(nonce_bytes.as_slice())
            .map_err(|_error| WebCatalogCursorCodecError::EncodingFailed)?;
        let aad = cursor_aad(generation)?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_error| WebCatalogCursorCodecError::EncodingFailed)?;
        let body_capacity = CURSOR_NONCE_BYTES
            .checked_add(ciphertext.len())
            .ok_or(WebCatalogCursorCodecError::EncodingFailed)?;
        let mut body = Vec::with_capacity(body_capacity);
        body.extend_from_slice(&nonce_bytes);
        body.extend_from_slice(&ciphertext);
        let token = format!(
            "{CURSOR_VERSION}.{generation}.{}",
            URL_SAFE_NO_PAD.encode(body)
        );
        if token.len() > MAX_ENCODED_CURSOR_BYTES {
            return Err(WebCatalogCursorCodecError::EncodingFailed);
        }
        Ok(token)
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
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded.unwrap_or_default())
            .map_err(|_error| WebCatalogCursorCodecError::InvalidCursor)?;
        if decoded.len() <= CURSOR_NONCE_BYTES {
            return Err(WebCatalogCursorCodecError::InvalidCursor);
        }
        let (nonce_bytes, ciphertext) = decoded.split_at(CURSOR_NONCE_BYTES);
        let nonce = Nonce::<U12>::try_from(nonce_bytes)
            .map_err(|_error| WebCatalogCursorCodecError::InvalidCursor)?;
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_error| WebCatalogCursorCodecError::InvalidCursor)?;
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
            .map_err(|_error| WebCatalogCursorCodecError::InvalidCursor)?;
        let value: Value = serde_json::from_slice(plaintext.as_slice())
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
