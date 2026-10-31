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
//   - Session-fork response parsing, pending-state classification, and payload
//     decryption.
// - Must-Not:
//   - Perform network I/O, persist authority, or expose tokens in diagnostics.
// - Allows:
//   - Parse provider responses and decrypt authenticated fork payloads locally.
// - Split-When:
//   - HTTP transport or credential-store installation gains independent policy.
// - Merge-When:
//   - Fork protocol parsing becomes inseparable from the target handoff.
// - Summary:
//   - Converts Proton fork responses into redacted, zeroized adapter values.
// - Description:
//   - Preserves HTTP 422 as pending and supports current and legacy AES-GCM
//     payload layouts.
// - Usage:
//   - Feed exact HTTP status/body pairs from the outbound Proton transport.
// - Defaults:
//   - Non-success status codes fail closed except 422 pending.
//

//! Proton session-fork response parsing and payload decryption.

use std::fmt;
use std::io::{self, Write};
use std::mem::take;

use aes_gcm::aead::consts::{U12, U16};
use aes_gcm::aead::{AeadInOut, KeyInit as _, Nonce as CipherNonce};
use aes_gcm::aes::Aes256;
use aes_gcm::{Aes256Gcm, AesGcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize as _, Zeroizing};

use crate::identity::ApprovedMailIdentity;
use crate::identity::ProviderAuthorizationSnapshot;
use crate::safe_fork_user_code;

const HTTP_OK: u16 = 200;
const HTTP_UNPROCESSABLE_ENTITY: u16 = 422;
const STANDARD_NONCE_LEN: usize = 12;
const LEGACY_NONCE_LEN: usize = 16;
const GCM_TAG_LEN: usize = 16;
const FORK_AAD: &[u8] = b"fork";
const FORK_SELECTOR_LEN: usize = 20;
// Restrict provider-controlled JSON and ciphertext before allocating parsed
// authority or invoking AEAD. These bounds apply even without a live adapter.
const MAX_AUTH_RESPONSE_BYTES: usize = 262_144;
// The UID and access bearer are forwarded as HTTP header values. Reject
// provider-controlled whitespace, non-ASCII, and oversized header material.
const MAX_HEADER_AUTHORITY_BYTES: usize = 8_192;
// Bound the number of individually allocated provider scope strings even
// when a hostile array still fits the overall response byte ceiling.
const MAX_AUTH_SCOPE_COUNT: usize = 128;
const MAX_AUTH_SCOPE_BYTES: usize = 4_096;
const MAX_ENCRYPTED_PAYLOAD_BYTES: usize = 65_536;
const ENCODED_PAYLOAD_CHUNKS: usize = MAX_ENCRYPTED_PAYLOAD_BYTES.div_ceil(3);
const MAX_ENCODED_PAYLOAD_BYTES: usize = ENCODED_PAYLOAD_CHUNKS * 4;

// Decode encrypted fork authority directly into guarded memory: ordinary
// Engine::decode can discard partially written bytes on invalid base64.
// jig-ignore-next-line: rustfmt fixes this private bounded decoder signature.
fn decode_encrypted_fork_payload(encoded: &str) -> ForkResult<Zeroizing<Vec<u8>>> {
    if encoded.len() > MAX_ENCODED_PAYLOAD_BYTES {
        return Err(ProtocolError::InvalidEncryptedPayload);
    }
    let capacity = base64::decoded_len_estimate(encoded.len());
    let mut decoded = Zeroizing::new(vec![0u8; capacity]);
    let used = STANDARD
        .decode_slice(encoded, &mut decoded)
        .map_err(|_error| ProtocolError::InvalidPayloadEncoding)?;
    if used > MAX_ENCRYPTED_PAYLOAD_BYTES {
        return Err(ProtocolError::InvalidEncryptedPayload);
    }
    // Base64 padding can leave bytes past the decoded prefix. Scrub them
    // before truncating: Zeroizing will only wipe a Vec's live length.
    decoded[used..].zeroize();
    decoded.truncate(used);
    Ok(decoded)
}

type LegacyAes256Gcm = AesGcm<Aes256, U16>;

/// Immutable SDK-model profile for the Proton Mail fork protocol.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProviderProfile;

impl ProviderProfile {
    /// Production base selected by Muon for an unnamed `Other` Mail app.
    pub const API_BASE: &'static str = "https://mail.proton.me/api";
    /// Unversioned SDK default used only for protocol modeling.
    pub const SDK_DEFAULT_APP_VERSION: &'static str = "Other";

    /// Returns the repository's current provider-authorization snapshot.
    #[must_use]
    pub fn authorization() -> ProviderAuthorizationSnapshot<'static> {
        ProviderAuthorizationSnapshot::current()
    }

    /// Returns the provider-approved fork payload version when available.
    #[must_use]
    pub fn live_fork_payload_version() -> Option<ForkPayloadVersion> {
        let version = Self::authorization().approved()?.fork_payload_version();
        match version {
            1 => Some(ForkPayloadVersion::V1),
            2 => Some(ForkPayloadVersion::V2),
            3 => Some(ForkPayloadVersion::V3),
            _ => None,
        }
    }

    /// Reports whether complete validated provider approval permits live auth.
    #[must_use]
    pub fn live_identity() -> Option<ProviderRequestIdentity<'static>> {
        Self::authorization()
            .approved()
            .map(ProviderRequestIdentity::approved)
    }

    /// Reports whether complete validated provider approval permits live auth.
    #[must_use]
    pub fn live_auth_supported() -> bool {
        Self::live_identity().is_some()
    }
    /// Header carrying the app identity.
    pub const APP_VERSION_HEADER: &'static str = "x-pm-appversion";
    /// Header binding an authenticated or anonymous provider session.
    pub const AUTH_UID_HEADER: &'static str = "x-pm-uid";
    /// Standard bearer-token header.
    pub const AUTHORIZATION_HEADER: &'static str = "authorization";
    /// Endpoint used to bootstrap an anonymous provider session.
    pub const SESSION_BOOTSTRAP_PATH: &'static str = "/auth/v4/sessions";
    /// Endpoint used to allocate a fork selector and user code.
    pub const FORK_START_PATH: &'static str = "/auth/v4/sessions/forks";
    /// Endpoint used to refresh provider authority.
    pub const REFRESH_PATH: &'static str = "/auth/v4/refresh";
    /// Endpoint used to revoke the current provider session.
    pub const LOGOUT_PATH: &'static str = "/auth/v4";
    /// Redirect URI expected by Proton's refresh flow.
    pub const REFRESH_REDIRECT_URI: &'static str = "https://protonmail.ch";

    /// Returns the SDK-model bootstrap request; not authorized for live use.
    #[must_use]
    pub const fn sdk_model_bootstrap_request() -> RequestSpec<'static> {
        RequestSpec {
            method: RequestMethod::Post,
            path: RequestPath::Static(Self::SESSION_BOOTSTRAP_PATH),
            identity: ProviderRequestIdentity::sdk_model(),
            uid: None,
            bearer: None,
            body: None,
        }
    }
}

/// Provenance class for the client identity attached to provider requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderRequestIdentityKind {
    /// Protocol-model identity using the SDK fallback `Other`.
    SdkModel,
    /// Identity emitted from complete provider-approval evidence.
    Approved,
}

/// Client identity that an outbound provider request must carry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderRequestIdentity<'identity> {
    kind: ProviderRequestIdentityKind,
    app_version: &'identity str,
    api_base: &'identity str,
}

impl ProviderRequestIdentity<'static> {
    /// Returns the SDK fallback identity for offline protocol modeling only.
    #[must_use]
    pub const fn sdk_model() -> Self {
        Self {
            kind: ProviderRequestIdentityKind::SdkModel,
            app_version: ProviderProfile::SDK_DEFAULT_APP_VERSION,
            api_base: ProviderProfile::API_BASE,
        }
    }
}

impl<'identity> ProviderRequestIdentity<'identity> {
    const fn approved(identity: ApprovedMailIdentity<'identity>) -> Self {
        Self {
            kind: ProviderRequestIdentityKind::Approved,
            app_version: identity.app_version(),
            api_base: identity.api_base(),
        }
    }

    /// Returns how the identity was authorized.
    #[must_use]
    pub const fn kind(&self) -> ProviderRequestIdentityKind {
        self.kind
    }

    /// Returns the API base only when provider approval backs the identity.
    #[must_use]
    pub const fn live_api_base(&self) -> Option<&str> {
        if self.is_live_authorized() {
            Some(self.api_base)
        } else {
            None
        }
    }

    /// Returns the app-version only when provider approval backs the identity.
    #[must_use]
    pub const fn live_app_version(&self) -> Option<&str> {
        if self.is_live_authorized() {
            Some(self.app_version)
        } else {
            None
        }
    }

    /// Reports whether provider approval, rather than an SDK model, backs it.
    #[must_use]
    pub const fn is_live_authorized(&self) -> bool {
        matches!(self.kind, ProviderRequestIdentityKind::Approved)
    }
}

/// HTTP method required by an outbound provider request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestMethod {
    /// `GET` request.
    Get,
    /// `POST` request.
    Post,
    /// `DELETE` request.
    Delete,
}

/// Secret-aware outbound request specification.
///
/// The specification borrows existing authority instead of copying token text.
/// Its optional serialized body and owned selector-scoped path are scrubbed
/// on drop.
pub struct RequestSpec<'authority> {
    method: RequestMethod,
    path: RequestPath<'authority>,
    identity: ProviderRequestIdentity<'authority>,
    uid: Option<&'authority str>,
    bearer: Option<&'authority str>,
    body: Option<Zeroizing<String>>,
}

// Keep static public routes borrowed. A selector-bearing poll route is an
// owned authorization artifact and must scrub its allocation on drop.
enum RequestPath<'authority> {
    Static(&'authority str),
    Sensitive(Zeroizing<String>),
}

impl RequestPath<'_> {
    fn as_str(&self) -> &str {
        match self {
            Self::Static(path) => path,
            Self::Sensitive(path) => path.as_str(),
        }
    }
}

impl fmt::Debug for RequestSpec<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestSpec")
            .field("method", &self.method)
            .field("path", &"[REDACTED]")
            .field("identity", &self.identity)
            .field("uid", &self.uid.map(|_| "[REDACTED]"))
            .field("bearer", &self.bearer.map(|_| "[REDACTED]"))
            .field("body", &self.body.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl RequestSpec<'_> {
    /// Returns the required HTTP method.
    #[must_use]
    pub const fn method(&self) -> RequestMethod {
        self.method
    }

    /// Returns the relative provider API path.
    #[must_use]
    pub fn path(&self) -> &str {
        self.path.as_str()
    }

    /// Returns the typed client identity required by the outbound transport.
    #[must_use]
    pub const fn request_identity(&self) -> ProviderRequestIdentity<'_> {
        self.identity
    }

    /// Exposes the provider session UID only to the outbound transport.
    #[must_use]
    pub const fn expose_uid(&self) -> Option<&str> {
        self.uid
    }

    /// Exposes the bearer token only to the outbound transport.
    #[must_use]
    pub const fn expose_bearer(&self) -> Option<&str> {
        self.bearer
    }

    /// Exposes a serialized request body only to the outbound transport.
    #[must_use]
    pub fn expose_body(&self) -> Option<&str> {
        self.body.as_deref().map(String::as_str)
    }
}

/// Anonymous provider authority required before allocating a fork challenge.
pub struct AnonymousSession {
    uid: Zeroizing<String>,
    access_token: SecretText,
    refresh_token: SecretText,
    scopes: Zeroizing<Vec<String>>,
}

impl fmt::Debug for AnonymousSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnonymousSession")
            .field("uid", &"[REDACTED]")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("scope_count", &self.scopes.len())
            .finish()
    }
}

impl AnonymousSession {
    /// Parses `POST /auth/v4/sessions` provider authority.
    ///
    /// # Errors
    ///
    /// Returns an error when status/JSON is invalid, when a user identity is
    /// unexpectedly bound, or when required authority is empty.
    pub fn parse(status: u16, body: &[u8]) -> ForkResult<Self> {
        if status != HTTP_OK {
            return Err(ProtocolError::UnexpectedStatus(status));
        }

        if body.len() > MAX_AUTH_RESPONSE_BYTES {
            return Err(ProtocolError::ResponseTooLarge);
        }
        let parsed = serde_json::from_slice::<RawAuth>(body);
        let raw = parsed.map_err(|_json| ProtocolError::MalformedJson)?;
        if raw.user_id.is_some() {
            return Err(ProtocolError::UnexpectedBoundUser);
        }
        let missing_uid = raw.uid.is_empty();
        let missing_access = raw.access_token.is_empty();
        let missing_refresh = raw.refresh_token.is_empty();
        if missing_uid || missing_access || missing_refresh {
            return Err(ProtocolError::IncompleteAuthority);
        }
        if !safe_header_authority_pair(&raw.uid, &raw.access_token) {
            return Err(ProtocolError::UnsafeHeaderAuthority);
        }

        Ok(Self {
            uid: raw.uid,
            access_token: SecretText::new(raw.access_token),
            refresh_token: SecretText::new(raw.refresh_token),
            scopes: raw.scopes,
        })
    }

    /// Returns the anonymous provider session UID.
    #[must_use]
    pub fn uid(&self) -> &str {
        &self.uid
    }

    /// Exposes the access token only to the outbound HTTP boundary.
    #[must_use]
    pub fn expose_access_token(&self) -> &str {
        self.access_token.expose()
    }

    /// Exposes the refresh token only to the refresh/storage boundary.
    #[must_use]
    pub fn expose_refresh_token(&self) -> &str {
        self.refresh_token.expose()
    }

    /// Returns the provider scopes attached to the anonymous authority.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        self.scopes.as_slice()
    }

    /// Builds the authenticated request that allocates a fork challenge.
    #[must_use]
    pub fn fork_start_request<'authority>(
        &'authority self,
        identity: ProviderRequestIdentity<'authority>,
    ) -> RequestSpec<'authority> {
        self.authenticated_request(
            identity,
            RequestMethod::Get,
            RequestPath::Static(ProviderProfile::FORK_START_PATH),
        )
    }

    /// Builds one selector-scoped polling request.
    #[must_use]
    pub fn poll_request<'authority>(
        &'authority self,
        identity: ProviderRequestIdentity<'authority>,
        challenge: &ForkChallenge,
    ) -> RequestSpec<'authority> {
        let path = RequestPath::Sensitive(challenge.poll_path());
        self.authenticated_request(identity, RequestMethod::Get, path)
    }

    fn authenticated_request<'authority>(
        &'authority self,
        identity: ProviderRequestIdentity<'authority>,
        method: RequestMethod,
        path: RequestPath<'authority>,
    ) -> RequestSpec<'authority> {
        RequestSpec {
            method,
            path,
            identity,
            uid: Some(self.uid()),
            bearer: Some(self.expose_access_token()),
            body: None,
        }
    }
}

/// Provider fork challenge returned before the user approves login.
#[derive(Clone, Eq, PartialEq)]
pub struct ForkChallenge {
    selector: Zeroizing<String>,
    user_code: Zeroizing<String>,
}

impl fmt::Debug for ForkChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForkChallenge")
            .field("selector", &"[REDACTED]")
            .field("user_code", &"[REDACTED]")
            .finish()
    }
}

impl ForkChallenge {
    /// Parses the initial fork response.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for unexpected status, malformed JSON, or an
    /// invalid selector/user-code shape.
    pub fn parse(status: u16, body: &[u8]) -> ForkResult<Self> {
        if status != HTTP_OK {
            return Err(ProtocolError::UnexpectedStatus(status));
        }

        if body.len() > MAX_AUTH_RESPONSE_BYTES {
            return Err(ProtocolError::ResponseTooLarge);
        }
        let parsed = serde_json::from_slice::<RawChallenge>(body);
        let raw = parsed.map_err(|_json| ProtocolError::MalformedJson)?;
        // Poll selectors are inserted verbatim into one URL path segment.
        // Permit URL-unreserved bytes and the +/= forms of Base64 only;
        // other reserved punctuation can be reinterpreted by intermediaries.
        let allowed_selector_byte = |byte: u8| {
            let alphanumeric = byte.is_ascii_alphanumeric();
            let safe_punctuation = b"-_.~+=".contains(&byte);
            alphanumeric || safe_punctuation
        };
        let safe_selector = raw.selector.bytes().all(allowed_selector_byte);
        // Approval codes are passed into a colon-delimited QR payload.
        let safe_code = safe_fork_user_code(&raw.user_code);
        let correct_selector_length = raw.selector.len() == FORK_SELECTOR_LEN;
        if !correct_selector_length || !safe_selector || !safe_code {
            return Err(ProtocolError::InvalidChallenge);
        }

        Ok(Self {
            selector: raw.selector,
            user_code: raw.user_code,
        })
    }

    /// Returns the opaque selector used only for provider polling.
    #[must_use]
    pub fn selector(&self) -> &str {
        &self.selector
    }

    /// Returns the human-friendly code embedded in the target handoff.
    #[must_use]
    pub fn user_code(&self) -> &str {
        &self.user_code
    }

    /// Returns the exact relative path used to poll this selector.
    ///
    /// The owned path embeds short-lived approval authority and is scrubbed
    /// when dropped. Callers must not convert it into a plain owned string.
    #[must_use]
    pub fn poll_path(&self) -> Zeroizing<String> {
        // Never construct a plain intermediate String with a private fork
        // selector. Reserve the complete route before appending it.
        let capacity = ProviderProfile::FORK_START_PATH
            .len()
            .saturating_add(self.selector.len())
            .saturating_add(1);
        let mut path = Zeroizing::new(String::with_capacity(capacity));
        path.push_str(ProviderProfile::FORK_START_PATH);
        path.push('/');
        path.push_str(&self.selector);
        path
    }
}

/// Result of one provider poll attempt.
pub enum ForkPoll {
    /// The origin has not approved the fork yet.
    Pending,
    /// The provider returned complete child-session authority.
    Complete(ForkSession),
}

impl fmt::Debug for ForkPoll {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => f.write_str("ForkPoll::Pending"),
            Self::Complete(session) => {
                let mut tuple = f.debug_tuple("ForkPoll::Complete");
                tuple.field(session);
                tuple.finish()
            }
        }
    }
}

impl ForkPoll {
    /// Parses one `GET /auth/v4/sessions/forks/{selector}` response.
    ///
    /// HTTP 422 is the provider's normal pending signal and is not an auth
    /// failure.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for other non-200 status codes, malformed JSON,
    /// missing identity, invalid payload encoding, or empty authority fields.
    pub fn parse(status: u16, body: &[u8]) -> ForkResult<Self> {
        if status != HTTP_OK && status != HTTP_UNPROCESSABLE_ENTITY {
            return Err(ProtocolError::UnexpectedStatus(status));
        }
        // Pending polls must not silently bypass the same bounded input
        // contract as completed responses. Their content is still ignored.
        if body.len() > MAX_AUTH_RESPONSE_BYTES {
            return Err(ProtocolError::ResponseTooLarge);
        }
        if status == HTTP_UNPROCESSABLE_ENTITY {
            return Ok(Self::Pending);
        }
        let parsed = serde_json::from_slice::<RawForkSession>(body);
        let raw = parsed.map_err(|_json| ProtocolError::MalformedJson)?;
        let user_id = raw.user_id.ok_or(ProtocolError::MissingUserId)?;
        if raw.uid.is_empty()
            || user_id.is_empty()
            || raw.access_token.is_empty()
            || raw.refresh_token.is_empty()
        {
            return Err(ProtocolError::IncompleteAuthority);
        }
        if !safe_header_authority_pair(&raw.uid, &raw.access_token) {
            return Err(ProtocolError::UnsafeHeaderAuthority);
        }

        let payload = raw
            .payload
            .as_deref()
            .map(|encoded| decode_encrypted_fork_payload(encoded))
            .transpose()?;

        Ok(Self::Complete(ForkSession {
            uid: raw.uid,
            user_id,
            access_token: SecretText::new(raw.access_token),
            refresh_token: SecretText::new(raw.refresh_token),
            scopes: raw.scopes,
            payload,
        }))
    }
}

/// Completed child-session response with secret-bearing fields redacted.
pub struct ForkSession {
    uid: Zeroizing<String>,
    user_id: Zeroizing<String>,
    access_token: SecretText,
    refresh_token: SecretText,
    scopes: Zeroizing<Vec<String>>,
    payload: Option<Zeroizing<Vec<u8>>>,
}

impl fmt::Debug for ForkSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForkSession")
            .field("uid", &"[REDACTED]")
            .field("user_id", &"[REDACTED]")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("scope_count", &self.scopes.len())
            .field("payload", &self.payload.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl ForkSession {
    /// Returns the provider session UID.
    #[must_use]
    pub fn uid(&self) -> &str {
        &self.uid
    }

    /// Returns the provider user ID used for account binding.
    #[must_use]
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// Returns the granted provider scopes.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        self.scopes.as_slice()
    }

    /// Exposes the access token only at a secret-aware storage/transport
    /// boundary.
    #[must_use]
    pub fn expose_access_token(&self) -> &str {
        self.access_token.expose()
    }

    /// Exposes the refresh token only at a secret-aware storage/transport
    /// boundary.
    #[must_use]
    pub fn expose_refresh_token(&self) -> &str {
        self.refresh_token.expose()
    }

    /// Returns the encrypted fork payload, if the origin supplied one.
    #[must_use]
    pub fn encrypted_payload(&self) -> Option<&[u8]> {
        self.payload.as_deref().map(Vec::as_slice)
    }

    /// Builds the provider refresh request using the current refresh token.
    ///
    /// # Errors
    ///
    /// Returns an error only if JSON serialization fails.
    pub fn refresh_request<'authority>(
        &'authority self,
        identity: ProviderRequestIdentity<'authority>,
    ) -> ForkResult<RequestSpec<'authority>> {
        let body = RefreshBody {
            refresh_token: self.expose_refresh_token(),
            response_type: "token",
            grant_type: "refresh_token",
            redirect_uri: ProviderProfile::REFRESH_REDIRECT_URI,
        };
        // Never construct an ordinary unzeroized JSON String containing the
        // refresh bearer, even if serialization aborts after writing it.
        let serialized = serialize_sensitive_json(&body)?;
        Ok(RequestSpec {
            method: RequestMethod::Post,
            path: RequestPath::Static(ProviderProfile::REFRESH_PATH),
            identity,
            uid: Some(self.uid()),
            bearer: None,
            body: Some(serialized),
        })
    }

    /// Builds the provider logout request for the current child session.
    #[must_use]
    pub fn logout_request<'authority>(
        &'authority self,
        identity: ProviderRequestIdentity<'authority>,
    ) -> RequestSpec<'authority> {
        RequestSpec {
            method: RequestMethod::Delete,
            path: RequestPath::Static(ProviderProfile::LOGOUT_PATH),
            identity,
            uid: Some(self.uid()),
            bearer: Some(self.expose_access_token()),
            body: None,
        }
    }
}

// Refresh bearer JSON can be larger than the initial Vec allocation. Keep
// every replaced plaintext allocation under a zeroizing owner before growth;
// ordinary Vec expansion would release prior token prefixes unmodified.
struct SensitiveRefreshJsonBuffer {
    bytes: Zeroizing<Vec<u8>>,
}

impl SensitiveRefreshJsonBuffer {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new(Vec::new()),
        }
    }

    fn into_guarded(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

#[expect(
    clippy::missing_trait_methods,
    reason = "Write defaults delegate to guarded serialization"
)]
impl Write for SensitiveRefreshJsonBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let required = self
            .bytes
            .len()
            .checked_add(buf.len())
            .ok_or_else(|| io::Error::other("sensitive JSON size overflow"))?;
        if required > self.bytes.capacity() {
            // jig-ignore-next-line: canonical checked growth capacity.
            let capacity = required.checked_next_power_of_two().unwrap_or(required);
            let mut replacement = Zeroizing::new(Vec::new());
            replacement
                .try_reserve_exact(capacity)
                // jig-ignore-next-line: canonical redacted allocation error.
                .map_err(|_error| io::Error::other("sensitive JSON allocation failed"))?;
            replacement.extend_from_slice(&self.bytes);
            self.bytes = replacement;
        }
        // Reserve above guarantees this cannot trigger ordinary Vec growth.
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// Serialize directly into zeroizing bytes, including partial writer errors.
// Moving the backing Vec into String preserves the allocation without a new
// plaintext copy; the UTF-8 error case also guards the original byte buffer.
fn serialize_sensitive_json<T>(value: &T) -> ForkResult<Zeroizing<String>>
where
    T: Serialize,
{
    let mut writer = SensitiveRefreshJsonBuffer::new();
    serde_json::to_writer(&mut writer, value)
        .map_err(|_json| ProtocolError::SerializationFailed)?;
    let mut bytes = writer.into_guarded();
    let serialized = String::from_utf8(take(&mut *bytes)).map_err(|error| {
        let _invalid_utf8 = Zeroizing::new(error.into_bytes());
        ProtocolError::SerializationFailed
    })?;
    Ok(Zeroizing::new(serialized))
}

/// Secret key password recovered from the authenticated fork payload.
pub struct KeyPassword(Zeroizing<String>);

impl KeyPassword {
    /// Exposes the value only to the key-unlock boundary.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for KeyPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyPassword([REDACTED])")
    }
}

/// Encrypted fork-payload format negotiated on the approval URL.
///
/// Mirrors pinned `WebClients` fork payload versions 1 through 3.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForkPayloadVersion {
    /// Legacy 16-byte IV without additional authenticated data.
    V1,
    /// Legacy 16-byte IV authenticated with the `fork` context.
    V2,
    /// Standard 12-byte IV authenticated with the `fork` context.
    V3,
}

/// Decoder that exclusively owns the target's short-lived handoff key.
pub struct ForkPayloadDecoder {
    key: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for ForkPayloadDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ForkPayloadDecoder([REDACTED])")
    }
}

impl ForkPayloadDecoder {
    pub(crate) const fn new(key: Zeroizing<[u8; 32]>) -> Self {
        Self { key }
    }

    /// Decrypts the provider payload into a zeroized key password.
    ///
    /// A missing payload means an empty key password, matching Proton's target
    /// flow for sessions that do not require a transferred passphrase.
    ///
    /// # Errors
    ///
    /// Returns an error for undersized payloads, failed authentication, invalid
    /// UTF-8/JSON, or a missing `keyPassword` value.
    pub fn decode(
        &self,
        payload: Option<&[u8]>,
        version: ForkPayloadVersion,
    ) -> ForkResult<KeyPassword> {
        let Some(payload) = payload else {
            return Ok(KeyPassword(Zeroizing::new(String::new())));
        };
        if payload.len() > MAX_ENCRYPTED_PAYLOAD_BYTES {
            return Err(ProtocolError::InvalidEncryptedPayload);
        }
        let plaintext = decrypt_payload(&self.key, payload, version)?;
        let bytes = plaintext.as_slice();
        let parsed = serde_json::from_slice::<RawForkPayload>(bytes);
        let decoded = parsed.map_err(|_json| ProtocolError::MalformedPayload)?;
        Ok(KeyPassword(decoded.key_password))
    }
}

/// Fail-closed session-fork protocol error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    /// The provider returned a status other than 200 or the pending 422.
    UnexpectedStatus(u16),
    /// The provider response exceeded the maximum number of input bytes.
    ResponseTooLarge,
    /// The response body is not the expected JSON shape.
    MalformedJson,
    /// The selector or human-readable code has an invalid shape.
    InvalidChallenge,
    /// Anonymous bootstrap unexpectedly returned a bound user identity.
    UnexpectedBoundUser,
    /// A provider UID or access bearer cannot safely enter HTTP headers.
    UnsafeHeaderAuthority,
    /// A completed fork omitted the provider user ID.
    MissingUserId,
    /// A completed fork omitted required session authority.
    IncompleteAuthority,
    /// The encrypted provider payload is not valid base64.
    InvalidPayloadEncoding,
    /// The encrypted payload is too short or exceeds the allowed byte size.
    InvalidEncryptedPayload,
    /// AES-GCM authentication failed for both supported payload layouts.
    PayloadAuthenticationFailed,
    /// The authenticated plaintext is not the expected JSON payload.
    MalformedPayload,
    /// A secret-bearing outbound JSON body could not be serialized.
    SerializationFailed,
}

type ForkResult<T> = Result<T, ProtocolError>;
type Plaintext = Zeroizing<Vec<u8>>;
type PlainResult = ForkResult<Plaintext>;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawChallenge {
    #[serde(deserialize_with = "read_sensitive")]
    selector: Zeroizing<String>,
    #[serde(rename = "UserCode", deserialize_with = "read_sensitive")]
    user_code: Zeroizing<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawAuth {
    #[serde(rename = "UID", deserialize_with = "read_sensitive")]
    uid: Zeroizing<String>,
    #[serde(rename = "UserID", default, deserialize_with = "read_opt_secret")]
    user_id: Option<Zeroizing<String>>,
    #[serde(deserialize_with = "read_sensitive")]
    access_token: Zeroizing<String>,
    #[serde(deserialize_with = "read_sensitive")]
    refresh_token: Zeroizing<String>,
    #[serde(deserialize_with = "read_sensitive_scopes")]
    scopes: Zeroizing<Vec<String>>,
}

// Avoid serde(flatten): Serde buffers a flattened map in intermediate
// content before visiting its fields, briefly owning unguarded authority
// strings. Read each child-session field directly into zeroizing storage.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawForkSession {
    #[serde(rename = "UID", deserialize_with = "read_sensitive")]
    uid: Zeroizing<String>,
    #[serde(rename = "UserID", default, deserialize_with = "read_opt_secret")]
    user_id: Option<Zeroizing<String>>,
    #[serde(deserialize_with = "read_sensitive")]
    access_token: Zeroizing<String>,
    #[serde(deserialize_with = "read_sensitive")]
    refresh_token: Zeroizing<String>,
    #[serde(deserialize_with = "read_sensitive_scopes")]
    scopes: Zeroizing<Vec<String>>,
    #[serde(default, deserialize_with = "read_opt_secret")]
    payload: Option<Zeroizing<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawForkPayload {
    #[serde(deserialize_with = "read_sensitive")]
    key_password: Zeroizing<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct RefreshBody<'secret> {
    refresh_token: &'secret str,
    response_type: &'static str,
    grant_type: &'static str,
    #[serde(rename = "RedirectURI")]
    redirect_uri: &'static str,
}

// Header values are not an arbitrary JSON text channel. Keep their syntax
// bounded before a later HTTP transport receives the parsed authority.
// Refresh tokens are serialized inside a guarded JSON body, not as headers.
fn safe_header_authority_pair(uid: &str, access_token: &str) -> bool {
    safe_header_authority(uid) && safe_header_authority(access_token)
}

fn safe_header_authority(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_HEADER_AUTHORITY_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

// Sensitive fields are wrapped *while* the JSON model is constructed, so
// validation failures also scrub already-deserialized values when it drops.
type SensitiveString = Zeroizing<String>;
type SensitiveOption = Option<SensitiveString>;

fn read_sensitive<'de, D>(deserializer: D) -> Result<SensitiveString, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Zeroizing::new)
}

fn read_opt_secret<'de, D>(deserializer: D) -> Result<SensitiveOption, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    Ok(value.map(Zeroizing::new))
}

// Keep already-read scope strings guarded even if a later scope in the
// untrusted provider array fails to deserialize.
// jig-ignore-next-line: canonical rustfmt sensitive Serde sequence signature.
fn read_sensitive_scopes<'de, D>(deserializer: D) -> Result<Zeroizing<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct ScopeVisitor;

    #[expect(
        clippy::missing_trait_methods,
        reason = "Serde Visitor defaults reject non-sequences"
    )]
    impl<'de> Visitor<'de> for ScopeVisitor {
        type Value = Zeroizing<Vec<String>>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an array of authorization scopes")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut scopes = Zeroizing::new(Vec::new());
            scopes.reserve_exact(MAX_AUTH_SCOPE_COUNT);
            while let Some(scope) = seq.next_element::<String>()? {
                // Take zeroizing ownership before checking the bound: rejected
                // provider text must not be dropped as an ordinary String.
                let mut scope = Zeroizing::new(scope);
                let too_many = scopes.len() >= MAX_AUTH_SCOPE_COUNT;
                let too_large = scope.len() > MAX_AUTH_SCOPE_BYTES;
                if too_many || too_large {
                    return Err(A::Error::custom(
                        "authorization scopes exceed safety bounds",
                    ));
                }
                scopes.push(take(&mut *scope));
            }
            Ok(scopes)
        }
    }

    deserializer.deserialize_seq(ScopeVisitor)
}

struct SecretText(Zeroizing<String>);

impl SecretText {
    const fn new(value: Zeroizing<String>) -> Self {
        Self(value)
    }

    fn expose(&self) -> &str {
        self.0.as_str()
    }
}

fn decrypt_payload(
    key: &[u8; 32],
    payload: &[u8],
    version: ForkPayloadVersion,
) -> ForkResult<Plaintext> {
    match version {
        ForkPayloadVersion::V1 => decrypt_legacy(key, payload, &[]),
        ForkPayloadVersion::V2 => decrypt_legacy(key, payload, FORK_AAD),
        ForkPayloadVersion::V3 => decrypt_standard(key, payload, FORK_AAD),
    }
}

fn decrypt_legacy(key: &[u8; 32], payload: &[u8], aad: &[u8]) -> PlainResult {
    if payload.len() < LEGACY_NONCE_LEN + GCM_TAG_LEN {
        return Err(ProtocolError::InvalidEncryptedPayload);
    }
    let cipher = LegacyAes256Gcm::new_from_slice(key)
        .map_err(|_error| ProtocolError::PayloadAuthenticationFailed)?;
    let (nonce, ciphertext) = payload.split_at(LEGACY_NONCE_LEN);
    let parsed_nonce = Nonce::<U16>::try_from(nonce);
    let invalid = ProtocolError::InvalidEncryptedPayload;
    let nonce = parsed_nonce.map_err(|_nonce| invalid)?;
    decrypt_into_guarded(&cipher, &nonce, aad, ciphertext)
}

fn decrypt_standard(key: &[u8; 32], payload: &[u8], aad: &[u8]) -> PlainResult {
    if payload.len() < STANDARD_NONCE_LEN + GCM_TAG_LEN {
        return Err(ProtocolError::InvalidEncryptedPayload);
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_error| ProtocolError::PayloadAuthenticationFailed)?;
    let (nonce, ciphertext) = payload.split_at(STANDARD_NONCE_LEN);
    let parsed_nonce = Nonce::<U12>::try_from(nonce);
    let invalid = ProtocolError::InvalidEncryptedPayload;
    let nonce = parsed_nonce.map_err(|_nonce| invalid)?;
    decrypt_into_guarded(&cipher, &nonce, aad, ciphertext)
}

// Never allocate decrypted fork key material in an ordinary Vec. The
// in-place AEAD operation owns its output inside zeroizing storage even when
// the authentication tag fails or leaves partially mutated bytes behind.
fn decrypt_into_guarded<C>(
    cipher: &C,
    nonce: &CipherNonce<C>,
    aad: &[u8],
    ciphertext: &[u8],
) -> PlainResult
where
    C: AeadInOut,
{
    let mut plaintext = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_in_place(nonce, aad, &mut *plaintext)
        .map_err(|_error| ProtocolError::PayloadAuthenticationFailed)?;
    Ok(plaintext)
}

#[cfg(test)]
#[path = "../../../../tests/mail/auth/adapter-outbound/raw_protocol_custody.rs"]
mod raw_protocol_custody_tests;
