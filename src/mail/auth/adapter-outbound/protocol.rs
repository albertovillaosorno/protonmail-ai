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

use std::borrow::Cow;

use aes_gcm::aead::consts::{U12, U16};
use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::aes::Aes256;
use aes_gcm::{Aes256Gcm, AesGcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::identity::ApprovedMailIdentity;
use crate::identity::ProviderAuthorizationSnapshot;

const HTTP_OK: u16 = 200;
const HTTP_UNPROCESSABLE_ENTITY: u16 = 422;
const STANDARD_NONCE_LEN: usize = 12;
const LEGACY_NONCE_LEN: usize = 16;
const GCM_TAG_LEN: usize = 16;
const FORK_AAD: &[u8] = b"fork";
const FORK_SELECTOR_LEN: usize = 20;
const FORK_USER_CODE_LEN: usize = 8;

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
            path: Cow::Borrowed(Self::SESSION_BOOTSTRAP_PATH),
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
/// The optional serialized body is zeroized when the specification is dropped.
pub struct RequestSpec<'authority> {
    method: RequestMethod,
    path: Cow<'authority, str>,
    identity: ProviderRequestIdentity<'authority>,
    uid: Option<&'authority str>,
    bearer: Option<&'authority str>,
    body: Option<Zeroizing<String>>,
}

impl fmt::Debug for RequestSpec<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestSpec")
            .field("method", &self.method)
            .field("path", &self.path)
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
        self.path.as_ref()
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
    uid: String,
    access_token: SecretText,
    refresh_token: SecretText,
    scopes: Vec<String>,
}

impl fmt::Debug for AnonymousSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnonymousSession")
            .field("uid", &self.uid)
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("scopes", &self.scopes)
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
        &self.scopes
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
            Cow::Borrowed(ProviderProfile::FORK_START_PATH),
        )
    }

    /// Builds one selector-scoped polling request.
    #[must_use]
    pub fn poll_request<'authority>(
        &'authority self,
        identity: ProviderRequestIdentity<'authority>,
        challenge: &ForkChallenge,
    ) -> RequestSpec<'authority> {
        let path = Cow::Owned(challenge.poll_path());
        self.authenticated_request(identity, RequestMethod::Get, path)
    }

    fn authenticated_request<'authority>(
        &'authority self,
        identity: ProviderRequestIdentity<'authority>,
        method: RequestMethod,
        path: Cow<'authority, str>,
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkChallenge {
    selector: String,
    user_code: String,
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

        let parsed = serde_json::from_slice::<RawChallenge>(body);
        let raw = parsed.map_err(|_json| ProtocolError::MalformedJson)?;
        if raw.selector.len() != FORK_SELECTOR_LEN
            || raw.user_code.len() != FORK_USER_CODE_LEN
            || raw.user_code.contains(':')
        {
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
    #[must_use]
    pub fn poll_path(&self) -> String {
        format!(
            "{}/{selector}",
            ProviderProfile::FORK_START_PATH,
            selector = self.selector
        )
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
        if status == HTTP_UNPROCESSABLE_ENTITY {
            return Ok(Self::Pending);
        }
        if status != HTTP_OK {
            return Err(ProtocolError::UnexpectedStatus(status));
        }

        let parsed = serde_json::from_slice::<RawForkSession>(body);
        let raw = parsed.map_err(|_json| ProtocolError::MalformedJson)?;
        let user_id = raw.auth.user_id.ok_or(ProtocolError::MissingUserId)?;
        if raw.auth.uid.is_empty()
            || user_id.is_empty()
            || raw.auth.access_token.is_empty()
            || raw.auth.refresh_token.is_empty()
        {
            return Err(ProtocolError::IncompleteAuthority);
        }

        let payload = raw
            .payload
            .map(|encoded| STANDARD.decode(encoded))
            .transpose()
            .map_err(|_error| ProtocolError::InvalidPayloadEncoding)?
            .map(Zeroizing::new);

        Ok(Self::Complete(ForkSession {
            uid: raw.auth.uid,
            user_id,
            access_token: SecretText::new(raw.auth.access_token),
            refresh_token: SecretText::new(raw.auth.refresh_token),
            scopes: raw.auth.scopes,
            payload,
        }))
    }
}

/// Completed child-session response with secret-bearing fields redacted.
pub struct ForkSession {
    uid: String,
    user_id: String,
    access_token: SecretText,
    refresh_token: SecretText,
    scopes: Vec<String>,
    payload: Option<Zeroizing<Vec<u8>>>,
}

impl fmt::Debug for ForkSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForkSession")
            .field("uid", &self.uid)
            .field("user_id", &self.user_id)
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("scopes", &self.scopes)
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
        &self.scopes
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
        let serialized = serde_json::to_string(&body);
        let serialized = match serialized {
            Ok(serialized) => serialized,
            Err(_json) => return Err(ProtocolError::SerializationFailed),
        };
        Ok(RequestSpec {
            method: RequestMethod::Post,
            path: Cow::Borrowed(ProviderProfile::REFRESH_PATH),
            identity,
            uid: Some(self.uid()),
            bearer: None,
            body: Some(Zeroizing::new(serialized)),
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
            path: Cow::Borrowed(ProviderProfile::LOGOUT_PATH),
            identity,
            uid: Some(self.uid()),
            bearer: Some(self.expose_access_token()),
            body: None,
        }
    }
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
        let plaintext = decrypt_payload(&self.key, payload, version)?;
        let bytes = plaintext.as_slice();
        let parsed = serde_json::from_slice::<RawForkPayload>(bytes);
        let decoded = parsed.map_err(|_json| ProtocolError::MalformedPayload)?;
        Ok(KeyPassword(Zeroizing::new(decoded.key_password)))
    }
}

/// Fail-closed session-fork protocol error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    /// The provider returned a status other than 200 or the pending 422.
    UnexpectedStatus(u16),
    /// The response body is not the expected JSON shape.
    MalformedJson,
    /// The selector or human-readable code has an invalid shape.
    InvalidChallenge,
    /// Anonymous bootstrap unexpectedly returned a bound user identity.
    UnexpectedBoundUser,
    /// A completed fork omitted the provider user ID.
    MissingUserId,
    /// A completed fork omitted required session authority.
    IncompleteAuthority,
    /// The encrypted provider payload is not valid base64.
    InvalidPayloadEncoding,
    /// The encrypted payload cannot contain a nonce and authentication tag.
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
    selector: String,
    #[serde(rename = "UserCode")]
    user_code: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawAuth {
    #[serde(rename = "UID")]
    uid: String,
    #[serde(rename = "UserID")]
    user_id: Option<String>,
    access_token: String,
    refresh_token: String,
    scopes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawForkSession {
    #[serde(flatten)]
    auth: RawAuth,
    payload: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawForkPayload {
    key_password: String,
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

struct SecretText(Zeroizing<String>);

impl SecretText {
    fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
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
    let input = Payload {
        msg: ciphertext,
        aad,
    };
    cipher
        .decrypt(&nonce, input)
        .map(Zeroizing::new)
        .map_err(|_error| ProtocolError::PayloadAuthenticationFailed)
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
    let input = Payload {
        msg: ciphertext,
        aad,
    };
    cipher
        .decrypt(&nonce, input)
        .map(Zeroizing::new)
        .map_err(|_error| ProtocolError::PayloadAuthenticationFailed)
}
