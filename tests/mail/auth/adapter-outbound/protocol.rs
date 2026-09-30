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
//   - Synthetic session-fork protocol and authenticated-payload evidence.
// - Must-Not:
//   - Contact Proton, use live tokens, or depend on a real account.
// - Allows:
//   - Build deterministic AES-GCM fixtures from synthetic handoff material.
// - Split-When:
//   - HTTP transport receives its own fixture server and timeout policy.
// - Merge-When:
//   - One deterministic auth-adapter suite fully owns fork protocol evidence.
// - Summary:
//   - Proves pending polling, authority parsing, redaction, and decryption.
// - Description:
//   - Exercises current and legacy Proton AES-GCM payload layouts offline.
// - Usage:
//   - Run through the workspace test gate.
// - Defaults:
//   - All identifiers, tokens, and key passwords are synthetic.
//

//! Offline Proton session-fork protocol regression tests.

use aes_gcm::aead::consts::{U12, U16};
use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::aes::Aes256;
use aes_gcm::{Aes256Gcm, AesGcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use mail_auth_fork_adapter::ForkPayloadVersion;
use mail_auth_fork_adapter::TargetHandoff;
use mail_auth_fork_adapter::{AnonymousSession, ForkChallenge, ForkPoll};
use mail_auth_fork_adapter::{ProtocolError, ProviderProfile, RequestMethod};
use serde_json::json;

const SELECTOR: &str = "0123456789ABCDEFGHIJ";
const USER_CODE: &str = "ABCDEFGH";
const ACCESS_TOKEN: &str = "synthetic-access-token";
const REFRESH_TOKEN: &str = "synthetic-refresh-token";
const KEY_PASSWORD: &str = "synthetic-key-password";

type LegacyAes256Gcm = AesGcm<Aes256, U16>;

const _: () = assert!(!ProviderProfile::LIVE_AUTH_SUPPORTED);

#[test]
fn provider_profile_records_sdk_default_mail_route() {
    assert_eq!(ProviderProfile::API_BASE, "https://mail.proton.me/api");
    assert_eq!(ProviderProfile::SDK_DEFAULT_APP_VERSION, "Other");
    assert_eq!(ProviderProfile::APP_VERSION_HEADER, "x-pm-appversion");
    assert_eq!(ProviderProfile::AUTH_UID_HEADER, "x-pm-uid");
    assert_eq!(ProviderProfile::AUTHORIZATION_HEADER, "authorization");
    assert_eq!(ProviderProfile::SESSION_BOOTSTRAP_PATH, "/auth/v4/sessions");
    assert_eq!(ProviderProfile::FORK_START_PATH, "/auth/v4/sessions/forks");
}

#[test]
fn bootstrap_request_has_no_provider_authority() {
    let request = ProviderProfile::sdk_model_bootstrap_request();

    assert_eq!(request.method(), RequestMethod::Post);
    assert_eq!(request.path(), "/auth/v4/sessions");
    assert_eq!(request.expose_uid(), None);
    assert_eq!(request.expose_bearer(), None);
    assert_eq!(request.expose_body(), None);
}

#[test]
fn anonymous_bootstrap_parses_authority_and_redacts_debug() {
    let body = serde_json::to_vec(&json!({
        "UID": "synthetic-anonymous-uid",
        "UserID": null,
        "AccessToken": ACCESS_TOKEN,
        "RefreshToken": REFRESH_TOKEN,
        "Scopes": ["loggedin"],
    }))
    .expect("fixture must serialize");
    let parsed = AnonymousSession::parse(200, &body);
    let session = parsed.expect("bootstrap must parse");
    let debug = format!("{session:?}");

    assert_eq!(session.uid(), "synthetic-anonymous-uid");
    assert_eq!(session.expose_access_token(), ACCESS_TOKEN);
    assert_eq!(session.expose_refresh_token(), REFRESH_TOKEN);
    assert_eq!(session.scopes(), ["loggedin"]);
    assert!(!debug.contains(ACCESS_TOKEN));
    assert!(!debug.contains(REFRESH_TOKEN));
}

#[test]
fn anonymous_bootstrap_rejects_bound_user() {
    let body = serde_json::to_vec(&json!({
        "UID": "synthetic-anonymous-uid",
        "UserID": "unexpected-user",
        "AccessToken": ACCESS_TOKEN,
        "RefreshToken": REFRESH_TOKEN,
        "Scopes": ["loggedin"],
    }))
    .expect("fixture must serialize");

    assert_eq!(
        AnonymousSession::parse(200, &body).expect_err("bound user must fail"),
        ProtocolError::UnexpectedBoundUser
    );
}

#[test]
fn challenge_poll_path_is_selector_scoped() {
    let body = json!({
        "Selector": SELECTOR,
        "UserCode": USER_CODE,
    });
    let bytes = serde_json::to_vec(&body).expect("fixture must serialize");
    let parsed = ForkChallenge::parse(200, &bytes);
    let challenge = parsed.expect("challenge must parse");

    assert_eq!(
        challenge.poll_path(),
        "/auth/v4/sessions/forks/0123456789ABCDEFGHIJ"
    );
}

#[test]
fn fork_start_and_poll_requests_borrow_anonymous_authority() {
    let auth = anonymous_session();
    let challenge = challenge();
    let start = auth.fork_start_request();
    let poll = auth.poll_request(&challenge);

    assert_eq!(start.method(), RequestMethod::Get);
    assert_eq!(start.path(), "/auth/v4/sessions/forks");
    assert_eq!(start.expose_uid(), Some("synthetic-anonymous-uid"));
    assert_eq!(start.expose_bearer(), Some(ACCESS_TOKEN));
    assert_eq!(poll.method(), RequestMethod::Get);
    assert_eq!(poll.path(), challenge.poll_path());
    assert_eq!(poll.expose_uid(), Some("synthetic-anonymous-uid"));
    assert_eq!(poll.expose_bearer(), Some(ACCESS_TOKEN));
    assert!(!format!("{poll:?}").contains(ACCESS_TOKEN));
}

#[test]
fn challenge_parser_accepts_exact_provider_shape() {
    let body = json!({
        "Selector": SELECTOR,
        "UserCode": USER_CODE,
    });
    let bytes = serde_json::to_vec(&body).expect("fixture must serialize");
    let parsed = ForkChallenge::parse(200, &bytes);
    let challenge = parsed.expect("challenge must parse");

    assert_eq!(challenge.selector(), SELECTOR);
    assert_eq!(challenge.user_code(), USER_CODE);
}

#[test]
fn polling_422_is_pending_not_auth_failure() {
    assert!(matches!(
        ForkPoll::parse(422, b"provider pending body is intentionally ignored"),
        Ok(ForkPoll::Pending)
    ));
    assert_eq!(
        ForkPoll::parse(401, b"{}").expect_err("401 must fail closed"),
        ProtocolError::UnexpectedStatus(401)
    );
}

#[test]
fn completed_fork_parses_authority_and_redacts_debug() {
    let body = complete_response(None);
    let poll = ForkPoll::parse(200, &body).expect("complete fork must parse");
    let debug = format!("{poll:?}");

    let ForkPoll::Complete(session) = poll else {
        panic!("expected completed fork");
    };
    assert_eq!(session.uid(), "synthetic-session-uid");
    assert_eq!(session.user_id(), "synthetic-user-id");
    assert_eq!(session.scopes(), ["full", "loggedin"]);
    assert_eq!(session.expose_access_token(), ACCESS_TOKEN);
    assert_eq!(session.expose_refresh_token(), REFRESH_TOKEN);
    assert!(!debug.contains(ACCESS_TOKEN));
    assert!(!debug.contains(REFRESH_TOKEN));
    assert!(debug.contains("[REDACTED]"));
}

#[test]
fn refresh_and_logout_specs_keep_secret_material_redacted() {
    let response = complete_response(None);
    let session = completed_session(&response);
    let refresh = session
        .refresh_request()
        .expect("refresh body must serialize");
    let logout = session.logout_request();
    let body = refresh.expose_body().expect("refresh body is required");

    assert_eq!(refresh.method(), RequestMethod::Post);
    assert_eq!(refresh.path(), "/auth/v4/refresh");
    assert_eq!(refresh.expose_uid(), Some("synthetic-session-uid"));
    assert_eq!(refresh.expose_bearer(), None);
    assert!(body.contains(REFRESH_TOKEN));
    assert!(body.contains("https://protonmail.ch"));
    assert!(!format!("{refresh:?}").contains(REFRESH_TOKEN));

    assert_eq!(logout.method(), RequestMethod::Delete);
    assert_eq!(logout.path(), "/auth/v4");
    assert_eq!(logout.expose_uid(), Some("synthetic-session-uid"));
    assert_eq!(logout.expose_bearer(), Some(ACCESS_TOKEN));
    assert_eq!(logout.expose_body(), None);
    assert!(!format!("{logout:?}").contains(ACCESS_TOKEN));
}

#[test]
fn v3_payload_round_trips_with_fork_aad() {
    let handoff = sdk_handoff();
    let key = handoff_key(&handoff);
    let encrypted = encrypt_v3(&key, KEY_PASSWORD);
    let encoded = STANDARD.encode(&encrypted);
    let response = complete_response(Some(&encoded));
    let session = completed_session(&response);
    let decoder = handoff.into_decoder();
    let password = decoder
        .decode(session.encrypted_payload(), ForkPayloadVersion::V3)
        .expect("authenticated current payload must decrypt");

    assert_eq!(password.expose(), KEY_PASSWORD);
    assert_eq!(format!("{password:?}"), "KeyPassword([REDACTED])");
}

#[test]
fn v1_payload_round_trips_without_aad() {
    let handoff = sdk_handoff();
    let key = handoff_key(&handoff);
    let encrypted = encrypt_legacy(&key, KEY_PASSWORD, &[]);
    let encoded = STANDARD.encode(&encrypted);
    let response = complete_response(Some(&encoded));
    let session = completed_session(&response);
    let decoder = handoff.into_decoder();
    let password = decoder
        .decode(session.encrypted_payload(), ForkPayloadVersion::V1)
        .expect("authenticated v1 payload must decrypt");

    assert_eq!(password.expose(), KEY_PASSWORD);
}

#[test]
fn v2_payload_round_trips_with_fork_aad() {
    let handoff = sdk_handoff();
    let key = handoff_key(&handoff);
    let encrypted = encrypt_legacy(&key, KEY_PASSWORD, b"fork");
    let encoded = STANDARD.encode(&encrypted);
    let response = complete_response(Some(&encoded));
    let session = completed_session(&response);
    let decoder = handoff.into_decoder();
    let password = decoder
        .decode(session.encrypted_payload(), ForkPayloadVersion::V2)
        .expect("authenticated v2 payload must decrypt");

    assert_eq!(password.expose(), KEY_PASSWORD);
}

#[test]
fn version_mismatch_fails_authentication() {
    let handoff = sdk_handoff();
    let key = handoff_key(&handoff);
    let encrypted = encrypt_v3(&key, KEY_PASSWORD);
    let decoder = handoff.into_decoder();

    assert_eq!(
        decoder
            .decode(Some(&encrypted), ForkPayloadVersion::V1)
            .expect_err("payload version mismatch must fail"),
        ProtocolError::PayloadAuthenticationFailed
    );
}

#[test]
fn wrong_handoff_key_and_malformed_payload_fail_closed() {
    let source = sdk_handoff();
    let source_key = handoff_key(&source);
    let encrypted = encrypt_v3(&source_key, KEY_PASSWORD);
    let other = sdk_handoff();
    let decoder = other.into_decoder();

    assert_eq!(
        decoder
            .decode(Some(&encrypted), ForkPayloadVersion::V3)
            .expect_err("wrong key must fail authentication"),
        ProtocolError::PayloadAuthenticationFailed
    );
    assert_eq!(
        source
            .into_decoder()
            .decode(Some(b"short"), ForkPayloadVersion::V3)
            .expect_err("undersized payload must fail"),
        ProtocolError::InvalidEncryptedPayload
    );
}

#[test]
fn absent_payload_decodes_to_empty_key_password() {
    let handoff = sdk_handoff();
    let password = handoff
        .into_decoder()
        .decode(None, ForkPayloadVersion::V3)
        .expect("missing payload represents empty key password");

    assert!(password.expose().is_empty());
}

fn sdk_handoff() -> TargetHandoff {
    TargetHandoff::new_for_sdk_model(USER_CODE).expect("entropy must exist")
}

fn anonymous_session() -> AnonymousSession {
    let body = serde_json::to_vec(&json!({
        "UID": "synthetic-anonymous-uid",
        "UserID": null,
        "AccessToken": ACCESS_TOKEN,
        "RefreshToken": REFRESH_TOKEN,
        "Scopes": ["loggedin"],
    }))
    .expect("fixture must serialize");
    AnonymousSession::parse(200, &body).expect("anonymous fixture must parse")
}

fn challenge() -> ForkChallenge {
    let body = serde_json::to_vec(&json!({
        "Selector": SELECTOR,
        "UserCode": USER_CODE,
    }))
    .expect("fixture must serialize");
    ForkChallenge::parse(200, &body).expect("challenge fixture must parse")
}

fn completed_session(body: &[u8]) -> mail_auth_fork_adapter::ForkSession {
    match ForkPoll::parse(200, body).expect("fixture must parse") {
        ForkPoll::Complete(session) => session,
        ForkPoll::Pending => panic!("fixture unexpectedly pending"),
    }
}

fn complete_response(payload: Option<&str>) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "UID": "synthetic-session-uid",
        "UserID": "synthetic-user-id",
        "AccessToken": ACCESS_TOKEN,
        "RefreshToken": REFRESH_TOKEN,
        "Scopes": ["full", "loggedin"],
        "Payload": payload,
    }))
    .expect("fixture must serialize")
}

fn handoff_key(handoff: &TargetHandoff) -> [u8; 32] {
    let payload = handoff.payload();
    let encoded = payload
        .expose()
        .split(':')
        .nth(2)
        .expect("handoff payload must contain key");
    let bytes = STANDARD.decode(encoded).expect("key must be base64");
    bytes.try_into().expect("handoff key must be 32 bytes")
}

fn encrypt_v3(key: &[u8; 32], password: &str) -> Vec<u8> {
    let initialized = Aes256Gcm::new_from_slice(key);
    let cipher = initialized.expect("fixture key must be valid");
    let nonce = Nonce::<U12>::try_from([0x11u8; 12].as_slice())
        .expect("fixture nonce must have valid length");
    let plaintext = json!({ "keyPassword": password }).to_string();
    let input = Payload {
        msg: plaintext.as_bytes(),
        aad: b"fork",
    };
    let ciphertext = cipher
        .encrypt(&nonce, input)
        .expect("fixture encryption must succeed");
    [nonce.as_slice(), ciphertext.as_slice()].concat()
}

fn encrypt_legacy(key: &[u8; 32], password: &str, aad: &[u8]) -> Vec<u8> {
    let initialized = LegacyAes256Gcm::new_from_slice(key);
    let cipher = initialized.expect("fixture key must be valid");
    let nonce = Nonce::<U16>::try_from([0x22u8; 16].as_slice())
        .expect("fixture nonce must have valid length");
    let plaintext = json!({ "keyPassword": password }).to_string();
    let input = Payload {
        msg: plaintext.as_bytes(),
        aad,
    };
    let ciphertext = cipher
        .encrypt(&nonce, input)
        .expect("fixture encryption must succeed");
    [nonce.as_slice(), ciphertext.as_slice()].concat()
}
