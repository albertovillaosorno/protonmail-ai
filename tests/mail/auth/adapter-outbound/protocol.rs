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
use mail_auth_fork_adapter::ProviderAuthorizationStatus;
use mail_auth_fork_adapter::ProviderRequestIdentity;
use mail_auth_fork_adapter::ProviderRequestIdentityKind;
use mail_auth_fork_adapter::TargetHandoff;
use mail_auth_fork_adapter::{AnonymousSession, ForkChallenge, ForkPoll};
use mail_auth_fork_adapter::{ProtocolError, ProviderProfile, RequestMethod};
use serde_json::json;
use zeroize::Zeroizing;

const SELECTOR: &str = "0123456789ABCDEFGHIJ";
const USER_CODE: &str = "ABCDEFGH";
const ACCESS_TOKEN: &str = "synthetic-access-token";
const REFRESH_TOKEN: &str = "synthetic-refresh-token";
const KEY_PASSWORD: &str = "synthetic-key-password";

type LegacyAes256Gcm = AesGcm<Aes256, U16>;

#[test]
fn provider_profile_records_sdk_default_mail_route() {
    let authorization = ProviderProfile::authorization();
    assert_eq!(authorization.status(), ProviderAuthorizationStatus::Blocked);
    assert_eq!(authorization.approved(), None);
    assert_eq!(authorization.evidence_reviewed_on(), "2026-09-30");
    assert_eq!(
        authorization.evidence_reference(),
        "docs/architecture/provider-client-registration.mdc"
    );
    assert!(!ProviderProfile::live_auth_supported());
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
    assert_eq!(
        request.request_identity().kind(),
        ProviderRequestIdentityKind::SdkModel
    );
    assert_eq!(request.request_identity().live_app_version(), None);
    assert_eq!(request.request_identity().live_api_base(), None);
    assert!(!request.request_identity().is_live_authorized());
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
fn explicit_provider_failure_cannot_authorize_synthetic_fork_state() {
    let bootstrap = json!({
        "UID":"synthetic-uid", "UserID":null,
        "AccessToken":ACCESS_TOKEN, "RefreshToken":REFRESH_TOKEN,
        "Scopes":["loggedin"]
    });
    let challenge = json!({"Selector":SELECTOR, "UserCode":USER_CODE});
    let fixture = complete_response(None);
    let parsed: Result<serde_json::Value, _> = serde_json::from_slice(&fixture);
    let complete = parsed.expect("complete synthetic fork fixture");
    let fixtures = [bootstrap, challenge, complete];
    for (kind, mut response) in fixtures.into_iter().enumerate() {
        // Each distinct response family must reject an explicit failure;
        // success and absent Code stay compatible with existing fixtures.
        let parse = |body: &[u8]| -> Result<(), ProtocolError> {
            match kind {
                0 => AnonymousSession::parse(200, body).map(|_| ()),
                1 => ForkChallenge::parse(200, body).map(|_| ()),
                _ => ForkPoll::parse(200, body).map(|_| ()),
            }
        };
        assert_eq!(parse(response.to_string().as_bytes()), Ok(()));
        response["Code"] = json!(1000u64);
        assert_eq!(parse(response.to_string().as_bytes()), Ok(()));
        for invalid in [8004u64, 0u64] {
            response["Code"] = json!(invalid);
            assert_eq!(
                parse(response.to_string().as_bytes()),
                Err(ProtocolError::ProviderRejected)
            );
        }
        let malformed_codes = [
            json!("1000"),
            json!(null),
            json!(-1i64),
            json!(1000.5f64),
            json!(true),
            json!(false),
            json!({}),
            json!([]),
        ];
        for malformed in malformed_codes {
            response["Code"] = malformed;
            assert_eq!(
                parse(response.to_string().as_bytes()),
                Err(ProtocolError::MalformedJson)
            );
        }
    }
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
fn header_bound_authority_refuses_unsafe_or_oversized_provider_values() {
    let unsafe_text = [
        "abc\nInjected: yes",
        "abc\rInjected: yes",
        "abc\tdef",
        "abc def",
        "abc\0def",
        "abc\u{7f}def",
        "abc\u{202e}def",
        "abc\u{00e9}def",
    ];
    let oversized = "x".repeat(8_193);
    for value in unsafe_text.into_iter().chain([oversized.as_str()]) {
        for field in ["UID", "AccessToken"] {
            let mut anonymous = json!({
                "UID":"synthetic-anonymous-uid", "UserID":null,
                "AccessToken":ACCESS_TOKEN, "RefreshToken":REFRESH_TOKEN,
                "Scopes":["loggedin"]
            });
            anonymous[field] = json!(value);
            let serialized = anonymous.to_string();
            assert_eq!(
                AnonymousSession::parse(200, serialized.as_bytes()).err(),
                Some(ProtocolError::UnsafeHeaderAuthority),
                "unsafe provider header authority must not be retained"
            );
            let child_body = complete_response(None);
            // jig-ignore-next-line: canonical synthetic JSON fixture parsing.
            let parsed = serde_json::from_slice::<serde_json::Value>(&child_body);
            let mut child = parsed.expect("synthetic child authority");
            child[field] = json!(value);
            let serialized = child.to_string();
            assert_eq!(
                ForkPoll::parse(200, serialized.as_bytes()).err(),
                Some(ProtocolError::UnsafeHeaderAuthority),
                "unsafe child header authority must not be retained"
            );
        }
    }
}

#[test]
fn provider_refresh_bearer_is_individually_bounded() {
    // The total response budget is intentionally much larger than a single
    // retained bearer. Probe exact boundary and one byte above on both paths.
    for (secret, accepted) in [
        ("r".repeat(8_192), true),
        ("r".repeat(8_193), false),
        ("\u{e9}".repeat(4_096), true),
        ("\u{e9}".repeat(4_097), false),
    ] {
        let mut anonymous = json!({
            "UID":"synthetic-anonymous-uid", "UserID":null,
            "AccessToken":ACCESS_TOKEN, "RefreshToken":REFRESH_TOKEN,
            "Scopes":["loggedin"]
        });
        anonymous["RefreshToken"] = json!(secret);
        let body = anonymous.to_string();
        assert!(body.len() < 262_144, "not a response-size rejection");
        let parsed = AnonymousSession::parse(200, body.as_bytes());
        if accepted {
            assert_eq!(
                parsed
                    .expect("bounded bootstrap authority")
                    .expose_refresh_token(),
                secret
            );
        } else {
            // jig-ignore-next-line: rustfmt fixes the typed bearer diagnostic.
            assert_eq!(parsed.err(), Some(ProtocolError::OversizedRefreshAuthority));
        }

        // jig-ignore-next-line: rustfmt keeps this synthetic parse on one line.
        let mut child: serde_json::Value = serde_json::from_slice(&complete_response(None))
            .expect("completed synthetic authority");
        child["RefreshToken"] = json!(secret);
        let body = child.to_string();
        assert!(body.len() < 262_144, "not a response-size rejection");
        let parsed = ForkPoll::parse(200, body.as_bytes());
        if accepted {
            // jig-ignore-next-line: rustfmt keeps the pattern match intact.
            let ForkPoll::Complete(session) = parsed.expect("bounded child authority") else {
                panic!("expected completed child authority");
            };
            assert_eq!(session.expose_refresh_token(), secret);
        } else {
            // jig-ignore-next-line: rustfmt fixes the typed bearer diagnostic.
            assert_eq!(parsed.err(), Some(ProtocolError::OversizedRefreshAuthority));
        }
    }
}

#[test]
fn provider_authority_refuses_ambiguous_scope_labels() {
    type JsonValue = serde_json::Value;
    let unsafe_scopes = [
        "",
        " ",
        "ma il",
        "scope\nline",
        "scope\0byte",
        "scope\u{202e}",
        "scope\u{200b}",
        "caf\u{00e9}",
    ];
    for scope in unsafe_scopes {
        for completed in [false, true] {
            let mut response = if completed {
                serde_json::from_slice::<JsonValue>(&complete_response(None))
                    .expect("completed synthetic authority")
            } else {
                json!({
                    "UID":"synthetic-anonymous-uid", "UserID":null,
                    "AccessToken":ACCESS_TOKEN, "RefreshToken":REFRESH_TOKEN,
                    "Scopes":["loggedin"]
                })
            };
            response["Scopes"] = json!(["loggedin", scope]);
            let body = response.to_string();
            let parsed = if completed {
                ForkPoll::parse(200, body.as_bytes()).map(|_| ())
            } else {
                AnonymousSession::parse(200, body.as_bytes()).map(|_| ())
            };
            assert_eq!(parsed, Err(ProtocolError::MalformedJson));
        }
    }
}

#[test]
fn provider_authority_accepts_bounded_ascii_scope_labels() {
    type JsonValue = serde_json::Value;
    let at_limit = "s".repeat(4_096);
    for label in ["full", "mail.read:write+/-._", at_limit.as_str()] {
        for completed in [false, true] {
            let mut response = if completed {
                serde_json::from_slice::<JsonValue>(&complete_response(None))
                    .expect("completed synthetic authority")
            } else {
                json!({
                    "UID":"synthetic-anonymous-uid", "UserID":null,
                    "AccessToken":ACCESS_TOKEN, "RefreshToken":REFRESH_TOKEN,
                    "Scopes":["loggedin"]
                })
            };
            response["Scopes"] = json!(["loggedin", label]);
            let body = response.to_string();
            if completed {
                let poll = ForkPoll::parse(200, body.as_bytes());
                let poll = poll.expect("valid fork scopes");
                let ForkPoll::Complete(session) = poll else {
                    panic!("expected completed fork");
                };
                assert_eq!(session.scopes()[1], label);
            } else {
                let session = AnonymousSession::parse(200, body.as_bytes());
                let session = session.expect("valid anonymous scopes");
                assert_eq!(session.scopes()[1], label);
            }
        }
    }
}

#[test]
fn completed_fork_rejects_ambiguous_account_binding_user_ids() {
    type JsonValue = serde_json::Value;
    let oversized = "a".repeat(8_193);
    let invalid = [
        " ",
        "synthetic user",
        "synthetic\nuser",
        "synthetic\0user",
        "synthetic\u{202e}user",
        "synthetic\u{034f}user",
        "synthetic\u{2800}user",
        "synthetic\u{3164}user",
        "synthetic\u{fe0f}user",
        "synthetic\u{e0020}user",
        oversized.as_str(),
    ];
    for user_id in invalid {
        let fixture = complete_response(None);
        let parsed: Result<JsonValue, _> = serde_json::from_slice(&fixture);
        let mut response = parsed.expect("synthetic complete response");
        response["UserID"] = json!(user_id);
        let serialized = response.to_string();
        assert!(
            matches!(
                ForkPoll::parse(200, serialized.as_bytes()),
                Err(ProtocolError::InvalidUserId)
            ),
            "malformed account-binding identity must not complete a fork"
        );
    }
}

#[test]
fn completed_fork_accepts_bounded_printable_account_identity() {
    type JsonValue = serde_json::Value;
    let at_limit = "a".repeat(8_192);
    for user_id in [
        "synthetic-user-id",
        "ma\u{00f1}ana",
        "user\u{1f600}",
        at_limit.as_str(),
    ] {
        let fixture = complete_response(None);
        let parsed: Result<JsonValue, _> = serde_json::from_slice(&fixture);
        let mut response = parsed.expect("synthetic complete response");
        response["UserID"] = json!(user_id);
        let serialized = response.to_string();
        let parsed = ForkPoll::parse(200, serialized.as_bytes());
        let parsed = parsed.expect("valid account identity");
        let ForkPoll::Complete(session) = parsed else {
            panic!("expected completed fork");
        };
        assert_eq!(session.user_id(), user_id);
    }
}

#[test]
fn printable_header_authority_preserves_wire_values() {
    let uid = "UID.+/=~!-_";
    let bearer = "Bearer.+/=~!-_";
    let payload = json!({
        "UID":uid, "UserID":null,
        "AccessToken":bearer, "RefreshToken":REFRESH_TOKEN,
        "Scopes":["loggedin"]
    });
    let serialized = payload.to_string();
    let parsed = AnonymousSession::parse(200, serialized.as_bytes());
    let anonymous = parsed.expect("synthetic printable authority");
    let request = anonymous.fork_start_request(sdk_identity());
    assert_eq!(request.expose_uid(), Some(uid));
    assert_eq!(request.expose_bearer(), Some(bearer));
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
        challenge.poll_path().as_str(),
        "/auth/v4/sessions/forks/0123456789ABCDEFGHIJ"
    );
}

#[test]
fn public_poll_path_remains_zeroizing_until_caller_drops_it() {
    fn require_scrubbed_path(_: &Zeroizing<String>) {}

    let challenge = challenge();
    let path = challenge.poll_path();
    require_scrubbed_path(&path);
    assert_eq!(
        path.as_str(),
        "/auth/v4/sessions/forks/0123456789ABCDEFGHIJ"
    );
}

#[test]
fn fork_start_and_poll_requests_borrow_anonymous_authority() {
    let auth = anonymous_session();
    let challenge = challenge();
    let start = auth.fork_start_request(sdk_identity());
    let poll = auth.poll_request(sdk_identity(), &challenge);

    assert_eq!(start.method(), RequestMethod::Get);
    assert_eq!(start.path(), "/auth/v4/sessions/forks");
    assert_eq!(start.expose_uid(), Some("synthetic-anonymous-uid"));
    assert_eq!(start.expose_bearer(), Some(ACCESS_TOKEN));
    assert_eq!(start.request_identity(), sdk_identity());
    assert_eq!(poll.method(), RequestMethod::Get);
    assert_eq!(poll.path(), challenge.poll_path().as_str());
    assert_eq!(poll.expose_uid(), Some("synthetic-anonymous-uid"));
    assert_eq!(poll.expose_bearer(), Some(ACCESS_TOKEN));
    assert_eq!(poll.request_identity(), sdk_identity());
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
fn provider_auth_response_body_size_is_bounded() {
    const MAX_RESPONSE_BYTES: usize = 262_144;
    let challenge = json!({
        "Selector":SELECTOR,"UserCode":USER_CODE,"IgnoredPadding":""
    });
    let base = challenge.to_string();
    let padding = "x".repeat(MAX_RESPONSE_BYTES - base.len());
    let at_limit = json!({
        "Selector":SELECTOR,"UserCode":USER_CODE,"IgnoredPadding":padding
    })
    .to_string();
    assert_eq!(at_limit.len(), MAX_RESPONSE_BYTES);
    assert!(ForkChallenge::parse(200, at_limit.as_bytes()).is_ok());
    let oversized = json!({
        "Selector":SELECTOR,"UserCode":USER_CODE,
        "IgnoredPadding":"x".repeat(MAX_RESPONSE_BYTES)
    })
    .to_string();
    assert!(oversized.len() > MAX_RESPONSE_BYTES);
    assert!(matches!(
        ForkChallenge::parse(200, oversized.as_bytes()),
        Err(ProtocolError::ResponseTooLarge)
    ));

    let bootstrap = json!({
        "UID":"synthetic-anonymous-uid","UserID":null,
        "AccessToken":ACCESS_TOKEN,"RefreshToken":REFRESH_TOKEN,
        "Scopes":["loggedin"],"IgnoredPadding":"x".repeat(MAX_RESPONSE_BYTES)
    })
    .to_string();
    assert!(bootstrap.len() > MAX_RESPONSE_BYTES);
    assert!(matches!(
        AnonymousSession::parse(200, bootstrap.as_bytes()),
        Err(ProtocolError::ResponseTooLarge)
    ));

    let complete_fixture = complete_response(None);
    let mut completed: serde_json::Value =
        serde_json::from_slice(&complete_fixture).expect("complete fixture");
    completed["IgnoredPadding"] = json!("x".repeat(MAX_RESPONSE_BYTES));
    let oversized_fork = completed.to_string();
    assert!(oversized_fork.len() > MAX_RESPONSE_BYTES);
    assert!(matches!(
        ForkPoll::parse(200, oversized_fork.as_bytes()),
        Err(ProtocolError::ResponseTooLarge)
    ));
    assert!(matches!(
        ForkPoll::parse(422, oversized_fork.as_bytes()),
        Err(ProtocolError::ResponseTooLarge)
    ));
}

#[test]
fn pending_fork_poll_has_same_raw_body_ceiling_as_completed_polls() {
    // Keep the provider's ordinary pending status independent of response
    // JSON, but never let it bypass the protocol's input byte ceiling.
    let at_limit = vec![b'x'; 262_144];
    assert!(matches!(
        ForkPoll::parse(422, &at_limit),
        Ok(ForkPoll::Pending)
    ));
    let mut too_large = at_limit;
    too_large.push(b'x');
    assert_eq!(
        ForkPoll::parse(422, &too_large).err(),
        Some(ProtocolError::ResponseTooLarge)
    );
    // Unsuccessful non-pending statuses remain failures, not pending polls.
    assert_eq!(
        ForkPoll::parse(401, &too_large).err(),
        Some(ProtocolError::UnexpectedStatus(401))
    );
}

#[test]
fn completed_poll_refuses_oversized_base64_before_decoding() {
    let encoded = "A".repeat(87_388);
    let response = complete_response(Some(&encoded));
    assert!(response.len() < 262_144);
    assert!(matches!(
        ForkPoll::parse(200, &response),
        Err(ProtocolError::InvalidEncryptedPayload)
    ));
}

#[test]
fn fork_payload_decoder_rejects_oversized_ciphertext_before_authentication() {
    let decoder = sdk_handoff().into_decoder();
    let oversized = vec![0xaa; 65_537];
    for version in [
        ForkPayloadVersion::V1,
        ForkPayloadVersion::V2,
        ForkPayloadVersion::V3,
    ] {
        assert_eq!(
            decoder
                .decode(Some(&oversized), version)
                .expect_err("oversized encrypted payload must fail before GCM"),
            ProtocolError::InvalidEncryptedPayload
        );
    }
}

#[test]
fn fork_challenge_refuses_selector_url_injection_and_control_bearing_codes() {
    // Selectors are interpolated verbatim into a single provider URL segment.
    // Equal-byte-width bad inputs previously crossed the parser unmodified.
    for bad in ['/', '\\', '%', '?', '#', '\n', '\r', '\t', ' ', '\0'] {
        let selector = format!("{}{}", "A".repeat(19), bad);
        let body = json!({"Selector":selector, "UserCode":USER_CODE});
        assert_eq!(
            ForkChallenge::parse(200, &body.to_string().into_bytes()),
            Err(ProtocolError::InvalidChallenge),
            "unsafe selector should not become a poll URL segment"
        );
    }
    // Reserved URI punctuation may alter path parameters or be rewritten by
    // intermediaries despite staying inside an apparent path segment.
    for bad in ";:@&$!*()'\"<>[]{}|^`,".chars() {
        let selector = format!("{}{}", "A".repeat(19), bad);
        let body = json!({"Selector":selector, "UserCode":USER_CODE});
        assert_eq!(
            ForkChallenge::parse(200, &body.to_string().into_bytes()),
            Err(ProtocolError::InvalidChallenge),
            "reserved selector punctuation should not enter the poll route"
        );
    }
    for bad in ['\n', '\r', '\t', ' ', '\0', ':'] {
        let code = format!("ABCDEF{bad}H");
        let body = json!({"Selector":SELECTOR, "UserCode":code});
        assert_eq!(
            ForkChallenge::parse(200, &body.to_string().into_bytes()),
            Err(ProtocolError::InvalidChallenge),
            "unsafe approval code should not reach a handoff"
        );
    }

    for bad in ["ABCDEFG", "ABCDEFGHI"] {
        let body = json!({"Selector":SELECTOR, "UserCode":bad});
        assert_eq!(
            ForkChallenge::parse(200, &body.to_string().into_bytes()),
            Err(ProtocolError::InvalidChallenge)
        );
    }

    let selector = "abcdefghijklmnop+_==";
    assert_eq!(selector.len(), 20);
    let body = json!({"Selector":selector,"UserCode":"AB-CD_12"});
    let accepted = ForkChallenge::parse(200, &body.to_string().into_bytes())
        .expect("safe printable opaque selector and approval code");
    assert_eq!(accepted.selector(), selector);
    assert_eq!(accepted.user_code(), "AB-CD_12");
}

#[test]
fn cloned_fork_challenge_keeps_selector_scope_without_diagnostic_exposure() {
    let challenge = challenge();
    let cloned = challenge.clone();
    assert_eq!(cloned, challenge);
    let anonymous = anonymous_session();
    let poll = anonymous.poll_request(sdk_identity(), &cloned);
    assert_eq!(poll.path(), challenge.poll_path().as_str());
    assert_eq!(cloned.selector(), SELECTOR);
    assert_eq!(cloned.user_code(), USER_CODE);
    let debug = format!("{challenge:?} {cloned:?} {poll:?}");
    assert!(!debug.contains(SELECTOR));
    assert!(!debug.contains(USER_CODE));
}

#[test]
fn fork_authority_debug_never_exposes_login_selectors_or_session_identity() {
    let challenge = challenge();
    let anonymous = anonymous_session();
    let poll = anonymous.poll_request(sdk_identity(), &challenge);
    let completed = complete_response(None);
    let session = completed_session(&completed);
    let debug = format!("{challenge:?} {anonymous:?} {poll:?} {session:?}");

    for sensitive in [
        SELECTOR,
        USER_CODE,
        "synthetic-anonymous-uid",
        "synthetic-session-uid",
        "synthetic-user-id",
        ACCESS_TOKEN,
        REFRESH_TOKEN,
    ] {
        assert!(
            !debug.contains(sensitive),
            "session identity or short-lived approval material was logged"
        );
    }
    assert!(debug.contains("[REDACTED]"));
    // Explicit transport and user-facing access must not be altered.
    assert_eq!(challenge.selector(), SELECTOR);
    assert_eq!(challenge.user_code(), USER_CODE);
    assert_eq!(poll.path(), challenge.poll_path().as_str());
    assert_eq!(session.uid(), "synthetic-session-uid");
}

#[test]
fn refresh_serializer_roundtrips_escaped_secret_without_exposing_it() {
    let decoded = serde_json::from_slice(&complete_response(None));
    let mut body: serde_json::Value = decoded.expect("synthetic authority");
    let secret = "synthetic-\\\"quoted\\\\slash\\nline";
    body["RefreshToken"] = json!(secret);
    let serialized = serde_json::to_vec(&body).expect("provider fixture");
    let session = completed_session(&serialized);
    let refresh = session
        .refresh_request(sdk_identity())
        .expect("serialize escaped refresh authority");
    let wire: serde_json::Value =
        serde_json::from_str(refresh.expose_body().expect("refresh body"))
            .expect("serialized refresh body stays valid JSON");
    assert_eq!(wire["RefreshToken"], json!(secret));
    assert_eq!(wire["ResponseType"], json!("token"));
    assert!(!format!("{refresh:?}").contains(secret));
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
        .refresh_request(sdk_identity())
        .expect("refresh body must serialize");
    let logout = session.logout_request(sdk_identity());
    let body = refresh.expose_body().expect("refresh body is required");

    assert_eq!(refresh.method(), RequestMethod::Post);
    assert_eq!(refresh.path(), "/auth/v4/refresh");
    assert_eq!(refresh.expose_uid(), Some("synthetic-session-uid"));
    assert_eq!(refresh.expose_bearer(), None);
    assert_eq!(refresh.request_identity(), sdk_identity());
    assert!(body.contains(REFRESH_TOKEN));
    assert!(body.contains("https://protonmail.ch"));
    assert!(!format!("{refresh:?}").contains(REFRESH_TOKEN));

    assert_eq!(logout.method(), RequestMethod::Delete);
    assert_eq!(logout.path(), "/auth/v4");
    assert_eq!(logout.expose_uid(), Some("synthetic-session-uid"));
    assert_eq!(logout.expose_bearer(), Some(ACCESS_TOKEN));
    assert_eq!(logout.expose_body(), None);
    assert_eq!(logout.request_identity(), sdk_identity());
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

    assert_eq!(password.expose().len(), 0);
}

const fn sdk_identity() -> ProviderRequestIdentity<'static> {
    ProviderRequestIdentity::sdk_model()
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
