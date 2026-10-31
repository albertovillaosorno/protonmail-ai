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
//   - Compile-checked custody assertions for private fork response models.
// - Must-Not:
//   - Contact Proton, inspect freed memory, or use live provider credentials.
// - Allows:
//   - Verify parsed synthetic sensitive fields have zeroizing owners.
// - Split-When:
//   - Parsed response types move to another protocol boundary.
// - Merge-When:
//   - Protocol custody can be proven by ordinary integration tests.
// - Summary:
//   - Detects unprotected raw parser fields before early-return cleanup.
// - Description:
//   - Asserts private raw-model field types stay zeroizing on parse failure.
// - Usage:
//   - Runs as a unit test of the fork adapter library.
// - Defaults:
//   - All authority, selectors, and decrypted payloads are synthetic.
//

//! Internal raw parser ownership checks for rejected provider responses.

use super::{AnonymousSession, ForkPoll};
use super::{RawAuth, RawChallenge, RawForkPayload, RawForkSession};
use zeroize::Zeroizing;

fn requires_zeroizing_string(_: &Zeroizing<String>) {}
fn requires_zeroizing_scopes(_: &Zeroizing<Vec<String>>) {}

#[test]
fn legacy_and_current_fork_aead_decrypt_into_guarded_plaintext() {
    use super::{LegacyAes256Gcm, decrypt_into_guarded};
    use aes_gcm::aead::consts::{U12, U16};
    use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};

    let key = [7u8; 32];
    let plaintext = b"synthetic-private-key-password";
    let current = Aes256Gcm::new_from_slice(&key).expect("current cipher");
    let current_nonce_bytes = [3u8; 12];
    let current_nonce =
        // jig-ignore-next-line: canonical synthetic nonce.
        Nonce::<U12>::try_from(current_nonce_bytes.as_slice()).expect("current nonce");
    let current_ciphertext = current
        .encrypt(
            &current_nonce,
            Payload {
                msg: plaintext,
                aad: b"fork",
            },
        )
        .expect("synthetic ciphertext");
    let opened: Zeroizing<Vec<u8>> =
        // jig-ignore-next-line: canonical guarded authenticated decryption.
        decrypt_into_guarded(&current, &current_nonce, b"fork", &current_ciphertext)
            .expect("current authenticated plaintext");
    assert_eq!(opened.as_slice(), plaintext);
    let mut tampered = current_ciphertext;
    tampered[0] ^= 1;
    // jig-ignore-next-line: canonical tampered authenticated decryption.
    assert!(decrypt_into_guarded(&current, &current_nonce, b"fork", &tampered).is_err());

    let legacy = LegacyAes256Gcm::new_from_slice(&key).expect("legacy cipher");
    let legacy_nonce_bytes = [4u8; 16];
    // jig-ignore-next-line: canonical synthetic nonce.
    let legacy_nonce = Nonce::<U16>::try_from(legacy_nonce_bytes.as_slice()).expect("legacy nonce");
    let legacy_ciphertext = legacy
        .encrypt(
            &legacy_nonce,
            Payload {
                msg: plaintext,
                aad: b"",
            },
        )
        .expect("synthetic legacy ciphertext");
    let opened: Zeroizing<Vec<u8>> =
        decrypt_into_guarded(&legacy, &legacy_nonce, b"", &legacy_ciphertext)
            .expect("legacy authenticated plaintext");
    assert_eq!(opened.as_slice(), plaintext);
    let mut tampered = legacy_ciphertext;
    tampered[0] ^= 1;
    // jig-ignore-next-line: canonical tampered authenticated decryption.
    assert!(decrypt_into_guarded(&legacy, &legacy_nonce, b"", &tampered).is_err());
}

#[test]
fn raw_anonymous_authority_and_challenge_fields_are_zeroizing() {
    let auth: RawAuth = serde_json::from_slice(
        br#"{
            "UID":"synthetic-uid",
            "UserID":"unexpected-user",
            "AccessToken":"synthetic-access",
            "RefreshToken":"synthetic-refresh",
            "Scopes":[]
        }"#,
    )
    .expect("synthetic bound authority must deserialize");
    requires_zeroizing_string(&auth.uid);
    requires_zeroizing_string(auth.user_id.as_ref().expect("bound user"));
    requires_zeroizing_string(&auth.access_token);
    requires_zeroizing_string(&auth.refresh_token);
    requires_zeroizing_scopes(&auth.scopes);

    let challenge: RawChallenge = serde_json::from_slice(
        br#"{"Selector":"synthetic/unsafe/path","UserCode":"invalid-code"}"#,
    )
    .expect("synthetic invalid challenge must deserialize");
    requires_zeroizing_string(&challenge.selector);
    requires_zeroizing_string(&challenge.user_code);
}

#[test]
fn accepted_auth_scope_collections_remain_scrub_on_drop() {
    let anonymous = AnonymousSession::parse(
        200,
        br#"{
        "UID":"synthetic-uid", "UserID":null,
        "AccessToken":"synthetic-access", "RefreshToken":"synthetic-refresh",
        "Scopes":["loggedin","private-scope"]
    }"#,
    )
    .expect("synthetic anonymous session");
    requires_zeroizing_scopes(&anonymous.scopes);
    assert_eq!(anonymous.scopes(), ["loggedin", "private-scope"]);

    let complete = ForkPoll::parse(
        200,
        br#"{
        "UID":"synthetic-uid", "UserID":"synthetic-user",
        "AccessToken":"synthetic-access", "RefreshToken":"synthetic-refresh",
        "Scopes":["full","private-scope"]
    }"#,
    )
    .expect("synthetic fork response");
    let ForkPoll::Complete(session) = complete else {
        panic!("must complete synthetic fork");
    };
    requires_zeroizing_scopes(&session.scopes);
    assert_eq!(session.scopes(), ["full", "private-scope"]);
}

#[test]
fn child_session_rejects_ambiguous_duplicate_private_authority_fields() {
    let duplicate_uid = br#"{
        "UID":"synthetic-uid", "UID":"synthetic-alias",
        "UserID":"synthetic-user", "AccessToken":"synthetic-access",
        "RefreshToken":"synthetic-refresh", "Scopes":[]
    }"#;
    let duplicate_token = br#"{
        "UID":"synthetic-uid", "UserID":"synthetic-user",
        "AccessToken":"synthetic-access", "AccessToken":"synthetic-alias",
        "RefreshToken":"synthetic-refresh", "Scopes":[]
    }"#;
    let duplicate_payload = br#"{
        "UID":"synthetic-uid", "UserID":"synthetic-user",
        "AccessToken":"synthetic-access", "RefreshToken":"synthetic-refresh",
        "Scopes":[], "Payload":"first", "Payload":"second"
    }"#;
    for body in [
        duplicate_uid.as_slice(),
        duplicate_token.as_slice(),
        duplicate_payload.as_slice(),
    ] {
        assert!(serde_json::from_slice::<RawForkSession>(body).is_err());
        assert!(ForkPoll::parse(200, body).is_err());
    }
}

#[test]
fn malformed_child_session_rejects_after_directly_parsed_private_authority() {
    // Malformed trailing scope/payload fields must drop already-read bearer
    // fields without Serde's flattened-map content buffer.
    for malformed in [
        br#"{
            "UID":"synthetic-uid", "UserID":"synthetic-user",
            "AccessToken":"synthetic-private-access",
            "RefreshToken":"synthetic-private-refresh",
            "Scopes":["synthetic-private-scope",42]
        }"#
        .as_slice(),
        br#"{
            "UID":"synthetic-uid", "UserID":"synthetic-user",
            "AccessToken":"synthetic-private-access",
            "RefreshToken":"synthetic-private-refresh",
            "Scopes":["scope"], "Payload":42
        }"#
        .as_slice(),
    ] {
        assert!(serde_json::from_slice::<RawForkSession>(malformed).is_err());
        assert!(ForkPoll::parse(200, malformed).is_err());
    }
}

#[test]
fn malformed_scope_arrays_fail_after_partial_sensitive_decode() {
    // A later invalid scope must not turn a previously parsed private scope
    // back into an unguarded temporary vector during the error path.
    let malformed = br#"{
        "UID":"synthetic-uid", "UserID":null,
        "AccessToken":"synthetic-access", "RefreshToken":"synthetic-refresh",
        "Scopes":["synthetic-private-scope",42]
    }"#;
    assert!(serde_json::from_slice::<RawAuth>(malformed).is_err());
    assert!(AnonymousSession::parse(200, malformed).is_err());
}

#[test]
fn raw_child_session_and_decrypted_password_fields_are_zeroizing() {
    let child: RawForkSession = serde_json::from_slice(
        br#"{
            "UID":"synthetic-uid",
            "UserID":"synthetic-user",
            "AccessToken":"synthetic-access",
            "RefreshToken":"synthetic-refresh",
            "Scopes":[],
            "Payload":"not-base64"
        }"#,
    )
    .expect("synthetic completed authority must deserialize");
    requires_zeroizing_string(&child.uid);
    requires_zeroizing_string(child.user_id.as_ref().expect("bound user"));
    requires_zeroizing_string(&child.access_token);
    requires_zeroizing_string(&child.refresh_token);
    requires_zeroizing_scopes(&child.scopes);
    requires_zeroizing_string(child.payload.as_ref().expect("encoded payload"));

    let plaintext: RawForkPayload =
        serde_json::from_slice(br#"{"keyPassword":"synthetic-password"}"#)
            .expect("synthetic decrypted payload must deserialize");
    requires_zeroizing_string(&plaintext.key_password);
}

#[test]
fn refresh_json_writer_preserves_guarded_growth_and_wipes_on_failure() {
    use super::{SensitiveRefreshJsonBuffer, serialize_sensitive_json};
    use std::io::Write as _;

    let mut bytes = SensitiveRefreshJsonBuffer::new();
    bytes
        .write_all(b"private-refresh-prefix")
        .expect("synthetic private prefix");
    let expanded = vec![b'x'; 12_000];
    bytes.write_all(&expanded).expect("grow guarded storage");
    let guarded: Zeroizing<Vec<u8>> = bytes.into_guarded();
    assert!(guarded.starts_with(b"private-refresh-prefix"));
    assert_eq!(&guarded[b"private-refresh-prefix".len()..], expanded);

    let token = "synthetic-private-refresh".repeat(500);
    let body = serde_json::json!({"RefreshToken": token});
    let serialized: Zeroizing<String> =
        serialize_sensitive_json(&body).expect("encode synthetic refresh JSON");
    let parsed: serde_json::Value =
        // jig-ignore-next-line: canonical synthetic refresh JSON parity check.
        serde_json::from_str(&serialized).expect("large serialized refresh JSON remains intact");
    assert_eq!(parsed, body);
}

#[test]
fn partial_refresh_serialization_fails_inside_guarded_buffer() {
    use super::{ProtocolError, serialize_sensitive_json};
    use serde::ser::{Error as _, SerializeMap as _};
    use serde::{Serialize, Serializer};

    struct FailAfterToken;

    impl Serialize for FailAfterToken {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut object = serializer.serialize_map(Some(2))?;
            let token = "synthetic-private-refresh";
            object.serialize_entry("RefreshToken", token)?;
            Err(S::Error::custom("synthetic failure after secret"))
        }
    }

    assert!(matches!(
        serialize_sensitive_json(&FailAfterToken),
        Err(ProtocolError::SerializationFailed)
    ));
}

#[test]
fn fork_payload_base64_decodes_directly_into_zeroizing_storage() {
    use super::decode_encrypted_fork_payload;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    let expected = [0u8, 1, 2, 3, 4, 254, 255];
    let encoded = STANDARD.encode(expected);
    let result = decode_encrypted_fork_payload(&encoded);
    let decoded: Zeroizing<Vec<u8>> = result.expect("synthetic fork payload");
    assert_eq!(decoded.as_slice(), expected);
    assert_eq!(decoded.len(), expected.len());
}

#[test]
fn fork_payload_base64_failed_decode_drops_guarded_prefix() {
    use super::{ProtocolError, decode_encrypted_fork_payload};

    // The parser can write a partial output prefix before finding bad base64.
    assert!(matches!(
        decode_encrypted_fork_payload("AAEC!AAA"),
        Err(ProtocolError::InvalidPayloadEncoding)
    ));
}

#[test]
fn fork_payload_base64_refuses_decoded_size_above_auth_bound() {
    use super::decode_encrypted_fork_payload;
    use super::{MAX_ENCODED_PAYLOAD_BYTES, ProtocolError};

    let encoded = "A".repeat(MAX_ENCODED_PAYLOAD_BYTES);
    assert!(matches!(
        decode_encrypted_fork_payload(&encoded),
        Err(ProtocolError::InvalidEncryptedPayload)
    ));
}
