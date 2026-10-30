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
    requires_zeroizing_string(&child.auth.uid);
    requires_zeroizing_string(child.auth.user_id.as_ref().expect("bound user"));
    requires_zeroizing_string(&child.auth.access_token);
    requires_zeroizing_string(&child.auth.refresh_token);
    requires_zeroizing_scopes(&child.auth.scopes);
    requires_zeroizing_string(child.payload.as_ref().expect("encoded payload"));

    let plaintext: RawForkPayload =
        serde_json::from_slice(br#"{"keyPassword":"synthetic-password"}"#)
            .expect("synthetic decrypted payload must deserialize");
    requires_zeroizing_string(&plaintext.key_password);
}
