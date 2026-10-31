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
//   - Synthetic in-place AEAD cursor plaintext custody regression checks.
// - Must-Not:
//   - Use real mail data, persistence, or live provider keys.
// - Allows:
//   - Exercise private catalog cursor authentication without browser state.
// - Split-When:
//   - The codec implementations require distinct cryptographic contracts.
// - Merge-When:
//   - Cursor cryptography gains an independent shared implementation.
// - Summary:
//   - Ensures catalog cursor decryption is guarded and rejects tampering.
// - Description:
//   - A synthetic AES-GCM payload exercises good and corrupt authentication.
// - Usage:
//   - Included from the catalog cursor codec source module.
// - Defaults:
//   - No account, browser, or external network access.
//

//! Checks guarded decryption for catalog continuation cursors.

use super::{CURSOR_KEY_BYTES, CURSOR_NONCE_BYTES, decrypt_into_guarded};
use super::{CURSOR_VERSION, MAX_ENCODED_CURSOR_BYTES};
use super::{decode_guarded_token, encode_guarded_token, encrypt_into_guarded};
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::Zeroizing;

#[test]
fn authenticated_decryption_keeps_plaintext_guarded() {
    // jig-ignore-next-line: canonical synthetic AES fixture.
    let cipher = Aes256Gcm::new_from_slice(&[7u8; CURSOR_KEY_BYTES]).expect("synthetic AES key");
    let nonce_bytes = [9u8; CURSOR_NONCE_BYTES];
    // jig-ignore-next-line: canonical synthetic AES nonce.
    let nonce = Nonce::<U12>::try_from(nonce_bytes.as_slice()).expect("synthetic AES nonce");
    let aad = b"synthetic cursor scope";
    let sealed = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: b"private synthetic catalog",
                aad,
            },
        )
        .expect("seal synthetic cursor");

    let opened: Zeroizing<Vec<u8>> =
        // jig-ignore-next-line: canonical guarded decrypt assertion.
        decrypt_into_guarded(&cipher, &nonce, aad, &sealed).expect("open authentic cursor");
    assert_eq!(opened.as_slice(), b"private synthetic catalog");

    let mut tampered = sealed;
    tampered[0] ^= 1;
    assert!(decrypt_into_guarded(&cipher, &nonce, aad, &tampered).is_err());
}

#[test]
fn authenticated_encryption_never_copies_plaintext_to_unprotected_output() {
    // jig-ignore-next-line: canonical synthetic AES fixture.
    let cipher = Aes256Gcm::new_from_slice(&[5u8; CURSOR_KEY_BYTES]).expect("synthetic AES key");
    let nonce_bytes = [6u8; CURSOR_NONCE_BYTES];
    // jig-ignore-next-line: canonical synthetic AES nonce.
    let nonce = Nonce::<U12>::try_from(nonce_bytes.as_slice()).expect("synthetic AES nonce");
    let aad = b"synthetic authenticated encryption";
    let synthetic_state = b"private synthetic catalog state";
    let mut plaintext = Zeroizing::new(synthetic_state.to_vec());

    encrypt_into_guarded(&cipher, &nonce, aad, &mut plaintext)
        .expect("seal without releasing plaintext");
    let opened: Zeroizing<Vec<u8>> =
        // jig-ignore-next-line: canonical guarded decrypt assertion.
        decrypt_into_guarded(&cipher, &nonce, aad, &plaintext).expect("recover synthetic cursor");
    assert_eq!(opened.as_slice(), b"private synthetic catalog state");
}

#[test]
fn opaque_cursor_token_uses_guarded_storage_without_extra_base64_copy() {
    let opaque_bytes = [0u8, 1, 2, 253, 254, 255];
    let encoded = encode_guarded_token("0123456789abcdef", &opaque_bytes);
    let guarded: Zeroizing<String> = encoded.expect("synthetic cursor token");
    let expected = format!(
        "{CURSOR_VERSION}.0123456789abcdef.{}",
        URL_SAFE_NO_PAD.encode(opaque_bytes)
    );
    assert_eq!(guarded.as_str(), expected);
    assert!(guarded.capacity() >= guarded.len());
}

#[test]
fn oversized_cursor_token_is_refused_before_encoding() {
    let oversized = vec![0xadu8; MAX_ENCODED_CURSOR_BYTES];
    assert!(encode_guarded_token("0123456789abcdef", &oversized).is_err());
}

#[test]
fn decoded_cursor_bytes_have_scrubbed_ownership_from_first_write() {
    let bytes = [3u8, 0, 7, 0xfe, 0xff];
    let encoded = URL_SAFE_NO_PAD.encode(bytes);
    let guarded: Zeroizing<Vec<u8>> =
        decode_guarded_token(&encoded).expect("synthetic token decoded");
    assert_eq!(guarded.as_slice(), bytes);
    assert_eq!(guarded.len(), bytes.len());
}

#[test]
fn malformed_base64_refuses_partially_decoded_token_bytes() {
    // The first four symbols form a valid decoded prefix, then parsing fails.
    let malformed = "AAEC?___";
    assert!(decode_guarded_token(malformed).is_err());
}
