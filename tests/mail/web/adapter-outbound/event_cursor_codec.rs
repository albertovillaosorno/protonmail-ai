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
//   - Exercise private event cursor authentication without provider state.
// - Split-When:
//   - The codec implementations require distinct cryptographic contracts.
// - Merge-When:
//   - Cursor cryptography gains an independent shared implementation.
// - Summary:
//   - Ensures event cursor decryption is guarded and rejects tampering.
// - Description:
//   - A synthetic AES-GCM payload exercises good and corrupt authentication.
// - Usage:
//   - Included from the event cursor codec source module.
// - Defaults:
//   - No account, browser, or external network access.
//

//! Checks guarded decryption for event continuation cursors.

use super::frame_guarded_cursor_body;
use super::{CURSOR_AAD_PREFIX, cursor_aad};
use super::{CURSOR_KEY_BYTES, CURSOR_NONCE_BYTES, decrypt_into_guarded};
use super::{CURSOR_VERSION, MAX_ENCODED_CURSOR_BYTES};
use super::{decode_guarded_token, encode_guarded_token, encrypt_into_guarded};
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::Zeroizing;

const VALID_GENERATION: &str = "0123456789abcdef0123456789abcdef";

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
                msg: b"private synthetic watermark",
                aad,
            },
        )
        .expect("seal synthetic cursor");

    let opened: Zeroizing<Vec<u8>> =
        // jig-ignore-next-line: canonical guarded decrypt assertion.
        decrypt_into_guarded(&cipher, &nonce, aad, &sealed).expect("open authentic cursor");
    assert_eq!(opened.as_slice(), b"private synthetic watermark");

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
    let synthetic_state = b"private synthetic event state";
    let mut plaintext = Zeroizing::new(synthetic_state.to_vec());

    encrypt_into_guarded(&cipher, &nonce, aad, &mut plaintext)
        .expect("seal without releasing plaintext");
    let opened: Zeroizing<Vec<u8>> =
        // jig-ignore-next-line: canonical guarded decrypt assertion.
        decrypt_into_guarded(&cipher, &nonce, aad, &plaintext).expect("recover synthetic cursor");
    assert_eq!(opened.as_slice(), b"private synthetic event state");
}

#[test]
fn sealed_cursor_token_body_is_scrubbed_on_drop() {
    let nonce = [7u8; CURSOR_NONCE_BYTES];
    let ciphertext = b"synthetic sealed continuation bytes";
    let framed = frame_guarded_cursor_body(&nonce, ciphertext);
    let body: Zeroizing<Vec<u8>> = framed.expect("guard cursor bytes");
    assert_eq!(&body[..CURSOR_NONCE_BYTES], &nonce);
    assert_eq!(&body[CURSOR_NONCE_BYTES..], ciphertext);
    let encoded = encode_guarded_token(VALID_GENERATION, &body);
    let token = encoded.expect("encode guarded replayable token");
    let encoded = token.rsplit_once('.').expect("framed cursor").1;
    let decoded = decode_guarded_token(encoded).expect("decode test cursor");
    assert_eq!(*decoded, *body);
}

#[test]
fn opaque_cursor_token_uses_guarded_storage_without_extra_base64_copy() {
    let opaque_bytes = [0u8, 1, 2, 253, 254, 255];
    let encoded = encode_guarded_token(VALID_GENERATION, &opaque_bytes);
    let guarded: Zeroizing<String> = encoded.expect("synthetic cursor token");
    let expected = format!(
        "{CURSOR_VERSION}.{VALID_GENERATION}.{}",
        URL_SAFE_NO_PAD.encode(opaque_bytes)
    );
    assert_eq!(guarded.as_str(), expected);
    assert!(guarded.capacity() >= guarded.len());
}

#[test]
fn cursor_authentication_aad_is_fixed_size_and_generation_scoped() {
    let aad = cursor_aad(VALID_GENERATION).expect("canonical generation");
    assert_eq!(aad.len(), CURSOR_AAD_PREFIX.len() + VALID_GENERATION.len());
    assert!(aad.starts_with(CURSOR_AAD_PREFIX));
    assert!(aad.ends_with(VALID_GENERATION.as_bytes()));
    assert!(cursor_aad("synthetic-invalid-tag").is_err());
}

#[test]
fn cursor_encoder_refuses_malformed_generation_tag_before_framing() {
    for bad in [
        "",
        "0123456789abcdef",
        "0123456789abcdef0123456789abc.",
        "0123456789abcdef0123456789abcg",
        "0123456789abcdef0123456789abcdef0",
    ] {
        assert!(encode_guarded_token(bad, b"synthetic sealed text").is_err());
    }
}

#[test]
fn oversized_cursor_token_is_refused_before_encoding() {
    let oversized = vec![0xadu8; MAX_ENCODED_CURSOR_BYTES];
    assert!(encode_guarded_token(VALID_GENERATION, &oversized).is_err());
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
