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
//   - Native Unix CLI byte-to-UTF8 conversion regression coverage.
// - Must-Not:
//   - Accept live credentials, print private argument content, or launch Mail.
// - Allows:
//   - Prove accepted arguments and malformed native input conversion.
// - Split-When:
//   - The native argument parser becomes a shared runtime component.
// - Merge-When:
//   - CLI argument custody joins a broader private parser suite.
// - Summary:
//   - Confirms malformed native CLI bytes fail before secret disclosure.
// - Description:
//   - Synthetic valid and invalid native argument strings are decoded.
// - Usage:
//   - Included from the CLI binary composition root in unit-test builds.
// - Defaults:
//   - No provider account, browser, or network access.
//

//! Native Unix CLI argument conversion regression tests.

use crate::decode_cli_argument;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt as _;

#[test]
fn validates_native_utf8_and_refuses_secret_invalid_bytes() {
    let accepted = OsString::from_vec(b"private-valid-secret".to_vec());
    assert_eq!(
        decode_cli_argument(accepted),
        Ok(String::from("private-valid-secret"))
    );
    let rejected = OsString::from_vec(b"private-invalid-\xff".to_vec());
    assert_eq!(decode_cli_argument(rejected), Err(()));
}
