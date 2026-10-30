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
//   - Synthetic strict-JSON parser parity and duplicate-key regressions.
// - Must-Not:
//   - Contact a provider or consume real mailbox content.
// - Allows:
//   - Compare accepted JSON with Serde Value and reject nested duplicates.
// - Split-When:
//   - Additional parser formats need independent tests.
// - Merge-When:
//   - The shared JSON visitor becomes an external crate.
// - Summary:
//   - Proves duplicate-key refusal and nonconflicting value preservation.
// - Description:
//   - Exercises scalar, array, nested-map, and numeric inputs with no network.
// - Usage:
//   - Runs with mail_web_adapter unit tests.
// - Defaults:
//   - All test values are synthetic.
//

//! Offline typed JSON decoding coverage.

use super::{from_slice, from_str};
use serde_json::{Value, json};

#[test]
fn strict_decoder_preserves_valid_value_types() {
    for value in [
        json!(null),
        json!(true),
        json!(-12i64),
        json!(123u64),
        json!(3.5f64),
        json!("unicode \u{2713}"),
        json!([null, 0i32, false, "a"]),
        json!({"a":[{"nested":1i32},[true,7i32]],"b":2.25f64}),
    ] {
        let serialized = value.to_string();
        assert_eq!(
            from_str(&serialized).expect("parse synthetic JSON text"),
            value
        );
        let serialized_bytes = serialized.as_bytes();
        let byte_value = from_slice(serialized_bytes).expect("parse bytes");
        assert_eq!(byte_value, value);
    }
}

#[test]
fn strict_decoder_rejects_duplicate_keys_at_every_depth() {
    for body in [
        r#"{"Code":2500,"Code":1000}"#,
        r#"{"Message":{"ID":"wrong","ID":"correct"}}"#,
        r#"{"Rows":[{"ID":"wrong","ID":"correct"}]}"#,
        r#"{"x":1,"y":2,"x":3}"#,
        r#"{"obj":{"nested":{"key":1,"key":2}}}"#,
    ] {
        assert!(from_str(body).is_err());
        assert!(from_slice(body.as_bytes()).is_err());
    }
}

#[test]
fn strict_decoder_distinguishes_unicode_escaped_equivalent_keys() {
    let duplicate = r#"{"ID":1,"\u0049D":2}"#;
    assert!(from_str(duplicate).is_err());
    let distinct = r#"{"ID":1,"id":2}"#;
    assert_eq!(
        from_str(distinct).expect("distinct keys are safe"),
        json!({"ID":1i32,"id":2i32})
    );
    assert!(from_slice(b"[").is_err());
    assert_eq!(from_str("null").expect("parse null"), Value::Null);
}
