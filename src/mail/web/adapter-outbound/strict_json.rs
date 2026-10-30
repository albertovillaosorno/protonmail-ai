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
//   - Reject ambiguous duplicate keys in provider and browser JSON objects.
// - Must-Not:
//   - Accept first-wins/last-wins conflicts or retain provider content.
// - Allows:
//   - Decode bounded JSON into the existing serde_json::Value projectors.
// - Split-When:
//   - JSON schema validation becomes independent of the read adapter.
// - Merge-When:
//   - Every untrusted browser JSON boundary uses a shared strict decoder.
// - Summary:
//   - Rejects duplicate keys recursively without changing projected values.
// - Description:
//   - A Serde visitor builds Values but errors on any repeated map key.
// - Usage:
//   - Call after the existing maximum input-byte check.
// - Defaults:
//   - No provider data is logged on parse failure.
//

//! Strict JSON decoding for untrusted provider and browser responses.

use core::fmt;

use serde::de::{Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};

#[expect(clippy::redundant_pub_crate, reason = "shared private module helper")]
pub(crate) fn from_str(input: &str) -> Result<Value, serde_json::Error> {
    serde_json::from_str::<StrictValue>(input).map(|value| value.0)
}

#[expect(clippy::redundant_pub_crate, reason = "shared private module helper")]
pub(crate) fn from_slice(input: &[u8]) -> Result<Value, serde_json::Error> {
    serde_json::from_slice::<StrictValue>(input).map(|value| value.0)
}

struct StrictValue(Value);

#[expect(
    clippy::inline_trait_bounds,
    clippy::missing_trait_methods,
    reason = "Serde Deserialize intentionally uses the default in-place method"
)]
impl<'de> Deserialize<'de> for StrictValue {
    // jig-ignore-next-line: Serde visitor method signature.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;

        #[expect(
            clippy::inline_trait_bounds,
            clippy::missing_trait_methods,
            clippy::renamed_function_params,
            reason = "JSON uses only relevant Serde Visitor callbacks"
        )]
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;

            // jig-ignore-next-line: Serde visitor method signature.
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON without duplicate object keys")
            }

            // jig-ignore-next-line: Serde visitor method signature.
            fn visit_bool<E: DeError>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(value)))
            }

            // jig-ignore-next-line: Serde visitor method signature.
            fn visit_i64<E: DeError>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(Number::from(value))))
            }

            // jig-ignore-next-line: Serde visitor method signature.
            fn visit_u64<E: DeError>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(Number::from(value))))
            }

            // jig-ignore-next-line: Serde visitor method signature.
            fn visit_f64<E: DeError>(self, value: f64) -> Result<Self::Value, E> {
                let number =
                    // jig-ignore-next-line: Serde visitor method signature.
                    Number::from_f64(value).ok_or_else(|| E::custom("non-finite JSON number"))?;
                Ok(StrictValue(Value::Number(number)))
            }

            // jig-ignore-next-line: Serde visitor method signature.
            fn visit_str<E: DeError>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(String::from(value))))
            }

            // jig-ignore-next-line: Serde visitor method signature.
            fn visit_string<E: DeError>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value)))
            }

            fn visit_unit<E: DeError>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_none<E: DeError>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_some<D: Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                StrictValue::deserialize(deserializer)
            }

            // jig-ignore-next-line: Serde visitor method signature.
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(StrictValue(Value::Array(values)))
            }

            // jig-ignore-next-line: Serde visitor method signature.
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut object = Map::new();
                // jig-ignore-next-line: Serde visitor method signature.
                while let Some((key, value)) = map.next_entry::<String, StrictValue>()? {
                    if object.contains_key(&key) {
                        return Err(A::Error::custom("duplicate key"));
                    }
                    object.insert(key, value.0);
                }
                Ok(StrictValue(Value::Object(object)))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

#[cfg(test)]
#[path = "../../../../tests/mail/web/adapter-outbound/strict_json.rs"]
mod strict_json_tests;
