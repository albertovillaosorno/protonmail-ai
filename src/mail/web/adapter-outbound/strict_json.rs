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
//   - Erase sensitive serialization buffers before replacing allocations.
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
use core::mem::take;
use core::ops::Deref;
use std::io::{self, Write};

use serde::de::{Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use zeroize::{Zeroize as _, Zeroizing};

// Zeroizing<Vec<u8>> erases only the *current* allocation on drop. A
// normal Vec growth releases its former allocation without wiping it first.
// Serialize private JSON through this writer, which copies into fresh guarded
// storage and destroys the previous allocation before accepting more bytes.
#[expect(clippy::redundant_pub_crate, reason = "private serialization guard")]
pub(crate) struct SensitiveJsonWriteBuffer {
    bytes: Zeroizing<Vec<u8>>,
}

impl SensitiveJsonWriteBuffer {
    pub(crate) fn new() -> Self {
        Self {
            bytes: Zeroizing::new(Vec::new()),
        }
    }

    // Reserve for a trailing CDP marker or AEAD tag before either can trigger
    // ordinary Vec growth. All capacity replacements go through this path.
    // jig-ignore-next-line: canonical checked capacity helper signature.
    pub(crate) fn reserve_additional(&mut self, additional: usize) -> io::Result<()> {
        let needed = self
            .bytes
            .len()
            .checked_add(additional)
            .ok_or_else(|| io::Error::other("sensitive buffer size overflow"))?;
        if needed > self.bytes.capacity() {
            let capacity = needed.checked_next_power_of_two().unwrap_or(needed);
            let mut replacement = Zeroizing::new(Vec::new());
            replacement
                .try_reserve_exact(capacity)
                // jig-ignore-next-line: canonical redacted allocation error.
                .map_err(|_error| io::Error::other("sensitive buffer allocation failed"))?;
            replacement.extend_from_slice(&self.bytes);
            self.bytes = replacement;
        }
        Ok(())
    }

    pub(crate) fn append(&mut self, next: &[u8]) -> io::Result<()> {
        self.reserve_additional(next.len())?;
        // Capacity is now sufficient, so extend cannot release old bytes.
        self.bytes.extend_from_slice(next);
        Ok(())
    }

    pub(crate) fn into_guarded(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }

    #[cfg(test)]
    fn capacity(&self) -> usize {
        self.bytes.capacity()
    }
}

#[expect(
    clippy::missing_trait_methods,
    reason = "Write defaults delegate to scrub-on-grow write"
)]
impl Write for SensitiveJsonWriteBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.append(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// This ordinary-Value decoder is test-only. Production read projectors must
// hold the full untrusted provider JSON in SensitiveValue until it is dropped.
#[cfg(test)]
fn from_str(input: &str) -> Result<Value, serde_json::Error> {
    let mut value = serde_json::from_str::<StrictValue>(input)?;
    Ok(take(&mut value.0))
}

// No ordinary full-response decoder is available in production. Unit tests
// retain this helper to compare strict parsing against Serde Value semantics.
#[cfg(test)]
fn from_slice(input: &[u8]) -> Result<Value, serde_json::Error> {
    let mut value = serde_json::from_slice::<StrictValue>(input)?;
    Ok(take(&mut value.0))
}

// AES cursor decoding uses the same strict duplicate-key rejection, but its
// parsed Value contains copies of decrypted account and watermark strings.
// Destroy those owned strings and all object keys before releasing the heap.
// jig-ignore-next-line: rustfmt requires one-line private lint attribute.
#[expect(clippy::redundant_pub_crate, reason = "cursor-only private JSON guard")]
pub(crate) struct SensitiveValue(Value);

// jig-ignore-next-line: rustfmt requires one-line private lint attribute.
#[expect(clippy::redundant_pub_crate, reason = "cursor-only private JSON guard")]
// jig-ignore-next-line: rustfmt keeps the private cursor decode signature.
pub(crate) fn from_sensitive_slice(input: &[u8]) -> Result<SensitiveValue, serde_json::Error> {
    let mut decoded = serde_json::from_slice::<StrictValue>(input)?;
    Ok(SensitiveValue(take(&mut decoded.0)))
}

impl SensitiveValue {
    // Guard a newly assembled browser command before serialization.
    pub(crate) const fn from_owned(value: Value) -> Self {
        Self(value)
    }

    // Transfer an owned child without copying private strings or losing
    // zeroizing custody between the CDP envelope and its projected result.
    pub(crate) fn take_object_field(&mut self, field: &str) -> Option<Self> {
        let child = self.0.as_object_mut()?.get_mut(field)?;
        Some(Self(take(child)))
    }
}

impl Deref for SensitiveValue {
    type Target = Value;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[expect(
    clippy::missing_trait_methods,
    reason = "Drop has no stable additional methods to implement"
)]
impl Drop for SensitiveValue {
    fn drop(&mut self) {
        zeroize_json_strings(&mut self.0);
    }
}

fn zeroize_json_strings(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => {
            for item in items {
                zeroize_json_strings(item);
            }
        }
        Value::Object(object) => {
            // Draining permits zeroizing keys too. On drop nobody may
            // retain a reference into the parsed JSON tree.
            for (mut key, mut item) in take(object) {
                key.zeroize();
                zeroize_json_strings(&mut item);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

// Retain map keys in scrub-on-drop storage while their value is decoded.
// A malformed value otherwise causes Serde's combined next_entry helper to
// release its already parsed key as an ordinary unzeroized String.
fn guarded_json_key(key: String) -> Zeroizing<String> {
    Zeroizing::new(key)
}

// Every partially decoded tree must scrub owned strings if Serde aborts
// before the successful outer cursor can create its SensitiveValue guard.
struct StrictValue(Value);

#[expect(
    clippy::missing_trait_methods,
    reason = "Drop is the only explicit destructor contract"
)]
impl Drop for StrictValue {
    fn drop(&mut self) {
        zeroize_json_strings(&mut self.0);
    }
}

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
                let mut values = StrictValue(Value::Array(Vec::new()));
                while let Some(mut value) = seq.next_element::<StrictValue>()? {
                    if let Value::Array(items) = &mut values.0 {
                        items.push(take(&mut value.0));
                    }
                }
                Ok(values)
            }

            // jig-ignore-next-line: Serde visitor method signature.
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut object = StrictValue(Value::Object(Map::new()));
                while let Some(key) = map.next_key::<String>()? {
                    let mut key = guarded_json_key(key);
                    let mut value = map.next_value::<StrictValue>()?;
                    if let Value::Object(entries) = &mut object.0 {
                        if entries.contains_key(key.as_str()) {
                            return Err(A::Error::custom("duplicate key"));
                        }
                        entries.insert(take(&mut *key), take(&mut value.0));
                    }
                }
                Ok(object)
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

#[cfg(test)]
#[path = "../../../../tests/mail/web/adapter-outbound/strict_json.rs"]
mod strict_json_tests;
