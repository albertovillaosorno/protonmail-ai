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
//   - Bounded semantic activation of Proton Mail's visible next-page control.
// - Must-Not:
//   - Read mailbox content, use localized text, or target mutation controls.
// - Allows:
//   - Click exactly one enabled provider-owned next-page button.
// - Split-When:
//   - Other navigation controls require independent transition semantics.
// - Merge-When:
//   - Read workflow navigation owns this single pagination action directly.
// - Summary:
//   - Activates only the verified locale-independent Mail pagination control.
// - Description:
//   - Reduces DOM state to present/disabled/clicked booleans before returning.
// - Usage:
//   - Message-page reads use it only after stable page/mode evidence.
// - Defaults:
//   - Missing, duplicated, non-button, or disabled controls fail closed.
//

//! Conservative next-page activation for read-only Mail navigation.

use serde_json::Value;

const NEXT_PAGE_CLICK_EXPRESSION: &str = concat!(
    "(() => {",
    "const q='[data-testid=\"pagination-row:go-to-next-page\"]';",
    "const nodes=[...document.querySelectorAll(q)];",
    "if(nodes.length!==1){return {present:nodes.length===1,",
    "disabled:null,clicked:false};}",
    "const next=nodes[0];",
    "if(!(next instanceof HTMLButtonElement)){",
    "return {present:true,disabled:null,clicked:false};}",
    "if(next.disabled){return {present:true,disabled:true,clicked:false};}",
    "next.click();",
    "return {present:true,disabled:false,clicked:true};",
    "})()"
);

/// Content-free result of attempting the verified next-page control.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NextPageActivation {
    /// Exactly one enabled button was present and clicked.
    Clicked,
    /// The provider control no longer matched the pre-click evidence.
    Changed,
}

impl NextPageActivation {
    pub(crate) const fn expression() -> &'static str {
        NEXT_PAGE_CLICK_EXPRESSION
    }

    pub(crate) fn from_value(value: &Value) -> Result<Self, ()> {
        let present = bool_field(value, "present")?;
        let clicked = bool_field(value, "clicked")?;
        let disabled = optional_bool(value, "disabled")?;
        if present && disabled == Some(false) && clicked {
            return Ok(Self::Clicked);
        }
        if !clicked && (!present && disabled.is_none()) {
            return Ok(Self::Changed);
        }
        if !clicked && present && disabled != Some(false) {
            return Ok(Self::Changed);
        }
        Err(())
    }
}

fn bool_field(value: &Value, key: &str) -> Result<bool, ()> {
    value.get(key).and_then(Value::as_bool).ok_or(())
}

fn optional_bool(value: &Value, key: &str) -> Result<Option<bool>, ()> {
    let field = value.get(key).ok_or(())?;
    if field.is_null() {
        return Ok(None);
    }
    field.as_bool().map(Some).ok_or(())
}
