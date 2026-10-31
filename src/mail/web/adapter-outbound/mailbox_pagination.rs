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
    // Check live origin inside the same JS task as the navigation click.
    "if(location.origin!=='https://mail.proton.me'){return null;}",
    // Refuse common authentication challenge controls immediately before click.
    "if(document.querySelector('input[type=\"password\"],",
    "input[autocomplete=\"one-time-code\"]')){return null;}",
    "if(document.querySelector('[role~=\"dialog\" i],",
    "[role~=\"alertdialog\" i],dialog[open],",
    "[aria-modal=\"true\" i]')){return null;}",
    "const visibleTree=(node)=>{let current=node;",
    "for(let depth=0;depth<64;depth++){",
    "if(!current){return true;}",
    "const style=getComputedStyle(current);",
    "if(!style||style.visibility!=='visible'||",
    "style.contentVisibility==='hidden'||",
    // Rectangles remain positive for fully clipped or filtered-out trees.
    "(style.clipPath&&style.clipPath!=='none')||",
    "(style.filter&&style.filter!=='none')||",
    "style.pointerEvents==='none'||",
    "!(Number(style.opacity)>0)){return false;}",
    "current=current.parentElement;}",
    "return false;};",
    // A transform may collapse a control without removing its DOMRects.
    // Programmatic .click() would still fire on that non-visible button.
    "const hasArea=(node)=>[...node.getClientRects()].some(",
    "(rect)=>rect.width>0&&rect.height>0);",
    // Programmatic click bypasses pointer hit-testing under overlays.
    "const hitTest=(node)=>[...node.getClientRects()].some((rect)=>{",
    "if(!(rect.width>0&&rect.height>0)){return false;}",
    "const x=rect.left+rect.width/2,y=rect.top+rect.height/2;",
    "if(!Number.isFinite(x)||!Number.isFinite(y)){return false;}",
    "const hit=document.elementFromPoint(x,y);",
    "return !!hit&&(hit===node||node.contains(hit));});",
    "const q='[data-testid=\"pagination-row:go-to-next-page\"]';",
    "const nodes=[...document.querySelectorAll(q)];",
    "if(nodes.length!==1){return {present:nodes.length===1,",
    "disabled:null,clicked:false};}",
    "const next=nodes[0];",
    // A submit button can trigger a form mutation instead of pagination.
    // Even an explicit type=button must not be owned by a form.
    "if(!(next instanceof HTMLButtonElement)||",
    "next.type!=='button'||next.form!==null){",
    "return {present:true,disabled:null,clicked:false};}",
    "if(next.matches(':disabled')||next.disabled||",
    "next.getAttribute('aria-disabled')?.toLowerCase()==='true'){",
    "return {present:true,disabled:true,clicked:false};}",
    "if(next.getClientRects().length===0||",
    "!hasArea(next)||!hitTest(next)||",
    "getComputedStyle(next).visibility!=='visible'||",
    "getComputedStyle(next).pointerEvents==='none'||",
    "getComputedStyle(next).opacity==='0'||",
    "!visibleTree(next)||",
    // jig-ignore-next-line: indivisible audited ARIA state check.
    "next.closest('[aria-hidden=\"true\" i],[inert],[aria-disabled=\"true\" i]')){",
    "return {present:true,disabled:null,clicked:false};}",
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
        if value.as_object().is_none_or(|fields| fields.len() != 3) {
            return Err(());
        }
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
