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
//   - Unit tests for the private, read-only Chromium CDP authority allowlist.
// - Must-Not:
//   - Issue real browser commands or access a Mail account.
// - Allows:
//   - Assert approved method scopes and known static UI expressions.
// - Split-When:
//   - A distinct browser command capability adds its own evidence contract.
// - Merge-When:
//   - CDP authority rules become part of a broader driver policy suite.
// - Summary:
//   - Proves private CDP command and expression authorization fails closed.
// - Description:
//   - Tests scope-aware methods and rejects arbitrary browser script strings.
// - Usage:
// jig-ignore-next-line: canonical rustfmt line.
//   - Included by the driver module for in-crate tests under the root tests tree.
// - Defaults:
//   - No live browser activity or provider data.
//

//! Tests for private, static CDP authority validation.

use super::{LOCATION_EXPRESSION, MailboxSortOrder, NextPageActivation};
use super::{MailboxListEvidence, MailboxModeEvidence, MailboxPageSnapshot};
// jig-ignore-next-line: canonical rustfmt line.
use super::{allowed_mail_cdp_method, allowed_mail_cdp_request, allowed_mail_runtime_expression};
use serde_json::json;

#[test]
fn only_audited_cdp_methods_are_accepted_in_their_session_scope() {
    for command in [
        "Browser.getVersion",
        "Browser.close",
        "Target.getTargets",
        "Target.attachToTarget",
        "Target.detachFromTarget",
    ] {
        assert!(allowed_mail_cdp_method(None, command));
        assert!(!allowed_mail_cdp_method(Some("session-a"), command));
    }
    for command in [
        "Runtime.evaluate",
        "DOM.getDocument",
        "Accessibility.queryAXTree",
        "Network.enable",
        "Network.disable",
        "Network.getResponseBody",
        "Page.reload",
    ] {
        assert!(allowed_mail_cdp_method(Some("session-a"), command));
        assert!(!allowed_mail_cdp_method(None, command));
    }
    for denied in [
        "Runtime.callFunctionOn",
        "Runtime.addBinding",
        "DOM.setAttributeValue",
        "DOM.setOuterHTML",
        "Input.dispatchMouseEvent",
        "Input.insertText",
        "Network.setCookie",
        "Network.setCookies",
        "Storage.clearDataForOrigin",
        "Page.navigate",
        "Page.addScriptToEvaluateOnNewDocument",
        "Fetch.fulfillRequest",
    ] {
        assert!(!allowed_mail_cdp_method(None, denied));
        assert!(!allowed_mail_cdp_method(Some("session-a"), denied));
    }
}

#[test]
fn only_static_audited_runtime_expressions_are_accepted() {
    for expression in [
        LOCATION_EXPRESSION,
        MailboxModeEvidence::expression(),
        MailboxListEvidence::expression(),
        MailboxPageSnapshot::expression(),
        MailboxSortOrder::open_expression(),
        MailboxSortOrder::expression(),
        MailboxSortOrder::close_expression(),
        MailboxSortOrder::closed_expression(),
        NextPageActivation::expression(),
    ] {
        assert!(allowed_mail_runtime_expression(expression));
    }
    for denied in [
        "",
        "document.cookie",
        "fetch('/api/mail/v4/messages')",
        "document.querySelector('button').click()",
        "window.location.href='https://example.test'",
    ] {
        assert!(!allowed_mail_runtime_expression(denied));
    }
}

#[test]
fn runtime_evaluation_must_prove_static_script_at_final_pipe_boundary() {
    let location = LOCATION_EXPRESSION;
    assert!(allowed_mail_cdp_request(
        Some("session-a"),
        "Runtime.evaluate",
        &json!({"expression":location,"returnByValue":true})
    ));
    for params in [
        json!({"expression":"document.cookie","returnByValue":true}),
        json!({"expression":location,"returnByValue":false}),
        json!({"expression":location,"returnByValue":true,"awaitPromise":true}),
        json!({"expression":location}),
        json!({"returnByValue":true}),
        json!({"expression":null,"returnByValue":true}),
        json!([]),
    ] {
        assert!(!allowed_mail_cdp_request(
            Some("session-a"),
            "Runtime.evaluate",
            &params
        ));
    }
    assert!(!allowed_mail_cdp_request(
        None,
        "Runtime.evaluate",
        &json!({"expression":location,"returnByValue":true})
    ));
}
