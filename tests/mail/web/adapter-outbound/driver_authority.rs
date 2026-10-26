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
//   - Included as private driver tests from the root tests directory.
// - Defaults:
//   - No live browser activity or provider data.
//

//! Tests for private, static CDP authority validation.

use super::safe_cdp_notification_method;
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

#[test]
fn transport_rejects_unsafe_cdps_parameter_shapes_in_every_authorized_method() {
    let session = Some("session-a");
    let accepted = [
        (None, "Browser.getVersion", json!({})),
        (None, "Browser.close", json!({})),
        (None, "Target.getTargets", json!({})),
        (
            None,
            "Target.attachToTarget",
            json!({"targetId":"page-1","flatten":true}),
        ),
        (
            None,
            "Target.detachFromTarget",
            json!({"sessionId":"session-a"}),
        ),
        (
            session,
            "DOM.getDocument",
            json!({"depth":0i32,"pierce":false}),
        ),
        (
            session,
            "Accessibility.queryAXTree",
            json!({"nodeId":1u64,"role":"search"}),
        ),
        (
            session,
            "Network.enable",
            json!({
                "maxPostDataSize":0u64,"maxResourceBufferSize":262_144u64,
                "maxTotalBufferSize":1_048_576u64
            }),
        ),
        (session, "Network.disable", json!({})),
        (
            session,
            "Network.getResponseBody",
            json!({"requestId":"12.37"}),
        ),
        (session, "Page.reload", json!({})),
        (session, "Page.reload", json!({"ignoreCache":false})),
    ];
    for (scope, method, params) in accepted {
        assert!(allowed_mail_cdp_request(scope, method, &params));
    }
    let refused = [
        (None, "Browser.getVersion", json!({"danger":"secret"})),
        (
            None,
            "Target.attachToTarget",
            json!({"targetId":"page-1","flatten":false}),
        ),
        (
            None,
            "Target.detachFromTarget",
            json!({"sessionId":"bad/session"}),
        ),
        (
            session,
            "DOM.getDocument",
            json!({"depth":-1i32,"pierce":true}),
        ),
        (
            session,
            "Accessibility.queryAXTree",
            json!({"nodeId":0u64,"role":"search"}),
        ),
        (
            session,
            "Accessibility.queryAXTree",
            json!({"nodeId":1u64,"role":"button"}),
        ),
        (
            session,
            "Network.enable",
            json!({
                "maxPostDataSize":100u64,"maxResourceBufferSize":262_144u64,
                "maxTotalBufferSize":1_048_576u64
            }),
        ),
        (
            session,
            "Network.enable",
            json!({
                "maxPostDataSize":0u64,"maxResourceBufferSize":16_777_217u64,
                "maxTotalBufferSize":16_777_217u64
            }),
        ),
        (session, "Network.disable", json!({"requestId":"123"})),
        (session, "Network.getResponseBody", json!({"requestId":""})),
        (session, "Page.reload", json!({"ignoreCache":true})),
        (Some(""), "Page.reload", json!({})),
    ];
    for (scope, method, params) in refused {
        assert!(!allowed_mail_cdp_request(scope, method, &params));
    }
}

#[test]
fn response_body_requests_refuse_invisible_cdp_request_ids() {
    for id in ["1.4", "req-1", "opaque_+~="] {
        assert!(allowed_mail_cdp_request(
            Some("session-a"),
            "Network.getResponseBody",
            &json!({"requestId":id})
        ));
    }
    for invalid in [
        "",
        "with space",
        "with\tcontrol",
        "with\nnewline",
        "unicode\u{200b}hidden",
        "soft\u{ad}hyphen",
        "dotted\u{e0020}tag",
        "nonascii-\u{b5}",
        &"x".repeat(513),
    ] {
        assert!(!allowed_mail_cdp_request(
            Some("session-a"),
            "Network.getResponseBody",
            &json!({"requestId":invalid})
        ));
    }
}

#[test]
fn audited_click_scripts_block_common_auth_inputs_before_any_activation() {
    for script in [
        NextPageActivation::expression(),
        MailboxSortOrder::open_expression(),
        MailboxSortOrder::close_expression(),
    ] {
        let password = script
            .find("input[type=\"password\"]")
            .expect("static UI click must guard password challenge input");
        let one_time = script
            .find("input[autocomplete=\"one-time-code\"]")
            .expect("static UI click must guard one-time-code input");
        let activation = script
            .find(".click();")
            .expect("audited page/navigation action exists");
        let live_origin = script
            .find("location.origin!=='https://mail.proton.me'")
            .expect("UI click must require the exact live Mail origin");
        assert!(live_origin < activation);
        assert!(password < activation);
        assert!(one_time < activation);
        assert!(!script.contains(".value"));
        assert!(allowed_mail_runtime_expression(script));
    }
}

#[test]
fn unsolicited_method_shape_has_one_nonempty_domain_and_event() {
    for accepted in [
        "Network.requestWillBeSent",
        "Network.responseReceived",
        "Network.requestWillBeSentExtraInfo",
        "Target.detachedFromTarget",
    ] {
        assert!(safe_cdp_notification_method(accepted));
    }
    for rejected in [
        "",
        "Network",
        ".loadingFinished",
        "Network.",
        "Network..loadingFinished",
        "Network/responseReceived",
        "Network. responseReceived",
        "Network.response_received",
        "Network.responseReceived\u{200b}",
    ] {
        assert!(!safe_cdp_notification_method(rejected));
    }
    assert!(!safe_cdp_notification_method(&"x".repeat(129)));
}

#[test]
fn visible_row_projection_must_not_follow_labels_outside_the_row() {
    let script = MailboxPageSnapshot::expression();
    assert!(script.contains("row.querySelectorAll('[id]')"));
    assert!(script.contains("node.id===labelled"));
    assert!(script.contains("subject:localHeading?"));
    assert!(allowed_mail_runtime_expression(script));
}

#[test]
fn mailbox_list_projection_must_refuse_ambiguous_loaded_roots() {
    let list = MailboxListEvidence::expression();
    assert!(list.contains("loadedNodes.length>1"));
    assert!(list.contains("loadingNodes.length>1"));
    let rows = MailboxPageSnapshot::expression();
    assert!(rows.contains("roots.length!==1"));
    assert!(allowed_mail_runtime_expression(list));
    assert!(allowed_mail_runtime_expression(rows));
}

#[test]
fn mailbox_list_projection_must_refuse_ambiguous_pagination_controls() {
    let script = MailboxListEvidence::expression();
    assert!(script.contains("nextNodes.length>1"));
    assert!(script.contains("currentNodes.length>1"));
    assert!(allowed_mail_runtime_expression(script));
}

#[test]
fn mailbox_read_scripts_reject_authentication_challenge_inputs() {
    for script in [
        MailboxListEvidence::expression(),
        MailboxPageSnapshot::expression(),
    ] {
        let password = script
            .find("input[type=\"password\"]")
            .expect("read-only projection must reject password inputs");
        let otp = script
            .find("input[autocomplete=\"one-time-code\"]")
            .expect("read-only projection must reject one-time codes");
        let projection = script
            .find("document.querySelectorAll(")
            .expect("read expression inspects DOM structure");
        assert!(password < projection && otp < projection);
        assert!(!script.contains(".value"));
        assert!(allowed_mail_runtime_expression(script));
    }
}

#[test]
fn audited_clicks_must_refuse_nonvisible_controls() {
    for script in [
        NextPageActivation::expression(),
        MailboxSortOrder::open_expression(),
        MailboxSortOrder::close_expression(),
    ] {
        let geometry = script
            .find("getClientRects().length===0")
            .expect("click target must occupy a visible layout rect");
        let aria = script
            .find("closest('[aria-hidden=\"true\"]')")
            .expect("click target cannot be inside an AX-hidden subtree");
        let click = script.find(".click();").expect("audited click action");
        assert!(geometry < click && aria < click);
        assert!(allowed_mail_runtime_expression(script));
    }
}

#[test]
fn mailbox_list_next_page_evidence_requires_an_actionable_button() {
    let script = MailboxListEvidence::expression();
    assert!(script.contains("next instanceof HTMLButtonElement"));
    assert!(script.contains("next.getClientRects().length===0"));
    assert!(script.contains("next.closest('[aria-hidden=\"true\"]')"));
    assert!(allowed_mail_runtime_expression(script));
}

#[test]
fn click_and_next_evidence_refuse_css_visibility_hidden() {
    for script in [
        MailboxListEvidence::expression(),
        NextPageActivation::expression(),
        MailboxSortOrder::open_expression(),
        MailboxSortOrder::close_expression(),
    ] {
        assert!(script.contains("getComputedStyle("));
        assert!(script.contains(".visibility!=='visible'"));
        assert!(allowed_mail_runtime_expression(script));
    }
}

#[test]
fn visible_rows_require_unique_local_heading_and_sender_nodes() {
    let script = MailboxPageSnapshot::expression();
    assert!(script.contains("headingNodes.length!==1"));
    assert!(script.contains("senders.length!==1"));
    assert!(script.contains("row.querySelectorAll('[id]')"));
    assert!(!script.contains("document.getElementById"));
    assert!(allowed_mail_runtime_expression(script));
}

#[test]
fn visible_row_projection_does_not_mutate_browser_global_state() {
    let script = MailboxPageSnapshot::expression();
    assert!(script.contains("const rows=[...root.querySelectorAll("));
    assert!(!script.contains(";rows=["));
    assert!(allowed_mail_runtime_expression(script));
}
