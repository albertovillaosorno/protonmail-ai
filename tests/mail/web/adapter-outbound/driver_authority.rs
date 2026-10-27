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

use super::BrowserDriverError;
use super::safe_cdp_notification_method;
use super::{LOCATION_EXPRESSION, MailboxSortOrder, NextPageActivation};
use super::{MailboxListEvidence, MailboxModeEvidence, MailboxPageSnapshot};
use crate::MailboxListState;
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

#[test]
fn loaded_list_cannot_be_treated_as_settled_while_loading_root_exists() {
    let script = MailboxListEvidence::expression();
    assert!(script.contains("if(loading&&loaded){return null;}"));
    assert!(allowed_mail_runtime_expression(script));
}

#[test]
fn mailbox_dom_reads_require_mail_origin_within_projection_task() {
    for script in [
        MailboxListEvidence::expression(),
        MailboxPageSnapshot::expression(),
    ] {
        let origin = script
            .find("location.origin!=='https://mail.proton.me'")
            .expect("Mail page origin must be checked inside the DOM read");
        let query = script
            .find("document.querySelector(")
            .expect("browser read queries only an authorized DOM");
        assert!(origin < query);
        assert!(allowed_mail_runtime_expression(script));
    }
}

#[test]
fn all_readonly_mode_and_sort_projections_bind_live_mail_origin() {
    for script in [
        MailboxModeEvidence::expression(),
        MailboxSortOrder::expression(),
        MailboxSortOrder::closed_expression(),
    ] {
        assert!(script.contains("location.origin!=='https://mail.proton.me'"));
        assert!(allowed_mail_runtime_expression(script));
    }
}

#[test]
fn navigation_controls_cannot_be_css_noninteractive_or_transparent() {
    for script in [
        MailboxListEvidence::expression(),
        NextPageActivation::expression(),
        MailboxSortOrder::open_expression(),
        MailboxSortOrder::close_expression(),
    ] {
        assert!(script.contains(".pointerEvents==='none'"));
        assert!(script.contains(".opacity==='0'"));
        assert!(allowed_mail_runtime_expression(script));
    }
}

#[test]
fn sort_menu_closed_evidence_rejects_contradictory_pressed_flags() {
    assert!(MailboxSortOrder::from_value(&json!({"ready": false})).is_ok());
    for invalid in [
        json!({"ready": false, "valid": true}),
        json!({"ready": false, "newest": true}),
        json!({"ready": false, "oldest": false}),
        json!({"ready": false, "largest": true}),
        json!({"ready": false, "smallest": true}),
    ] {
        assert!(MailboxSortOrder::from_value(&invalid).is_err());
    }
}

#[test]
fn row_subject_and_sender_evidence_must_be_visibly_rendered() {
    let script = MailboxPageSnapshot::expression();
    assert!(script.contains("localHeading.getClientRects().length===0"));
    assert!(script.contains("sender.getClientRects().length===0"));
    assert!(script.contains("localHeading.closest('[aria-hidden="));
    assert!(script.contains("sender.closest('[aria-hidden="));
    assert!(script.contains("getComputedStyle(localHeading).visibility"));
    assert!(script.contains("getComputedStyle(sender).visibility"));
    assert!(allowed_mail_runtime_expression(script));
}

#[test]
fn explicit_empty_mailbox_requires_one_visible_placeholder() {
    let script = MailboxListEvidence::expression();
    assert!(script.contains("emptyNodes.length>1"));
    assert!(script.contains("emptyNode.getClientRects().length===0"));
    assert!(script.contains("getComputedStyle(emptyNode).visibility"));
    assert!(script.contains("emptyNode.closest('[aria-hidden="));
    assert!(allowed_mail_runtime_expression(script));
}

#[test]
fn list_row_identifiers_must_come_from_visible_dom_rows() {
    let script = MailboxListEvidence::expression();
    assert!(script.contains("real.some((row)=>"));
    assert!(script.contains("row.getClientRects().length===0"));
    assert!(script.contains("getComputedStyle(row).visibility"));
    assert!(script.contains("row.closest('[aria-hidden="));
    assert!(allowed_mail_runtime_expression(script));
}

#[test]
fn current_page_evidence_must_be_visible_before_page_number_projection() {
    let script = MailboxListEvidence::expression();
    assert!(script.contains("current.getClientRects().length===0"));
    assert!(script.contains("getComputedStyle(current).visibility"));
    assert!(script.contains("current.closest('[aria-hidden="));
    assert!(allowed_mail_runtime_expression(script));
}

#[test]
fn selected_sort_state_cannot_come_from_hidden_menu_options() {
    let script = MailboxSortOrder::expression();
    assert!(script.contains("controls.some((node)=>"));
    assert!(script.contains("node.getClientRects().length===0"));
    assert!(script.contains("getComputedStyle(node).visibility"));
    assert!(script.contains("node.closest('[aria-hidden="));
    assert!(allowed_mail_runtime_expression(script));
}

#[test]
fn sort_menu_toggle_actions_require_unambiguous_current_menu_state() {
    let open = MailboxSortOrder::open_expression();
    assert!(open.contains("groups.every((group)=>group.length===1)"));
    assert!(open.contains("groups.every((group)=>group.length===0)"));
    let close = MailboxSortOrder::close_expression();
    assert!(close.contains("menuNodes.every((group)=>group.length===1)"));
    assert!(allowed_mail_runtime_expression(open));
    assert!(allowed_mail_runtime_expression(close));
}

#[test]
fn read_only_mode_and_sort_projections_refuse_auth_challenge_overlays() {
    for script in [
        MailboxModeEvidence::expression(),
        MailboxSortOrder::expression(),
        MailboxSortOrder::closed_expression(),
    ] {
        assert!(script.contains("input[type=\"password\"]"));
        assert!(script.contains("input[autocomplete=\"one-time-code\"]"));
        assert!(allowed_mail_runtime_expression(script));
    }
}

#[test]
fn active_sort_evidence_refuses_unexpected_control_fields() {
    let valid = json!({
        "ready": true, "valid": true, "newest": true,
        "oldest": false, "largest": false, "smallest": false
    });
    assert_eq!(
        MailboxSortOrder::from_value(&valid),
        Ok(Some(MailboxSortOrder::NewestFirst))
    );
    let mut extra = valid;
    extra["shadowState"] = json!(true);
    assert!(MailboxSortOrder::from_value(&extra).is_err());
}

#[test]
fn mailbox_list_parser_refuses_unexpected_projection_fields() {
    let mut ready = json!({
        "loading": false, "loaded": true, "rowIds": ["row-1"],
        "skeletonCount": 0u64, "emptyMarker": false,
        "nextPresent": false, "nextDisabled": null,
        "currentTestId": null
    });
    assert!(MailboxListEvidence::from_runtime_value(&ready).is_ok());
    ready["unexpected"] = json!(true);
    assert!(MailboxListEvidence::from_runtime_value(&ready).is_err());
    let mut loading = json!({
        "loading": true, "loaded": false, "rowIds": [],
        "skeletonCount": 0u64, "emptyMarker": false,
        "nextPresent": false, "nextDisabled": null,
        "currentTestId": null
    });
    assert!(MailboxListEvidence::from_runtime_value(&loading).is_ok());
    loading["unexpected"] = json!(true);
    assert!(MailboxListEvidence::from_runtime_value(&loading).is_err());
}

#[test]
fn message_mode_evidence_rejects_unrecognized_projection_fields() {
    let valid = json!({"forcedMessageRoute":true,"activeSearch":false});
    assert!(MailboxModeEvidence::from_value(&valid).is_ok());
    let extra = json!({
        "forcedMessageRoute":true,"activeSearch":false,
        "unrecognized":true
    });
    assert!(MailboxModeEvidence::from_value(&extra).is_err());
}

#[test]
fn content_bearing_rows_reject_unrecognized_dom_fields() {
    let before = MailboxListEvidence::from_runtime_value(&json!({
        "loading":false,"loaded":true,"rowIds":["row-1"],
        "skeletonCount":0u64,"emptyMarker":false,"nextPresent":false,
        "nextDisabled":null,"currentTestId":null
    }))
    .expect("synthetic settled list");
    let mut rows = json!([{"id":"row-1","subject":"subject",
        "addresses":"contact@example.test","unread":false}]);
    assert!(
        // jig-ignore-next-line: canonical rustfmt line.
        MailboxPageSnapshot::from_observations(&before, Some(&rows), Some(&rows), &before).is_ok()
    );
    rows[0]["unrecognized"] = json!("secret-bearing-property");
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        MailboxPageSnapshot::from_observations(&before, Some(&rows), Some(&rows), &before),
        Err(BrowserDriverError::MailboxPageIncompatible)
    );
}

#[test]
fn ui_navigation_click_receipts_require_exact_audited_schema() {
    use super::SortMenuActivation;
    let open = json!({"alreadyOpen":false,"clicked":true});
    assert_eq!(
        SortMenuActivation::from_value(&open),
        Ok(SortMenuActivation::Opened)
    );
    // jig-ignore-next-line: canonical rustfmt line.
    let open_with_extra = json!({"alreadyOpen":false,"clicked":true,"sideEffect":true});
    assert_eq!(
        SortMenuActivation::from_value(&open_with_extra),
        Err(BrowserDriverError::MailboxSortIncompatible)
    );
    let next = json!({"present":true,"disabled":false,"clicked":true});
    assert_eq!(
        NextPageActivation::from_value(&next),
        Ok(NextPageActivation::Clicked)
    );
    let next_with_extra = json!({
        "present":true,"disabled":false,"clicked":true,"sideEffect":true
    });
    assert!(NextPageActivation::from_value(&next_with_extra).is_err());
}

#[test]
fn read_only_sort_clicks_must_refuse_disabled_or_modal_controls() {
    for script in [
        MailboxSortOrder::open_expression(),
        MailboxSortOrder::close_expression(),
    ] {
        assert!(script.contains("nodes[0].disabled"));
        assert!(script.contains("[role=\"dialog\"]"));
        assert!(script.contains("[role=\"alertdialog\"]"));
        assert!(allowed_mail_runtime_expression(script));
    }
    let next = NextPageActivation::expression();
    assert!(next.contains("[role=\"dialog\"]"));
    assert!(next.contains("[role=\"alertdialog\"]"));
}

#[test]
fn preopened_sort_menu_requires_visible_option_controls() {
    let script = MailboxSortOrder::open_expression();
    let menu_marker = "const menuOptions=groups.map((group)=>group[0]);";
    assert!(script.contains(menu_marker));
    assert!(script.contains("menuOptions.some((node)=>"));
    assert!(script.contains("node.getClientRects().length===0"));
    assert!(script.contains("getComputedStyle(node).visibility"));
    assert!(script.contains("node.closest('[aria-hidden="));
    assert!(allowed_mail_runtime_expression(script));
}

#[test]
fn visible_row_script_separates_independent_const_declarations() {
    let script = MailboxPageSnapshot::expression();
    assert!(script.contains("item-container\"]';const rows="));
    assert!(!script.contains("item-container\"]',const rows="));
}

#[test]
fn audited_dom_expressions_parse_and_reject_foreign_origins_in_node() {
    use std::process::Command;

    // Node is a developer-only diagnostic; cargo checks remain usable on
    // minimal Rust installations without an installed JavaScript runtime.
    if Command::new("node").arg("--version").output().is_err() {
        eprintln!("Node unavailable: skipping JavaScript syntax check");
        return;
    }
    let expressions = [
        MailboxModeEvidence::expression(),
        MailboxListEvidence::expression(),
        MailboxPageSnapshot::expression(),
        MailboxSortOrder::expression(),
        MailboxSortOrder::open_expression(),
        MailboxSortOrder::close_expression(),
        MailboxSortOrder::closed_expression(),
        NextPageActivation::expression(),
    ];
    let encoded = serde_json::to_string(&expressions).expect("static source");
    let source = format!(
        "const snippets={encoded};\n\
     for(const script of snippets){{new Function('return ('+script+');');}}\n\
         globalThis.location={{origin:'https://lookalike.example.test'}};\n\
         for(const script of snippets){{\n\
           const result=eval(script);\n\
           if(result!==null&&result!==false){{\n\
             throw Error('untrusted origin was not rejected');\n\
           }}\n\
         }}"
    );
    let output = Command::new("node")
        .args(["--eval", &source])
        .output()
        .expect("launch synthetic JS runtime");
    assert!(
        output.status.success(),
        "audited browser scripts failed to compile or deny foreign origins: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn live_javascript_search_mode_rejects_malformed_routes() {
    use std::process::Command;

    if Command::new("node").arg("--version").output().is_err() {
        return;
    }
    let encoded = serde_json::to_string(MailboxModeEvidence::expression())
        .expect("serialize audited mode expression");
    let mut source = format!("const expression={encoded};\n");
    source.push_str(
        "
globalThis.document={querySelector:()=>null};
for(const [path,hash,expected] of [
  ['/u/0/inbox','#keyword=valid',true],
  ['/u/0/unknown','#keyword=valid',false],
  ['/unknown','#keyword=valid',false],
  ['/u/00/inbox','#keyword=valid',null],
  ['/u/0/inbox/nested','#keyword=valid',null],
  ['/inbox/extra','#keyword=valid',null],
  ['/u/0/sent','',true],
  ['/u/0/inbox','',false],
  ['/sent','',true],
  ['/','',null]
]){
  globalThis.location={origin:'https://mail.proton.me',pathname:path,hash};
  const result=eval(expression);
 const actual=result===null?null:result.forcedMessageRoute||result.activeSearch;
  if(actual!==expected){throw Error('invalid mode proof for '+path);}
}
",
    );
    let result = Command::new("node")
        .args(["--eval", &source])
        .output()
        .expect("execute synthetic mode proof");
    assert!(result.status.success(), "synthetic mode proof failed");
}

#[test]
fn pagination_and_sort_clicks_refuse_aria_disabled_controls() {
    let list = MailboxListEvidence::expression();
    let next = NextPageActivation::expression();
    assert!(list.contains("next.getAttribute('aria-disabled')"));
    assert!(next.contains("next.getAttribute('aria-disabled')"));
    for script in [
        MailboxSortOrder::open_expression(),
        MailboxSortOrder::close_expression(),
    ] {
        assert!(script.contains("nodes[0].getAttribute('aria-disabled')"));
        assert!(allowed_mail_runtime_expression(script));
    }
}

#[test]
fn visible_row_javascript_projects_only_rendered_synthetic_content() {
    use std::process::Command;

    if Command::new("node").arg("--version").output().is_err() {
        return;
    }
    let encoded = serde_json::to_string(MailboxPageSnapshot::expression())
        .expect("static row projection source");
    let mut source = format!("const script={encoded};\n");
    source.push_str(
        "
globalThis.location={origin:'https://mail.proton.me'};
let subjectOpacity='1', senderOpacity='1', ancestorOpacity='1';
globalThis.getComputedStyle=(node)=>({visibility:'visible',
 opacity:node===heading?subjectOpacity:node===sender?senderOpacity:
 node===ancestor?ancestorOpacity:'1'});
const heading={id:'heading-id',getAttribute:()=> 'synthetic subject',
  getClientRects:()=>[{}],closest:()=>null};
const sender={getAttribute:()=> 'sender@example.test',
  getClientRects:()=>[{}],closest:()=>null};
const ancestor={parentElement:null};
const row={getAttribute:(key)=>key==='data-element-id'?'row-a':
  key==='aria-labelledby'?'heading-id':null,
  querySelectorAll:(key)=>key==='[id]'?[heading]:[sender],
  parentElement:ancestor,classList:{contains:()=>true}};
heading.parentElement=row;sender.parentElement=row;
const root={querySelectorAll:()=>[row]};
globalThis.document={querySelector:()=>null,querySelectorAll:()=>[root]};
const projected=eval(script);
if(!Array.isArray(projected)||projected.length!==1||
 projected[0].id!=='row-a'||projected[0].subject!=='synthetic subject'||
 projected[0].addresses!=='sender@example.test'||!projected[0].unread){
 throw Error('visible row projection failed');
}
heading.getClientRects=()=>[];
const hidden=eval(script);
if(!Array.isArray(hidden)||hidden.length!==1||hidden[0]!==null){
 throw Error('hidden subject remained readable');
}
heading.getClientRects=()=>[{}];
subjectOpacity='0';
if(eval(script)[0]!==null){throw Error('opacity-zero heading exposed');}
subjectOpacity='1';senderOpacity='0';
if(eval(script)[0]!==null){throw Error('opacity-zero sender exposed');}
senderOpacity='1';ancestorOpacity='0';
if(eval(script)[0]!==null){throw Error('hidden ancestor exposed content');}
ancestorOpacity='1';
const chain=Array.from({length:70},()=>({parentElement:null}));
chain.forEach((node,index)=>{node.parentElement=chain[index+1]||null;});
ancestor.parentElement=chain[0];
if(eval(script)[0]!==null){throw Error('unbounded ancestor depth accepted');}
",
    );
    let result = Command::new("node")
        .args(["--eval", &source])
        .output()
        .expect("execute synthetic row JS");
    assert!(
        result.status.success(),
        "visible row JS failed synthetic DOM"
    );
}

#[test]
fn live_javascript_list_projection_rejects_hidden_or_ambiguous_mailbox() {
    use std::process::Command;

    if Command::new("node").arg("--version").output().is_err() {
        return;
    }
    let encoded = serde_json::to_string(MailboxListEvidence::expression())
        .expect("encode audited list expression");
    let mut source = format!("const expression={encoded};\n");
    source.push_str(
        "
globalThis.location={origin:'https://mail.proton.me'};
globalThis.getComputedStyle=(node)=>({visibility:'visible',
 pointerEvents:node===next&&(nextDisabled||pointerBlocked)?'none':'auto',
 opacity:node===row?rowOpacity:node===current?currentOpacity:
 node===empty?emptyOpacity:node===ancestor?ancestorOpacity:'1'});
globalThis.HTMLButtonElement=class {};
let rowHidden=false, showLoading=false, nextDisabled=false;
let pointerBlocked=false, rowOpacity='1', currentOpacity='1';
let showEmpty=false,emptyOpacity='1',ancestorOpacity='1';
const ancestor={parentElement:null};
const row={getAttribute:()=> 'synthetic-row',
 getClientRects:()=>rowHidden?[]:[{}],closest:()=>null};
const empty={getClientRects:()=>[{}],closest:()=>null};
const loaded={parentElement:ancestor,querySelectorAll:(q)=>
 q.includes(':not(')?[]:
 q.includes('empty-view-placeholder')?(showEmpty?[empty]:[]):
 (showEmpty?[]:[row])};
row.parentElement=loaded;
const next=new HTMLButtonElement();
next.disabled=false;
next.getClientRects=()=>[{}];
next.closest=()=>null;
next.getAttribute=(key)=>key==='aria-disabled'&&nextDisabled?'true':null;
const current={getClientRects:()=>[{}],closest:()=>null,
 getAttribute:()=> 'pagination-row:go-to-page-2'};
globalThis.document={querySelector:()=>null,
 querySelectorAll:(q)=>q.includes('message-list-loading')?
   (showLoading?[{querySelectorAll:()=>[]}]:[]):
   q.includes('message-list-loaded')?[loaded]:
   q.includes('go-to-next-page')?[next]:
   q.includes('go-to-page-')?[current]:[]};
const ready=eval(expression);
if(ready.rowIds[0]!=='synthetic-row'||ready.currentTestId!==
 'pagination-row:go-to-page-2'||ready.nextDisabled!==false){
 throw Error('visible list projection was not complete');
}
rowHidden=true;
if(eval(expression)!==null){throw Error('hidden row was accepted');}
rowHidden=false;
ancestorOpacity='0';
if(eval(expression)!==null){throw Error('hidden list root was accepted');}
ancestorOpacity='1';
const chain=Array.from({length:70},()=>({parentElement:null}));
chain.forEach((node,index)=>{node.parentElement=chain[index+1]||null;});
ancestor.parentElement=chain[0];
if(eval(expression)!==null){throw Error('unbounded root ancestry accepted');}
ancestor.parentElement=null;
rowOpacity='0';
if(eval(expression)!==null){throw Error('opacity-zero row was accepted');}
rowOpacity='1';
currentOpacity='0';
if(eval(expression)!==null){throw Error('invisible page was accepted');}
currentOpacity='1';
showEmpty=true;nextDisabled=true;
if(eval(expression).emptyMarker!==true){
 throw Error('visible explicit-empty title was not detected');
}
emptyOpacity='0';
if(eval(expression)!==null){throw Error('invisible empty title was accepted');}
emptyOpacity='1';showEmpty=false;nextDisabled=false;
showLoading=true;
if(eval(expression)!==null){throw Error('two active roots were accepted');}
showLoading=false;
nextDisabled=true;
if(eval(expression).nextDisabled!==true){
 throw Error('disabled Next with pointer-events none must remain observable');
}
nextDisabled=false;
pointerBlocked=true;
if(eval(expression)!==null){
 throw Error('enabled Next with pointer-events none was accepted');
}
pointerBlocked=false;
next.getClientRects=()=>[];
if(eval(expression)!==null){throw Error('invisible enabled Next was accepted');}
",
    );
    let output = Command::new("node")
        .args(["--eval", &source])
        .output()
        .expect("run synthetic list projection");
    assert!(
        output.status.success(),
        "audited list projection rejected synthetic DOM: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn live_javascript_sort_menu_clicks_only_safe_visible_controls() {
    use std::process::Command;

    if Command::new("node").arg("--version").output().is_err() {
        return;
    }
    let scripts = [
        MailboxSortOrder::open_expression(),
        MailboxSortOrder::close_expression(),
    ];
    let script_json = serde_json::to_string(&scripts);
    let encoded = script_json.expect("audited sort scripts");
    let mut source = format!("const [open,close]={encoded};\n");
    source.push_str(
        "
globalThis.location={origin:'https://mail.proton.me'};
globalThis.HTMLButtonElement=class {};
let isOpen=false, hidden=false, disabled=false, modal=false, clicks=0;
let optionOpacity='1';
const ids=['toolbar:sort-new-to-old','toolbar:sort-old-to-new',
 'toolbar:sort-desc','toolbar:sort-asc'];
const option={getClientRects:()=>hidden?[]:[{}],closest:()=>null};
const toggle=new HTMLButtonElement();
toggle.getClientRects=()=>[{}];toggle.closest=()=>null;
toggle.getAttribute=()=>disabled?'true':null;
toggle.click=()=>{clicks++;isOpen=!isOpen;};
Object.defineProperty(toggle,'disabled',{get:()=>disabled});
globalThis.getComputedStyle=(node)=>({
 visibility:'visible',pointerEvents:'auto',
 opacity:node===option?optionOpacity:'1'});
globalThis.document={querySelector:(q)=>modal&&q.includes('dialog')?{}:null,
 querySelectorAll:(q)=>q.includes('filter-dropdown:show-filters')?[toggle]:
 ids.some(id=>q.includes(id))?(isOpen?[option]:[]):[]};
const opened=eval(open);
if(!opened.clicked||opened.alreadyOpen||clicks!==1){
 throw Error('opening did not perform exactly one click');
}
const alreadyOpen=eval(open);
if(!alreadyOpen.alreadyOpen||alreadyOpen.clicked||clicks!==1){
 throw Error('open menu triggered a second click');
}
hidden=true;
if(eval(close)!==false||clicks!==1){
 throw Error('hidden sort options triggered close');
}
hidden=false;
optionOpacity='0';
if(eval(open)!==null||eval(close)!==false||clicks!==1){
 throw Error('opacity-zero sort option was actionable');
}
optionOpacity='1';
if(eval(close)!==true||clicks!==2||isOpen){
 throw Error('closing did not perform exactly one click');
}
disabled=true;
if(eval(open)!==null||clicks!==2){
 throw Error('disabled control was clicked');
}
disabled=false;modal=true;
if(eval(open)!==null||clicks!==2){
 throw Error('modal allowed a sort click');
}
",
    );
    let output = Command::new("node")
        .args(["--eval", &source])
        .output()
        .expect("run sort control JS");
    assert!(
        output.status.success(),
        "sort click JS crossed a read-only boundary: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn loading_list_rejects_malformed_ignored_projection_fields() {
    let valid = json!({
        "loading":true,"loaded":false,"rowIds":["partial-row"],
        "skeletonCount":3u64,"emptyMarker":false,
        "nextPresent":true,"nextDisabled":true,
        "currentTestId":"pagination-row:go-to-page-1"
    });
    assert_eq!(
        MailboxListEvidence::from_runtime_value(&valid)
            .expect("valid partial loading projection")
            .state(),
        MailboxListState::Loading
    );
    for (key, invalid) in [
        ("rowIds", json!("opaque-not-array")),
        ("rowIds", json!([17i64])),
        ("skeletonCount", json!("three")),
        ("nextPresent", json!(0i64)),
        ("nextDisabled", json!([])),
        ("currentTestId", json!(false)),
    ] {
        let mut evidence = valid.clone();
        evidence[key] = invalid;
        assert!(MailboxListEvidence::from_runtime_value(&evidence).is_err());
    }
}

#[test]
fn live_javascript_next_click_requires_one_actionable_control() {
    use std::process::Command;

    if Command::new("node").arg("--version").output().is_err() {
        return;
    }
    let expression = NextPageActivation::expression();
    let encoded_json = serde_json::to_string(expression);
    let encoded = encoded_json.expect("static next-page source");
    let mut source = format!("const script={encoded};\n");
    source.push_str(
        "
let clicks=0, disabled=false, hidden=false, modal=false, duplicate=false;
globalThis.location={origin:'https://mail.proton.me'};
globalThis.HTMLButtonElement=class {};
const next=new HTMLButtonElement();
next.getAttribute=(key)=>key==='aria-disabled'&&disabled?'true':null;
next.getClientRects=()=>hidden?[]:[{}];
next.closest=()=>null;
next.click=()=>{clicks++;};
Object.defineProperty(next,'disabled',{get:()=>disabled});
globalThis.getComputedStyle=()=>({visibility:'visible',
 pointerEvents:'auto',opacity:'1'});
globalThis.document={querySelector:(q)=>modal&&q.includes('dialog')?{}:null,
 querySelectorAll:()=>duplicate?[next,next]:[next]};
if(eval(script).clicked!==true||clicks!==1){
 throw Error('enabled Next did not click exactly once');
}
disabled=true;
if(eval(script).clicked||clicks!==1){
 throw Error('ARIA-disabled Next was clicked');
}
disabled=false;hidden=true;
if(eval(script).clicked||clicks!==1){
 throw Error('layout-hidden Next was clicked');
}
hidden=false;duplicate=true;
if(eval(script).clicked||clicks!==1){
 throw Error('ambiguous Next was clicked');
}
duplicate=false;modal=true;
if(eval(script)!==null||clicks!==1){
 throw Error('modal allowed Next interaction');
}
modal=false;globalThis.location.origin='https://mail.evil.test';
if(eval(script)!==null||clicks!==1){
 throw Error('foreign origin allowed Next interaction');
}
",
    );
    let output = Command::new("node")
        .args(["--eval", &source])
        .output()
        .expect("evaluate synthetic Next click");
    assert!(
        output.status.success(),
        "audited Next click violated synthetic control state: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
