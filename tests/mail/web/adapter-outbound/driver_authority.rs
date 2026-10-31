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
fn response_body_capture_returns_guarded_json() {
    use super::{CdpEventObserver, ManagedBrowser};
    use crate::strict_json::SensitiveValue;

    type ReadBody = fn(
        &mut ManagedBrowser,
        &str,
        &str,
        &mut dyn CdpEventObserver,
    ) -> Result<SensitiveValue, BrowserDriverError>;
    let _: ReadBody = ManagedBrowser::read_cdp_body;
}

#[test]
fn scoped_browser_attachment_has_guarded_string_custody() {
    use super::{ManagedBrowser, ProviderPage};
    use zeroize::Zeroizing;

    type AttachResult = Result<Zeroizing<String>, BrowserDriverError>;
    // jig-ignore-next-line: canonical scoped attachment type signature.
    let _: fn(&mut ManagedBrowser, &ProviderPage) -> AttachResult = ManagedBrowser::attach;
}

#[test]
fn accepted_cdp_request_selectors_scrub_when_handling_aborts() {
    use super::guard_selected_request;
    use std::cell::Cell;
    use zeroize::{Zeroize, Zeroizing};

    struct Probe<'flag>(&'flag Cell<bool>);

    impl Zeroize for Probe<'_> {
        fn zeroize(&mut self) {
            self.0.set(true);
        }
    }

    fn assert_guarded<T>(_: &Zeroizing<T>)
    where
        T: Zeroize,
    {
    }

    let single = Cell::new(false);
    let paired = [Cell::new(false), Cell::new(false)];
    let failed = || -> Result<(), BrowserDriverError> {
        let request = guard_selected_request(Probe(&single));
        let pair = (Probe(&paired[0]), Probe(&paired[1]));
        let tuple = guard_selected_request(pair);
        assert_guarded(&request);
        assert_guarded(&tuple);
        Err(BrowserDriverError::Protocol)
    };
    assert!(matches!(failed(), Err(BrowserDriverError::Protocol)));
    assert!(single.get());
    assert!(paired.iter().all(Cell::get));
}

#[test]
fn ambiguous_finished_request_rows_scrub_every_rejected_value() {
    use super::{BrowserDriverError, take_exactly_one_finished};
    use std::cell::Cell;
    use zeroize::Zeroize;

    struct Probe<'flag>(&'flag Cell<bool>);

    impl Zeroize for Probe<'_> {
        fn zeroize(&mut self) {
            self.0.set(true);
        }
    }

    let flags = [Cell::new(false), Cell::new(false)];
    let failed = take_exactly_one_finished(
        vec![Probe(&flags[0]), Probe(&flags[1])],
        BrowserDriverError::MessageDetailAmbiguous,
    );
    assert!(matches!(
        failed,
        Err(BrowserDriverError::MessageDetailAmbiguous)
    ));
    assert!(flags.iter().all(Cell::get));

    let kept = Cell::new(false);
    let success = take_exactly_one_finished(
        vec![Probe(&kept)],
        BrowserDriverError::MessageDetailAmbiguous,
    );
    assert!(matches!(success, Ok(Some(_))));
    assert!(
        !kept.get(),
        "one completed row is transferred to its caller"
    );

    let empty = take_exactly_one_finished(
        Vec::<String>::new(),
        BrowserDriverError::MessageDetailAmbiguous,
    );
    assert!(matches!(empty, Ok(None)));
}

#[test]
fn passive_network_captures_require_scrub_on_drop() {
    use crate::AttachmentMetadataNetworkCapture;
    use crate::ConversationDetailNetworkCapture;
    use crate::ConversationListNetworkCapture;
    use crate::LatestMailboxEventNetworkCapture;
    use crate::MailboxCatalogNetworkCapture;
    use crate::MailboxEventNetworkCapture;
    use crate::MessageDetailNetworkCapture;
    use crate::MessageListNetworkCapture;

    #[expect(drop_bounds, reason = "require CDP request identifier custody")]
    fn requires_scrub_on_drop<T>()
    where
        T: Drop,
    {
    }
    requires_scrub_on_drop::<MessageListNetworkCapture>();
    requires_scrub_on_drop::<MessageDetailNetworkCapture>();
    requires_scrub_on_drop::<AttachmentMetadataNetworkCapture>();
    requires_scrub_on_drop::<ConversationDetailNetworkCapture>();
    requires_scrub_on_drop::<ConversationListNetworkCapture>();
    requires_scrub_on_drop::<MailboxCatalogNetworkCapture>();
    requires_scrub_on_drop::<LatestMailboxEventNetworkCapture>();
    requires_scrub_on_drop::<MailboxEventNetworkCapture>();
}

#[test]
fn managed_browser_target_and_message_list_state_require_scrub_on_drop() {
    use super::CapturedMessageListResponses;
    use super::CompletedMessageListRequest;
    use super::ProviderPage;

    #[expect(drop_bounds, reason = "require browser identifier scrubbing")]
    fn requires_scrub_on_drop<T>()
    where
        T: Drop,
    {
    }
    requires_scrub_on_drop::<ProviderPage>();
    requires_scrub_on_drop::<CompletedMessageListRequest>();
    requires_scrub_on_drop::<CapturedMessageListResponses>();
}

#[test]
fn only_audited_cdp_methods_are_accepted_in_their_session_scope() {
    for command in [
        "Browser.getVersion",
        "Browser.close",
        "Target.getTargets",
        "Target.getBrowserContexts",
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
fn browser_context_catalog_command_is_exact_and_browser_scoped() {
    let method = "Target.getBrowserContexts";
    assert!(allowed_mail_cdp_request(None, method, &json!({})));
    for params in [
        json!({"browserContextId":"incognito"}),
        json!({"id":1i32}),
        json!([]),
    ] {
        assert!(!allowed_mail_cdp_request(None, method, &params));
    }
    assert!(!allowed_mail_cdp_request(
        Some("session-a"),
        method,
        &json!({}),
    ));
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
#[expect(clippy::too_many_lines, reason = "all eight passive capture states")]
fn passive_network_observers_refuse_request_ids_unusable_by_cdp_transport() {
    use crate::attachment_metadata::AttachmentMetadataNetworkCapture;
    use crate::conversation_detail::ConversationDetailNetworkCapture;
    use crate::conversation_list_response::ConversationListNetworkCapture;
    use crate::mailbox_catalog::MailboxCatalogNetworkCapture;
    use crate::mailbox_event_watermark::{
        LatestMailboxEventNetworkCapture, MailboxEventNetworkCapture,
    };
    use crate::message_detail::MessageDetailNetworkCapture;
    use crate::message_list_response::MessageListNetworkCapture;

    let event = |id: &str, url: &str| {
        json!({
            "sessionId":"session-a", "method":"Network.requestWillBeSent",
            "params":{"requestId":id,"request":{"method":"GET","url":url}}
        })
    };
    let origin = "https://mail.proton.me/api/";
    let query = "?Page=0&PageSize=50&Limit=50&Sort=Time&Desc=1";
    let urls = [
        format!("{origin}mail/v4/messages{query}"),
        format!("{origin}mail/v4/conversations{query}"),
        format!("{origin}mail/v4/conversations/conversation-1"),
        format!("{origin}mail/v4/messages/message-1"),
        format!("{origin}mail/v4/attachments/attachment-1/metadata"),
        format!("{origin}core/v4/labels?Type=1"),
        format!("{origin}core/v4/events/latest"),
        format!("{origin}core/v5/events/event-1"),
    ];
    let good = "42.7";
    assert!(
        MessageListNetworkCapture::new("session-a")
            .observe(&event(good, &urls[0]))
            .is_ok()
    );
    assert!(
        ConversationListNetworkCapture::new("session-a")
            .observe(&event(good, &urls[1]))
            .is_ok()
    );
    assert!(
        ConversationDetailNetworkCapture::new("session-a")
            .observe(&event(good, &urls[2]))
            .is_ok()
    );
    assert!(
        MessageDetailNetworkCapture::new("session-a")
            .observe(&event(good, &urls[3]))
            .is_ok()
    );
    assert!(
        AttachmentMetadataNetworkCapture::new("session-a")
            .observe(&event(good, &urls[4]))
            .is_ok()
    );
    assert!(
        MailboxCatalogNetworkCapture::new("session-a")
            .observe(&event(good, &urls[5]))
            .is_ok()
    );
    assert!(
        LatestMailboxEventNetworkCapture::new("session-a")
            .observe(&event(good, &urls[6]))
            .is_ok()
    );
    assert!(
        MailboxEventNetworkCapture::new("session-a")
            .observe(&event(good, &urls[7]))
            .is_ok()
    );
    for invalid in ["bad space", "unicode\u{200b}hidden", "opaque\u{00e9}"] {
        assert!(
            MessageListNetworkCapture::new("session-a")
                .observe(&event(invalid, &urls[0]))
                .is_err()
        );
        assert!(
            ConversationListNetworkCapture::new("session-a")
                .observe(&event(invalid, &urls[1]))
                .is_err()
        );
        assert!(
            ConversationDetailNetworkCapture::new("session-a")
                .observe(&event(invalid, &urls[2]))
                .is_err()
        );
        assert!(
            MessageDetailNetworkCapture::new("session-a")
                .observe(&event(invalid, &urls[3]))
                .is_err()
        );
        assert!(
            AttachmentMetadataNetworkCapture::new("session-a")
                .observe(&event(invalid, &urls[4]))
                .is_err()
        );
        assert!(
            MailboxCatalogNetworkCapture::new("session-a")
                .observe(&event(invalid, &urls[5]))
                .is_err()
        );
        assert!(
            LatestMailboxEventNetworkCapture::new("session-a")
                .observe(&event(invalid, &urls[6]))
                .is_err()
        );
        assert!(
            MailboxEventNetworkCapture::new("session-a")
                .observe(&event(invalid, &urls[7]))
                .is_err()
        );
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
fn read_only_click_scripts_reject_form_submission_controls() {
    for script in [
        NextPageActivation::expression(),
        MailboxSortOrder::open_expression(),
        MailboxSortOrder::close_expression(),
    ] {
        let click = script.find(".click();").expect("audited click action");
        let type_guard = script
            .find(".type!=='button'")
            .expect("click must require a non-submit button");
        let form_guard = script
            .find(".form!==null")
            .expect("click must refuse a form-associated control");
        assert!(type_guard < click && form_guard < click);
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
    assert!(script.contains("const subject=localHeading.getAttribute"));
    assert!(script.contains("subject:subject"));
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
            .find("closest('[aria-hidden=")
            .expect("click target cannot be inside an AX-hidden subtree");
        let click = script.find(".click();").expect("audited click action");
        assert!(geometry < click && aria < click);
        assert!(script.contains("[aria-disabled=\"true\" i]"));
        assert!(allowed_mail_runtime_expression(script));
    }
}

#[test]
fn mailbox_list_next_page_evidence_requires_an_actionable_button() {
    let script = MailboxListEvidence::expression();
    assert!(script.contains("next instanceof HTMLButtonElement"));
    assert!(script.contains("next.type!=='button'"));
    assert!(script.contains("next.form!==null"));
    assert!(script.contains("next.getClientRects().length===0"));
    // jig-ignore-next-line: exact audited selector fixture.
    assert!(script.contains("next.closest('[aria-hidden=\"true\" i],[inert]')"));
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
fn visible_row_projections_reject_hidden_unicode_metadata() {
    let before = MailboxListEvidence::from_runtime_value(&json!({
        "loading":false,"loaded":true,"rowIds":["row-a"],
        "skeletonCount":0u64,"emptyMarker":false,"nextPresent":false,
        "nextDisabled":null,"currentTestId":null
    }))
    .expect("synthetic settled list");
    for mark in [
        // jig-ignore-next-line: canonical rustfmt Unicode scalar matrix.
        '\u{0600}', '\u{0605}', '\u{06dd}', '\u{070f}', '\u{0890}', '\u{0891}', '\u{08e2}',
        '\u{2800}', '\u{3164}', '\u{ffa0}',
    ] {
        for field in ["subject", "addresses"] {
            let mut rows = json!([{
                "id":"row-a","subject":"subject",
                "addresses":"contact@example.test","unread":false
            }]);
            rows[0][field] = json!(format!("invoice{mark}approved"));
            assert_eq!(
                // jig-ignore-next-line: canonical rustfmt projection signature.
                MailboxPageSnapshot::from_observations(&before, Some(&rows), Some(&rows), &before),
                Err(BrowserDriverError::MailboxPageIncompatible),
                "hidden Unicode metadata must fail closed"
            );
        }
    }
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
        assert!(script.contains("[role~=\"dialog\" i]"));
        assert!(script.contains("[role~=\"alertdialog\" i]"));
        assert!(allowed_mail_runtime_expression(script));
    }
    let next = NextPageActivation::expression();
    assert!(next.contains("[role~=\"dialog\" i]"));
    assert!(next.contains("[role~=\"alertdialog\" i]"));
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
fn live_javascript_visible_rows_deny_hidden_unicode_before_cdp() {
    use std::process::Command;

    if Command::new("node").arg("--version").output().is_err() {
        return;
    }
    let encoded = serde_json::to_string(MailboxPageSnapshot::expression())
        .expect("serialize audited visible-row expression");
    let mut source = format!("const expression={encoded};\n");
    source.push_str(
        "
globalThis.location={origin:'https://mail.proton.me'};
globalThis.getComputedStyle=()=>({visibility:'visible',opacity:'1'});
globalThis.currentSubject='ordinary subject';
globalThis.currentAddresses='reader@example.test';
const visible={parentElement:null,contains:()=>false,
 getClientRects:()=>[{left:10,top:10,width:90,height:18}],
 closest:()=>null};
const header={...visible,id:'heading',getAttribute:(key)=>
  key==='title'?currentSubject:null};
const sender={...visible,getClientRects:()=>[
 {left:120,top:10,width:90,height:18}],getAttribute:(key)=>
  key==='title'?currentAddresses:null};
const row={...visible,classList:{contains:()=>false},
 getAttribute:(key)=>key==='data-element-id'?'row-a':
   key==='aria-labelledby'?'heading':null,
 querySelectorAll:(selector)=>selector==='[id]'?[header]:[sender]};
const root={...visible,querySelectorAll:()=>[row]};
globalThis.document={querySelector:()=>null,
 elementFromPoint:(x)=>x<100?header:sender,
 querySelectorAll:(selector)=>selector.includes('message-list-loaded')?
 [root]:[]};
const valid=eval(expression);
if(!Array.isArray(valid)||valid.length!==1||
 valid[0].subject!=='ordinary subject'){
 throw Error('printable metadata must still project');
}
for(const point of [0x600,0x605,0x6dd,0x70f,0x890,0x891,
 0x8e2,0x2800,0x3164,0xffa0,0xfdd0,0xfffe,0x10ffff]){
 for(const field of ['currentSubject','currentAddresses']){
  globalThis[field]='invoice'+String.fromCodePoint(point)+'approved';
  if(eval(expression)!==null){
   throw Error('hidden metadata crossed CDP '+point.toString(16));
  }
  globalThis[field]=field==='currentSubject'?'ordinary subject':
   'reader@example.test';
 }
}
",
    );
    let result = Command::new("node")
        .args(["--eval", &source])
        .output()
        .expect("execute synthetic visible-row projection");
    assert!(
        result.status.success(),
        "visible-row browser projection must fail closed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
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
#[expect(
    clippy::too_many_lines,
    reason = "synthetic mode and Unicode route matrix"
)]
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
  ['/u/0/inbox','#keyword=valid&begin=1',true],
  ['/u/0/inbox','#wildcard=1',false],
  ['/u/0/inbox','#wildcard=1&begin=1',true],
  ['/u/0/inbox','#wildcard=1&keyword=valid',true],
  ['/u/0/inbox','#wildcard=2&keyword=valid',false],
  ['/u/0/inbox','#wildcard=99&begin=1',false],
  ['/u/0/inbox','#begin=1',true],
  ['/u/0/inbox','#begin=20&end=10',false],
  ['/u/0/inbox','#begin=10&end=10',true],
  ['/u/0/inbox','#begin=10&end=20',true],
  ['/u/0/inbox','#keyword=valid&begin=20&end=10',false],
  ['/u/0/inbox','#%6Beyword=valid',false],
  ['/u/0/inbox','#keyword=valid&%66rom=alice',false],
  ['/u/0/inbox','#keyword=valid&Keyword=decoy',false],
  ['/u/0/inbox','#keyword=valid&BEGIN=1',false],
  ['/u/0/inbox','#keyword=valid&view=threads',false],
  ['/u/0/inbox','#keyword=valid&future=1',false],
  ['/u/0/inbox','#keyword=valid&',false],
  ['/u/0/inbox','#keyword=valid&=hidden',false],
  ['/u/0/inbox','#keyword=caf%C3%A9',true],
  ['/u/0/inbox','#keyword=red%20blue',true],
  ['/u/0/inbox','#keyword=one%26two',true],
  ['/u/0/inbox','#keyword=one%3Dtwo',true],
  ['/u/0/inbox','#from=%E6%B5%8B%E8%AF%95',true],
  ['/u/0/inbox','#from=alice&to=bob',true],
  ['/u/0/inbox','#keyword=valid&begin=0',false],
  ['/u/0/inbox','#keyword=valid&begin=01',false],
  ['/u/0/inbox','#keyword=%E2%80%AE',false],
  ['/u/0/inbox','#keyword=%EF%B7%90',false],
  ['/u/0/inbox','#keyword=visible%EF%B7%90',false],
  ['/u/0/inbox','#keyword=%EF%B7%AF',false],
  ['/u/0/inbox','#keyword=%EF%BF%BE',false],
  ['/u/0/inbox','#keyword=%F4%8F%BF%BF',false],
  ['/u/0/inbox','#keyword=%F0%9F%93%A8',true],
  ['/u/0/sent','#keyword=%EF%B7%90',null],
  ['/u/0/inbox','#keyword=%E2%80%8B',false],
  ['/u/0/inbox','#keyword=%E1%85%9F',false],
  ['/u/0/inbox','#keyword=%E3%85%A4',false],
  ['/u/0/inbox','#keyword=%EF%BE%A0',false],
  ['/u/0/inbox','#keyword=%E2%A0%80',false],
  ['/u/0/inbox','#keyword=%EF%B8%8F',false],
  ['/u/0/inbox','#keyword=%EF%B8%80',false],
  ['/u/0/inbox','#keyword=%E1%A0%8B',false],
  ['/u/0/inbox','#keyword=%E1%A0%8F',false],
  ['/u/0/inbox','#keyword=%E1%9E%B4',false],
  ['/u/0/inbox','#keyword=%F0%9B%B2%A0',false],
  ['/u/0/inbox','#keyword=%F3%A0%84%80',false],
  ['/u/0/inbox','#from=%C2%AD',false],
  ['/u/0/inbox','#keyword=hello%E2%80%A8',false],
  ['/u/0/inbox','#keyword=valid&end=not-a-number',false],
  ['/u/0/inbox','#keyword=valid&from=%EF%BF%BD',false],
  ['/u/0/inbox','#keyword=valid&to=%0A',false],
  ['/u/0/unknown','#keyword=valid',false],
  ['/unknown','#keyword=valid',false],
  ['/u/00/inbox','#keyword=valid',null],
  ['/u/0/inbox/nested','#keyword=valid',null],
  ['/inbox/extra','#keyword=valid',null],
  ['/u/0/sent','',true],
  ['/u/0/sent','#keyword=valid',true],
  ['/u/0/sent','#wildcard=2&keyword=valid',null],
  ['/u/0/sent','#view=conversations',null],
  ['/u/0/sent','#keyword=valid&view=threads',null],
  ['/u/0/sent','#keyword=valid&begin=invalid',null],
  ['/u/0/sent','#keyword=valid&begin=20&end=10',null],
  ['/u/0/sent','#keyword=valid&keyword=again',null],
  ['/sent','#keyword=%E2%80%8B',null],
  ['/u/0/inbox','',false],
  ['/sent','',true],
  ['/','',null]
]){
  globalThis.location={origin:'https://mail.proton.me',pathname:path,hash};
  const result=eval(expression);
 const actual=result===null?null:result.forcedMessageRoute||result.activeSearch;
  if(actual!==expected){throw Error('invalid mode proof for '+path+hash);}
}
for(const point of [0x600,0x6dd,0x70f,0x890,0x8e2,0xfff9,
 0x110bd,0x110cd,0x13430,0x1d173,0xfdd0,0xfffe,0x10ffff]){
  const query='visible'+String.fromCodePoint(point);
  globalThis.location={origin:'https://mail.proton.me',
    pathname:'/inbox',search:'',hash:'#keyword='+encodeURIComponent(query)};
  if(eval(expression)?.activeSearch!==false){
    throw Error('format control proved search '+point.toString(16));
  }
}
for(const [path,search,hash] of [
  ['/sent/','',''],
  ['/u/0/sent/','',''],
  ['/u/0/inbox/','','#keyword=valid'],
  ['/u/0/inbox','?view=threads','#keyword=valid'],
  ['/u/0/sent','?view=threads',''],
  ['/u/0/inbox','?keyword=other','#keyword=valid'],
]){
  globalThis.location={
    origin:'https://mail.proton.me',pathname:path,search,hash};
  if(eval(expression)!==null){
    throw Error('noncanonical location '+path+search+hash);
  }
}
",
    );
    let result = Command::new("node")
        .args(["--eval", &source])
        .output()
        .expect("execute synthetic mode proof");
    assert!(
        result.status.success(),
        "synthetic mode proof failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
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
#[expect(clippy::too_many_lines, reason = "synthetic content DOM state matrix")]
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
let ancestorContentHidden=false;
let ancestorClip=false,ancestorFilter=false,ancestorMasked=false;
let ancestorWebkitMasked=false;
let headingZeroArea=false,senderZeroArea=false;
let headingCovered=false,senderCovered=false,offscreenTitles=false;
let subjectValue='synthetic subject',addressValue='sender@example.test';
let idValue='row-a',modal=false,ancestorInert=false,nativeDialog=false;
let ariaHiddenUpper=false;
let duplicateRows=false,titleReads=0,invalidSecondRow=false;
let loadingOverlay=false;
globalThis.getComputedStyle=(node)=>({visibility:'visible',
 contentVisibility:node===ancestor&&ancestorContentHidden?'hidden':'visible',
 clipPath:node===ancestor&&ancestorClip?'inset(100%)':'none',
 filter:node===ancestor&&ancestorFilter?'opacity(0)':'none',
 maskImage:node===ancestor&&ancestorMasked?
 'linear-gradient(transparent,transparent)':'none',
 webkitMaskImage:node===ancestor&&ancestorWebkitMasked?
 'linear-gradient(transparent,transparent)':'none',
 opacity:node===heading?subjectOpacity:node===sender?senderOpacity:
 node===ancestor?ancestorOpacity:'1'});
const heading={contains:()=>false,id:'heading-id',
 getAttribute:()=>{titleReads++;return subjectValue;},
  getClientRects:()=>[{left:10,top:10,width:headingZeroArea?0:80,
   height:headingZeroArea?0:14}],
  closest:(q)=>(ancestorInert&&q.includes('[inert]')||
  ariaHiddenUpper&&q.includes('[aria-hidden=\"true\" i]'))?ancestor:null};
const sender={contains:()=>false,
 getAttribute:()=>{titleReads++;return addressValue;},
  getClientRects:()=>[{left:120,top:10,width:senderZeroArea?0:80,
   height:senderZeroArea?0:14}],
  closest:(q)=>(ancestorInert&&q.includes('[inert]')||
  ariaHiddenUpper&&q.includes('[aria-hidden=\"true\" i]'))?ancestor:null};
const ancestor={parentElement:null};
const row={getAttribute:(key)=>key==='data-element-id'?idValue:
  key==='aria-labelledby'?'heading-id':null,
  querySelectorAll:(key)=>key==='[id]'?[heading]:[sender],
  parentElement:ancestor,classList:{contains:()=>true}};
heading.parentElement=row;sender.parentElement=row;
const brokenHeading={id:'heading-b',getClientRects:()=>[],
 closest:()=>null};
const brokenRow={getAttribute:(key)=>key==='data-element-id'?'row-b':
 key==='aria-labelledby'?'heading-b':null,
 querySelectorAll:(key)=>key==='[id]'?[brokenHeading]:[sender]};
brokenHeading.parentElement=brokenRow;brokenRow.parentElement=ancestor;
const root={querySelectorAll:()=>duplicateRows?[row,row]:
 invalidSecondRow?[row,brokenRow]:[row]};
globalThis.document={elementFromPoint:(x)=>
 offscreenTitles?null:x<100?(headingCovered?{}:heading):
 (senderCovered?{}:sender),querySelector:(q)=>
 (modal&&q.includes('dialog')||
 nativeDialog&&q.includes('dialog[open]'))?{}:null,
 querySelectorAll:(q)=>q.includes('message-list-loading')?
 (loadingOverlay?[{}]:[]):[root]};
const projected=eval(script);
if(!Array.isArray(projected)||projected.length!==1||
 projected[0].id!=='row-a'||projected[0].subject!=='synthetic subject'||
 projected[0].addresses!=='sender@example.test'||!projected[0].unread){
 throw Error('visible row projection failed');
}
headingCovered=true;titleReads=0;
if(eval(script)!==null||titleReads!==0){
 throw Error('covered subject exposed private title');
}
headingCovered=false;senderCovered=true;titleReads=0;
if(eval(script)!==null||titleReads!==0){
 throw Error('covered correspondent exposed private title');
}
senderCovered=false;offscreenTitles=true;titleReads=0;
if(eval(script)!==null||titleReads!==0){
 throw Error('offscreen subject exposed private title');
}
offscreenTitles=false;duplicateRows=true;titleReads=0;
if(eval(script)!==null){throw Error('duplicate IDs were projected');}
if(titleReads!==0){throw Error('duplicate IDs caused content reads');}
duplicateRows=false;loadingOverlay=true;titleReads=0;
if(eval(script)!==null){throw Error('loading overlay leaked content');}
if(titleReads!==0){throw Error('loading overlay caused title access');}
loadingOverlay=false;invalidSecondRow=true;
if(eval(script)!==null){
 throw Error('partial content released despite invalid row');
}
invalidSecondRow=false;
for(const invalidText of ['line\\nfeed', 'carriage\\rreturn',
 'line\\u2028separator', 'null\\u0000character',
 'bidi\\u202eoverride', 'isolate\\u2066mark',
 'zero\\u200bwidth',
 'soft\\u00adhyphen',
 'bom\\ufeffmark', 'tag\\u{e0001}mark',
 'unpaired-high\\ud800unit', 'unpaired-low\\udcffunit']){
 subjectValue=invalidText;
 if(eval(script)!==null){throw Error('unsafe subject entered CDP');}
 subjectValue='synthetic subject';addressValue=invalidText;
 if(eval(script)!==null){throw Error('unsafe address entered CDP');}
 addressValue='sender@example.test';
}
for(const point of [0xfdd0,0xfffe,0x10ffff]){
 const unsafe='ordinary'+String.fromCodePoint(point);
 subjectValue=unsafe;
 if(eval(script)!==null){throw Error('noncharacter subject crossed CDP');}
 subjectValue='synthetic subject';addressValue=unsafe;
 if(eval(script)!==null){throw Error('noncharacter addresses crossed CDP');}
 addressValue='sender@example.test';
}
subjectValue='heart\\u2764\\ufe0f and face\\u{1f600}';
addressValue='Name\\u200cpart <sender@example.test>';
const rich=eval(script);
if(rich?.[0]?.subject!==subjectValue||
 rich?.[0]?.addresses!==addressValue){
 throw Error('ordinary grapheme formatting was refused');
}
subjectValue='synthetic subject';addressValue='sender@example.test';
heading.getClientRects=()=>[];
const hidden=eval(script);
if(hidden!==null){
 throw Error('hidden subject remained readable');
}
heading.getClientRects=()=>[{left:10,top:10,
 width:headingZeroArea?0:80,
 height:headingZeroArea?0:14}];
headingZeroArea=true;titleReads=0;
if(eval(script)!==null||titleReads!==0){
 throw Error('zero-area subject exposed title');
}
headingZeroArea=false;senderZeroArea=true;titleReads=0;
if(eval(script)!==null||titleReads!==0){
 throw Error('zero-area sender exposed title');
}
senderZeroArea=false;
subjectOpacity='0';
if(eval(script)!==null){throw Error('opacity-zero heading exposed');}
subjectOpacity='1';senderOpacity='0';
if(eval(script)!==null){throw Error('opacity-zero sender exposed');}
senderOpacity='1';ancestorOpacity='0';
if(eval(script)!==null){throw Error('hidden ancestor exposed content');}
ancestorOpacity='1';ancestorContentHidden=true;titleReads=0;
if(eval(script)!==null||titleReads!==0){
 throw Error('content-hidden ancestor leaked row content');
}
ancestorContentHidden=false;ancestorClip=true;titleReads=0;
if(eval(script)!==null||titleReads!==0){
 throw Error('clipped parent exposed private row titles');
}
ancestorClip=false;ancestorFilter=true;titleReads=0;
if(eval(script)!==null||titleReads!==0){
 throw Error('filtered-out parent exposed private row titles');
}
ancestorFilter=false;ancestorMasked=true;titleReads=0;
if(eval(script)!==null||titleReads!==0){
 throw Error('masked parent exposed private row titles');
}
ancestorMasked=false;ancestorWebkitMasked=true;titleReads=0;
if(eval(script)!==null||titleReads!==0){
 throw Error('WebKit-masked parent exposed private row titles');
}
ancestorWebkitMasked=false;
const chain=Array.from({length:70},()=>({parentElement:null}));
chain.forEach((node,index)=>{node.parentElement=chain[index+1]||null;});
ancestor.parentElement=chain[0];
if(eval(script)!==null){throw Error('unbounded ancestor depth accepted');}
ancestor.parentElement=null;
subjectValue='x'.repeat(16385);
if(eval(script)!==null){throw Error('oversized subject crossed CDP');}
subjectValue='\\u00e9'.repeat(9000);
if(eval(script)!==null){throw Error('oversized UTF-8 crossed CDP');}
subjectValue='synthetic subject';
addressValue='y'.repeat(16385);
if(eval(script)!==null){throw Error('oversized addresses crossed CDP');}
addressValue='sender@example.test';idValue='z'.repeat(513);
if(eval(script)!==null){throw Error('oversized row ID crossed CDP');}
idValue='row-a';
for(const invalidId of ['.', '..', 'white space', 'with/slash',
 'encoded%2fpath', 'matrix;param=value', 'newline\\n', 'zero\\u200bwidth',
 'hangul\\u115ffiller', 'mongolian\\u180fvariation',
 'braille\\u2800blank', 'tag\\u{e0100}selector',
 'khmer\\u17b4vowel', 'shorthand\\u{1bca0}control',
 'surrogate\\ud800half', 'surrogate\\udcfforphan',
 'lossy\\ufffdid']){
 idValue=invalidId;titleReads=0;
 if(eval(script)!==null){throw Error('unsafe row ID crossed CDP');}
 if(titleReads!==0){throw Error('invalid ID caused a content read');}
}
for(const point of [0x600,0x6dd,0x70f,0x890,0x8e2,0xfff9,
 0x110bd,0x110cd,0x13430,0x1d173,0xfdd0,0xfffe,0x10ffff]){
 idValue='hidden'+String.fromCodePoint(point);titleReads=0;
 if(eval(script)!==null||titleReads!==0){
  throw Error('format control exposed row content '+point.toString(16));
 }
}
idValue='valid\\u{1f600}emoji';
if(eval(script)[0]?.id!==idValue){throw Error('valid astral ID refused');}
idValue='m\\u00e9moire';
if(eval(script)[0]?.id!==idValue){throw Error('valid unicode ID refused');}
idValue='row-a';modal=true;
if(eval(script)!==null){throw Error('modal exposed content rows');}
modal=false;nativeDialog=true;
if(eval(script)!==null){throw Error('native dialog exposed content');}
nativeDialog=false;
modal=false;ancestorInert=true;
if(eval(script)!==null){throw Error('inert ancestor exposed content');}
ancestorInert=false;ariaHiddenUpper=true;titleReads=0;
if(eval(script)!==null||titleReads!==0){
 throw Error('uppercase aria-hidden ancestor exposed content');
}
",
    );
    let result = Command::new("node")
        .args(["--eval", &source])
        .output()
        .expect("execute synthetic row JS");
    assert!(
        result.status.success(),
        "visible row JS failed synthetic DOM: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
#[expect(clippy::too_many_lines, reason = "full synthetic DOM state matrix")]
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
 contentVisibility:node===ancestor&&ancestorContentHidden?'hidden':'visible',
 clipPath:node===ancestor&&ancestorClip?'inset(100%)':'none',
 filter:node===ancestor&&ancestorFilter?'opacity(0)':'none',
 maskImage:node===ancestor&&ancestorMasked?
 'linear-gradient(transparent,transparent)':'none',
 pointerEvents:node===loaded&&parentPointerBlocked?'none':
 node===next&&(nextDisabled||pointerBlocked)?'none':'auto',
 opacity:node===row?rowOpacity:node===current?currentOpacity:
 node===empty?emptyOpacity:node===ancestor?ancestorOpacity:'1'});
globalThis.HTMLButtonElement=class {};
let rowHidden=false, showLoading=false, nextDisabled=false;
let duplicateRows=false;
let fieldsetDisabled=false;
let pointerBlocked=false,parentPointerBlocked=false,zeroNextArea=false;
let overlayNext=false,viewportNext=false;
let rowCovered=false,emptyCovered=false,currentCovered=false;
let rowOpacity='1', currentOpacity='1';
let showEmpty=false,emptyOpacity='1',ancestorOpacity='1';
let ancestorContentHidden=false,ancestorClip=false,ancestorFilter=false;
let ancestorMasked=false;
let rowZeroArea=false,currentZeroArea=false,emptyZeroArea=false;
let modal=false,rootInert=false,nextParentDisabled=false;
let rootAriaHiddenUpper=false,nextAriaUpper=false;
let nativeDialog=false;
let rowId='synthetic-row',pageId='pagination-row:go-to-page-2';
const ancestor={parentElement:null};
const row={contains:()=>false,getAttribute:()=>rowId,
 getClientRects:()=>rowHidden?[]:[{left:10,top:10,
 width:rowZeroArea?0:90,
 height:rowZeroArea?0:18}],
 closest:(q)=>(rootInert&&q.includes('[inert]')||
 rootAriaHiddenUpper&&q.includes('[aria-hidden=\"true\" i]'))?loaded:null};
const empty={contains:()=>false,
 getClientRects:()=>[{left:110,top:10,width:emptyZeroArea?0:90,
 height:emptyZeroArea?0:18}],
 closest:(q)=>(rootInert&&q.includes('[inert]')||
 rootAriaHiddenUpper&&q.includes('[aria-hidden=\"true\" i]'))?loaded:null};
const loaded={parentElement:ancestor,querySelectorAll:(q)=>
 q.includes(':not(')?[]:
 q.includes('empty-view-placeholder')?(showEmpty?[empty]:[]):
 (showEmpty?[]:duplicateRows?[row,row]:[row])};
row.parentElement=loaded;
const next=new HTMLButtonElement();
next.parentElement=loaded;
next.type='button';next.form=null;
next.disabled=false;
next.getClientRects=()=>[{left:310,top:10,width:zeroNextArea?0:60,
 height:zeroNextArea?0:20}];
next.contains=()=>false;
next.closest=(q)=>(rootInert&&q.includes('[inert]')||
 nextParentDisabled&&q.includes('[aria-disabled'))?loaded:null;
next.getAttribute=(key)=>key==='aria-disabled'&&
 (nextDisabled||nextAriaUpper)?(nextAriaUpper?'TRUE':'true'):null;
next.matches=(selector)=>selector===':disabled'&&fieldsetDisabled;
const current={contains:()=>false,
 getClientRects:()=>[{left:210,top:10,width:currentZeroArea?0:45,
 height:currentZeroArea?0:20}],
 closest:(q)=>rootInert&&q.includes('[inert]')?loaded:null,
 getAttribute:()=>pageId};
globalThis.document={querySelector:(q)=>
 (modal&&q.includes('dialog')||
 nativeDialog&&q.includes('dialog[open]'))?{}:null,
 elementFromPoint:(x)=>x<100?(rowCovered?{}:row):
 x<205?(emptyCovered?{}:empty):
 x<300?(currentCovered?{}:current):
 (viewportNext?null:overlayNext?{}:next),
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
overlayNext=true;
if(eval(expression)!==null){
 throw Error('covered enabled Next reported actionable');
}
nextDisabled=true;
if(eval(expression)?.nextDisabled!==true){
 throw Error('disabled Next may remain observable beneath overlay');
}
nextDisabled=false;overlayNext=false;viewportNext=true;
if(eval(expression)!==null){
 throw Error('off-viewport enabled Next reported actionable');
}
viewportNext=false;
rowCovered=true;
if(eval(expression)!==null){
 throw Error('covered loaded row reported visible');
}
rowCovered=false;currentCovered=true;
if(eval(expression)!==null){
 throw Error('covered page marker proved pagination');
}
currentCovered=false;nextAriaUpper=true;
if(eval(expression)?.nextDisabled!==true){
 throw Error('uppercase ARIA-disabled Next was reported enabled');
}
nextAriaUpper=false;rootAriaHiddenUpper=true;
if(eval(expression)!==null){
 throw Error('uppercase aria-hidden list row was serialized');
}
rootAriaHiddenUpper=false;
duplicateRows=true;
if(eval(expression)!==null){throw Error('duplicate list IDs accepted');}
duplicateRows=false;
rowHidden=true;
if(eval(expression)!==null){throw Error('hidden row was accepted');}
rowHidden=false;rowZeroArea=true;
if(eval(expression)!==null){throw Error('zero-area list row accepted');}
rowZeroArea=false;
ancestorOpacity='0';
if(eval(expression)!==null){throw Error('hidden list root was accepted');}
ancestorOpacity='1';ancestorContentHidden=true;
if(eval(expression)!==null){
 throw Error('content-hidden list root was exposed');
}
ancestorContentHidden=false;ancestorClip=true;
if(eval(expression)!==null){
 throw Error('clipped loaded list reported visible rows');
}
ancestorClip=false;ancestorFilter=true;
if(eval(expression)!==null){
 throw Error('filtered-out loaded list reported visible rows');
}
ancestorFilter=false;ancestorMasked=true;
if(eval(expression)!==null){
 throw Error('masked list reported visible rows');
}
ancestorMasked=false;
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
currentOpacity='1';currentZeroArea=true;
if(eval(expression)!==null){throw Error('zero-area current page accepted');}
currentZeroArea=false;
showEmpty=true;nextDisabled=true;
if(eval(expression).emptyMarker!==true){
 throw Error('visible explicit-empty title was not detected');
}
emptyCovered=true;
if(eval(expression)!==null){
 throw Error('covered empty-title marker proved empty Mail');
}
emptyCovered=false;emptyOpacity='0';
if(eval(expression)!==null){throw Error('invisible empty title was accepted');}
emptyOpacity='1';emptyZeroArea=true;
if(eval(expression)!==null){throw Error('zero-area empty title accepted');}
emptyZeroArea=false;showEmpty=false;nextDisabled=false;
showLoading=true;
if(eval(expression)!==null){throw Error('two active roots were accepted');}
showLoading=false;
nextDisabled=true;parentPointerBlocked=true;
if(eval(expression).nextDisabled!==true){
 throw Error('disabled Next with pointer-events none must remain observable');
}
parentPointerBlocked=false;nextDisabled=false;nextParentDisabled=true;
if(eval(expression).nextDisabled!==true){
 throw Error('inherited disabled Next was reported enabled');
}
nextParentDisabled=false;fieldsetDisabled=true;
if(eval(expression).nextDisabled!==true){
 throw Error('fieldset-disabled Next reported enabled');
}
fieldsetDisabled=false;
next.type='submit';
if(eval(expression)!==null){throw Error('submit Next exposed in list');}
next.type='button';next.form={};
if(eval(expression)!==null){throw Error('form-bound Next exposed in list');}
next.form=null;
rowId='A'.repeat(513);
if(eval(expression)!==null){throw Error('oversized row IDs entered CDP');}
rowId='synthetic-row';
for(const invalidId of ['.', '..', 'white space', 'with/slash',
 'encoded%2fpath', 'matrix;param=value', 'newline\\n', 'zero\\u200bwidth',
 'hangul\\u115ffiller', 'mongolian\\u180fvariation',
 'braille\\u2800blank', 'tag\\u{e0100}selector',
 'khmer\\u17b4vowel', 'shorthand\\u{1bca0}control',
 'surrogate\\ud800half', 'surrogate\\udcfforphan',
 'lossy\\ufffdid']){
 rowId=invalidId;
 if(eval(expression)!==null){throw Error('unsafe list ID crossed CDP');}
}
for(const point of [0x600,0x6dd,0x70f,0x890,0x8e2,0xfff9,
 0x110bd,0x110cd,0x13430,0x1d173,0xfdd0,0xfffe,0x10ffff]){
 rowId='hidden'+String.fromCodePoint(point);
 if(eval(expression)!==null){
  throw Error('format control exposed list ID '+point.toString(16));
 }
}
rowId='valid\\u{1f600}emoji';
if(eval(expression)?.rowIds[0]!==rowId){
 throw Error('valid astral list ID refused');
}
rowId='m\\u00e9moire';
if(eval(expression)?.rowIds[0]!==rowId){
 throw Error('valid unicode list ID refused');
}
rowId='\\u00e9'.repeat(260);
if(eval(expression)!==null){throw Error('UTF-8 row IDs exceeded limit');}
rowId='synthetic-row';pageId='pagination-row:go-to-page-'+ '9'.repeat(100);
if(eval(expression)!==null){throw Error('oversized page selector entered CDP');}
pageId='pagination-row:go-to-page-2';
pointerBlocked=true;
if(eval(expression)!==null){
 throw Error('enabled Next with pointer-events none was accepted');
}
pointerBlocked=false;parentPointerBlocked=true;
if(eval(expression)!==null){
 throw Error('enabled Next beneath pointer-blocked parent was accepted');
}
parentPointerBlocked=false;zeroNextArea=true;
if(eval(expression)!==null){
 throw Error('zero-area Next was reported actionable');
}
zeroNextArea=false;
next.getClientRects=()=>[];
if(eval(expression)!==null){throw Error('invisible enabled Next was accepted');}
next.getClientRects=()=>[{width:60,height:20}];rootInert=true;
if(eval(expression)!==null){throw Error('inert list was exposed');}
rootInert=false;modal=true;
if(eval(expression)!==null){throw Error('modal exposed list state');}
modal=false;nativeDialog=true;
if(eval(expression)!==null){throw Error('native modal exposed list');}
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
#[expect(clippy::too_many_lines, reason = "synthetic sort DOM state matrix")]
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
let optionCovered=false,toggleCovered=false;
let optionOpacity='1', optionParentOpacity='1', toggleParentOpacity='1';
let optionParentPointerBlocked=false,toggleParentPointerBlocked=false;
let optionParentContentHidden=false,toggleParentContentHidden=false;
let optionParentClip=false,toggleParentFilter=false;
let optionParentMasked=false,toggleParentMasked=false;
let zeroOptionArea=false,zeroToggleArea=false;
let sortInert=false,parentAriaDisabled=false,fieldsetDisabled=false;
let ariaOnlyDisabled=false,uppercaseAriaDisabled=false;
let optionParentDisabled=false;
const ids=['toolbar:sort-new-to-old','toolbar:sort-old-to-new',
 'toolbar:sort-desc','toolbar:sort-asc'];
const optionParent={parentElement:null};
const toggleParent={parentElement:null};
const option={getClientRects:()=>hidden?[]:[{left:10,top:10,
 width:zeroOptionArea?0:40,height:zeroOptionArea?0:20}],
 closest:(q)=>(sortInert&&q.includes('[inert]')||
 optionParentDisabled&&q.includes('[aria-disabled'))?optionParent:null,
 contains:()=>false,parentElement:optionParent};
const toggle=new HTMLButtonElement();
toggle.type='button';toggle.form=null;
toggle.parentElement=toggleParent;
toggle.getClientRects=()=>[{left:90,top:10,
 width:zeroToggleArea?0:60,height:zeroToggleArea?0:20}];
toggle.contains=()=>false;
toggle.closest=(q)=>(sortInert&&q.includes('[inert]')||
 parentAriaDisabled&&q.includes('[aria-disabled'))?toggleParent:null;
toggle.getAttribute=()=>(disabled||ariaOnlyDisabled)?
 (uppercaseAriaDisabled?'TRUE':'true'):null;
toggle.click=()=>{clicks++;isOpen=!isOpen;};
Object.defineProperty(toggle,'disabled',{get:()=>disabled});
toggle.matches=(q)=>q===':disabled'&&fieldsetDisabled;
globalThis.getComputedStyle=(node)=>({
 visibility:'visible',
 contentVisibility:(node===optionParent&&optionParentContentHidden)||
 (node===toggleParent&&toggleParentContentHidden)?'hidden':'visible',
 clipPath:node===optionParent&&optionParentClip?'inset(100%)':'none',
 filter:node===toggleParent&&toggleParentFilter?'opacity(0)':'none',
 maskImage:node===optionParent&&optionParentMasked||
 node===toggleParent&&toggleParentMasked?
 'linear-gradient(transparent,transparent)':'none',
 pointerEvents:(node===optionParent&&optionParentPointerBlocked)||
 (node===toggleParent&&toggleParentPointerBlocked)?'none':'auto',
 opacity:node===option?optionOpacity:
 node===optionParent?optionParentOpacity:
 node===toggleParent?toggleParentOpacity:'1'});
globalThis.document={querySelector:(q)=>modal&&q.includes('dialog')?{}:null,
 elementFromPoint:(x)=>x<70?(optionCovered?{}:option):
 (toggleCovered?{}:toggle),
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
optionParentDisabled=true;
if(eval(open)!==null||eval(close)!==false||clicks!==1){
 throw Error('ARIA-disabled sort option was actionable');
}
optionParentDisabled=false;hidden=true;
if(eval(close)!==false||clicks!==1){
 throw Error('hidden sort options triggered close');
}
hidden=false;
optionOpacity='0';
if(eval(open)!==null||eval(close)!==false||clicks!==1){
 throw Error('opacity-zero sort option was actionable');
}
optionOpacity='1';
optionParentOpacity='0';
if(eval(open)!==null||eval(close)!==false||clicks!==1){
 throw Error('transparent option parent allowed action');
}
optionParentOpacity='1';
optionParentPointerBlocked=true;
if(eval(open)!==null||eval(close)!==false||clicks!==1){
 throw Error('pointer-blocked sort options allowed programmatic action');
}
optionParentPointerBlocked=false;
optionParentContentHidden=true;
if(eval(open)!==null||eval(close)!==false||clicks!==1){
 throw Error('content-hidden sort options allowed programmatic action');
}
optionParentContentHidden=false;optionParentClip=true;
if(eval(open)!==null||eval(close)!==false||clicks!==1){
 throw Error('clipped sort options authorized an action');
}
optionParentClip=false;optionCovered=true;
if(eval(open)!==null||eval(close)!==false||clicks!==1){
 throw Error('covered sort options authorized programmatic click');
}
optionCovered=false;optionParentMasked=true;
if(eval(open)!==null||eval(close)!==false||clicks!==1){
 throw Error('masked sort options authorized programmatic action');
}
optionParentMasked=false;zeroOptionArea=true;
if(eval(open)!==null||eval(close)!==false||clicks!==1){
 throw Error('zero-area sort options passed geometry proof');
}
zeroOptionArea=false;
toggle.type='submit';
if(eval(close)!==false||clicks!==1){
 throw Error('submit sort toggle closed menu');
}
toggle.type='button';toggle.form={};
if(eval(close)!==false||clicks!==1){
 throw Error('form-associated sort toggle closed menu');
}
toggle.form=null;
if(eval(close)!==true||clicks!==2||isOpen){
 throw Error('closing did not perform exactly one click');
}
toggleParentOpacity='0';
if(eval(open)!==null||clicks!==2){
 throw Error('transparent toggle parent was clicked');
}
toggleParentOpacity='1';
toggleParentPointerBlocked=true;
if(eval(open)!==null||clicks!==2){
 throw Error('pointer-blocked sort toggle was programmatically clicked');
}
toggleParentPointerBlocked=false;
toggleParentContentHidden=true;
if(eval(open)!==null||clicks!==2){
 throw Error('content-hidden sort toggle was programmatically clicked');
}
toggleParentContentHidden=false;toggleParentFilter=true;
if(eval(open)!==null||clicks!==2){
 throw Error('filtered-out sort toggle received a click');
}
toggleParentFilter=false;toggleCovered=true;
if(eval(open)!==null||clicks!==2){
 throw Error('covered sort toggle was programmatically opened');
}
toggleCovered=false;toggleParentMasked=true;
if(eval(open)!==null||clicks!==2){
 throw Error('masked sort toggle was programmatically opened');
}
toggleParentMasked=false;zeroToggleArea=true;
if(eval(open)!==null||clicks!==2){
 throw Error('zero-area sort toggle received programmatic click');
}
zeroToggleArea=false;
sortInert=true;
if(eval(open)!==null||clicks!==2){throw Error('inert sort menu clicked');}
sortInert=false;parentAriaDisabled=true;
if(eval(open)!==null||clicks!==2){
 throw Error('ARIA-disabled sort parent permitted a click');
}
parentAriaDisabled=false;fieldsetDisabled=true;
if(eval(open)!==null||clicks!==2){
 throw Error('fieldset-disabled sort toggle permitted click');
}
fieldsetDisabled=false;toggle.type='submit';
if(eval(open)!==null||clicks!==2){
 throw Error('submit sort toggle opened menu');
}
toggle.type='button';toggle.form={};
if(eval(open)!==null||clicks!==2){
 throw Error('form-associated sort toggle opened menu');
}
toggle.form=null;disabled=true;
if(eval(open)!==null||clicks!==2){
 throw Error('disabled control was clicked');
}
disabled=false;ariaOnlyDisabled=true;uppercaseAriaDisabled=true;
if(eval(open)!==null||clicks!==2){
 throw Error('uppercase ARIA-disabled sort toggle was clicked');
}
ariaOnlyDisabled=false;uppercaseAriaDisabled=false;modal=true;
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
        "loading":true,"loaded":false,"rowIds":[],
        "skeletonCount":0u64,"emptyMarker":false,
        "nextPresent":false,"nextDisabled":null,
        "currentTestId":null
    });
    assert_eq!(
        MailboxListEvidence::from_runtime_value(&valid)
            .expect("canonical content-free loading projection")
            .state(),
        MailboxListState::Loading
    );
    for (key, invalid) in [
        ("rowIds", json!(["partial-row"])),
        ("skeletonCount", json!(3u64)),
        ("nextPresent", json!(true)),
        ("nextDisabled", json!(true)),
        ("currentTestId", json!("pagination-row:go-to-page-1")),
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
#[expect(clippy::too_many_lines, reason = "synthetic Next control matrix")]
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
let overlayCoversNext=false,offViewportNext=false;
let descendantHitNext=false,invalidNextCoordinates=false;
let uppercaseAriaDisabled=false,ariaOnlyDisabled=false;
let parentOpacity='1',parentInert=false,parentAriaDisabled=false;
let parentPointerBlocked=false,parentContentHidden=false;
let parentClip=false,parentFilter=false,parentMasked=false;
let parentWebkitMasked=false;
let fieldsetDisabled=false;
globalThis.location={origin:'https://mail.proton.me'};
globalThis.HTMLButtonElement=class {};
const parent={parentElement:null};
const next=new HTMLButtonElement();
next.type='button';next.form=null;
next.parentElement=parent;
next.getAttribute=(key)=>key==='aria-disabled'&&(disabled||ariaOnlyDisabled)?
 (uppercaseAriaDisabled?'TRUE':'true'):null;
next.getClientRects=()=>hidden?[]:[{left:invalidNextCoordinates?NaN:10,
 top:10,width:80,height:20}];
const nextChild={};next.contains=(hit)=>hit===nextChild;
next.closest=(q)=>(parentInert&&q.includes('[inert]')||
 parentAriaDisabled&&q.includes('[aria-disabled'))?parent:null;
next.click=()=>{clicks++;};
Object.defineProperty(next,'disabled',{get:()=>disabled});
next.matches=(selector)=>selector===':disabled'&&fieldsetDisabled;
globalThis.getComputedStyle=(node)=>({visibility:'visible',
 contentVisibility:node===parent&&parentContentHidden?'hidden':'visible',
 clipPath:node===parent&&parentClip?'inset(100%)':'none',
 filter:node===parent&&parentFilter?'opacity(0)':'none',
 maskImage:node===parent&&parentMasked?
 'linear-gradient(transparent,transparent)':'none',
 webkitMaskImage:node===parent&&parentWebkitMasked?
 'linear-gradient(transparent,transparent)':'none',
 pointerEvents:node===parent&&parentPointerBlocked?'none':'auto',
 opacity:node===parent?parentOpacity:'1'});
globalThis.document={querySelector:(q)=>modal&&q.includes('dialog')?{}:null,
 elementFromPoint:()=>offViewportNext?null:
 overlayCoversNext?{}:descendantHitNext?nextChild:next,
 querySelectorAll:()=>duplicate?[next,next]:[next]};
if(eval(script).clicked!==true||clicks!==1){
 throw Error('enabled Next did not click exactly once');
}
descendantHitNext=true;
if(eval(script).clicked!==true||clicks!==2){
 throw Error('descendant hit on Next refused valid activation');
}
descendantHitNext=false;clicks=1;
disabled=true;
if(eval(script).clicked||clicks!==1){
 throw Error('ARIA-disabled Next was clicked');
}
disabled=false;ariaOnlyDisabled=true;uppercaseAriaDisabled=true;
if(eval(script).clicked||clicks!==1){
 throw Error('uppercase ARIA-disabled Next was clicked');
}
ariaOnlyDisabled=false;uppercaseAriaDisabled=false;parentOpacity='0';
if(eval(script).clicked||clicks!==1){
 throw Error('transparent Next parent permitted a click');
}
parentOpacity='1';parentPointerBlocked=true;
if(eval(script).clicked||clicks!==1){
 throw Error('pointer-blocked Next parent permitted a programmatic click');
}
parentPointerBlocked=false;parentContentHidden=true;
if(eval(script).clicked||clicks!==1){
 throw Error('content-hidden Next parent permitted a programmatic click');
}
parentContentHidden=false;parentClip=true;
if(eval(script).clicked||clicks!==1){
 throw Error('clipped Next parent permitted programmatic click');
}
parentClip=false;parentFilter=true;
if(eval(script).clicked||clicks!==1){
 throw Error('filtered-out Next parent permitted programmatic click');
}
parentFilter=false;parentMasked=true;
if(eval(script).clicked||clicks!==1){
 throw Error('masked Next parent permitted programmatic click');
}
parentMasked=false;parentWebkitMasked=true;
if(eval(script).clicked||clicks!==1){
 throw Error('WebKit-masked Next parent received a click');
}
parentWebkitMasked=false;overlayCoversNext=true;
if(eval(script).clicked||clicks!==1){
 throw Error('overlay-covered Next was programmatically clicked');
}
overlayCoversNext=false;offViewportNext=true;
if(eval(script).clicked||clicks!==1){
 throw Error('off-viewport Next was programmatically clicked');
}
offViewportNext=false;invalidNextCoordinates=true;
if(eval(script).clicked||clicks!==1){
 throw Error('invalid viewport midpoint authorized Next click');
}
invalidNextCoordinates=false;
next.getClientRects=()=>[{left:10,top:10,width:0,height:0}];
if(eval(script).clicked||clicks!==1){
 throw Error('zero-area Next control received programmatic click');
}
next.getClientRects=()=>hidden?[]:[{left:10,top:10,
 width:80,height:20}];
parentInert=true;
if(eval(script).clicked||clicks!==1){throw Error('inert Next clicked');}
parentInert=false;parentAriaDisabled=true;
if(eval(script).clicked||clicks!==1){
 throw Error('ARIA-disabled parent permitted a click');
}
parentAriaDisabled=false;fieldsetDisabled=true;
if(eval(script).clicked||clicks!==1){
 throw Error('fieldset-disabled Next permitted a click');
}
fieldsetDisabled=false;next.type='submit';
if(eval(script).clicked||clicks!==1){
 throw Error('submit Next button was clicked');
}
next.type='button';next.form={};
if(eval(script).clicked||clicks!==1){
 throw Error('form-associated Next button was clicked');
}
next.form=null;hidden=true;
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

#[test]
fn uppercase_aria_modal_or_dialog_role_blocks_audited_dom_actions() {
    use std::process::Command;

    if Command::new("node").arg("--version").output().is_err() {
        return;
    }
    let scripts = [
        MailboxModeEvidence::expression(),
        MailboxListEvidence::expression(),
        MailboxPageSnapshot::expression(),
        MailboxSortOrder::expression(),
        MailboxSortOrder::open_expression(),
        MailboxSortOrder::close_expression(),
        MailboxSortOrder::closed_expression(),
        NextPageActivation::expression(),
    ];
    // jig-ignore-next-line: canonical synthetic script source.
    let encoded = serde_json::to_string(&scripts).expect("encode audited scripts");
    let source = format!(
        r#"const scripts={encoded};
globalThis.location={{origin:'https://mail.proton.me',
 pathname:'/u/0/inbox',hash:'#keyword=synthetic'}};
let blocker='';
globalThis.document={{querySelector:(selector)=>{{
  if(blocker==='role'&&selector.includes('[role~="dialog" i]')){{return {{}};}}
  if(blocker==='modal'&&
 selector.includes('[aria-modal="true" i]')){{return {{}};}}
  return null;
}}}};
for (const type of ['role','modal']){{
 blocker=type;
 for(const script of scripts){{
  const result=eval(script);
  if(result!==null&&result!==false){{
   throw Error('case-variant blocker escaped '+type);
  }}
 }}
}}
"#,
    );
    let output = Command::new("node")
        .args(["--eval", &source])
        .output()
        .expect("run uppercase modal fixture");
    assert!(
        output.status.success(),
        "case-variant modal failed closed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn read_only_mode_and_sort_evidence_refuse_new_modal_dialogs() {
    use std::process::Command;

    if Command::new("node").arg("--version").output().is_err() {
        return;
    }
    let expressions = [
        MailboxModeEvidence::expression(),
        MailboxSortOrder::expression(),
        MailboxSortOrder::closed_expression(),
    ];
    let serialized = serde_json::to_string(&expressions);
    let json = serialized.expect("audited expressions");
    let mut source = format!("const expressions={json};\n");
    source.push_str(
        "
globalThis.location={origin:'https://mail.proton.me',
 pathname:'/u/0/inbox',hash:'#keyword=synthetic'};
let modalMarker='dialog';
globalThis.document={querySelector:(q)=>
 q.includes(modalMarker)?{}:null,querySelectorAll:()=>[]};
for(const marker of ['dialog','dialog[open]','aria-modal']){
 modalMarker=marker;
 for(const expression of expressions){
  if(eval(expression)!==null){throw Error('modal did not block a read');}
 }
}
",
    );
    let output = Command::new("node")
        .args(["--eval", &source])
        .output()
        .expect("run synthetic modal read test");
    assert!(
        output.status.success(),
        "read-only state was projected through a modal: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn event_cursor_encoder_refuses_noncanonical_browser_generation() {
    use crate::event_cursor_codec::WebEventCursorCodec;
    use crate::event_cursor_codec::WebEventCursorCodecError;
    use mail_capability_domain::EventCursorScope;

    let codec = WebEventCursorCodec::fresh().expect("fresh synthetic codec");
    let adapter = "proton-mail-web-v1";
    for bad in ["not-hex-generation", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"] {
        let scope = EventCursorScope::new("acct", adapter, bad)
            .expect("opaque public scope permits arbitrary generation");
        let bound = scope.clone().bind(String::from("event-safe"));
        assert_eq!(
            codec.encode(bad, &bound, &scope),
            Err(WebEventCursorCodecError::EncodingFailed),
        );
    }
    let valid = "0123456789abcdef0123456789abcdef";
    let scope = EventCursorScope::new("acct", adapter, valid).expect("scope");
    let bound = scope.clone().bind(String::from("event-safe"));
    assert!(codec.encode(valid, &bound, &scope).is_ok());
}

#[test]
fn catalog_cursor_state_requires_whole_page_offset() {
    use crate::mailbox_catalog_page::MailboxCatalogCursorState;
    use crate::mailbox_catalog_page::MailboxCatalogPageError;
    use crate::mailbox_catalog_page::MailboxCatalogPageKind;

    let snapshot = "0123456789abcdef0123456789abcdef";
    let kind = MailboxCatalogPageKind::Labels;
    assert!(MailboxCatalogCursorState::new(snapshot, kind, 10, 10).is_ok());
    assert!(MailboxCatalogCursorState::new(snapshot, kind, 10, 20).is_ok());
    for offset in [1, 9, 11, 19, 21] {
        assert_eq!(
            MailboxCatalogCursorState::new(snapshot, kind, 10, offset),
            Err(MailboxCatalogPageError::InvalidCursorState)
        );
    }
}

#[test]
fn live_javascript_loading_list_never_reads_transitional_row_ids() {
    use std::process::Command;

    if Command::new("node").arg("--version").output().is_err() {
        return;
    }
    let encoded = serde_json::to_string(MailboxListEvidence::expression())
        .expect("serialize content-free list expression");
    let mut source = format!("const expression={encoded};\n");
    source.push_str(
        "
globalThis.location={origin:'https://mail.proton.me'};
globalThis.document={
 querySelector:()=>null,
 querySelectorAll:(selector)=>{
  if(selector.includes('message-list-loading')){
   return [root];
  }
  if(selector.includes('message-list-loaded')){return [];}
  throw Error('pagination must not be inspected during loading');
 }
};
let rowReads=0;
const root={parentElement:null,querySelectorAll:()=>{
 rowReads++;
 throw Error('transitional rows entered CDP');
}};
globalThis.getComputedStyle=()=>({visibility:'visible',opacity:'1'});
const result=eval(expression);
if(!result||!result.loading||result.loaded||
 result.rowIds.length!==0||result.nextPresent||
 result.currentTestId!==null||rowReads!==0){
 throw Error('loading list retained transitional data');
}
",
    );
    let output = Command::new("node")
        .args(["--eval", &source])
        .output()
        .expect("evaluate loading list expression");
    assert!(
        output.status.success(),
        "loading list inspected transitional row metadata: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn equal_time_and_order_cannot_prove_deterministic_message_sort() {
    use super::metadata_pair_matches_time_order;
    use crate::message_list_response::ObservedMessageListResponse;

    let url = "https://mail.proton.me/api/mail/v4/messages";
    let body = concat!(
        r#"{"Stale":0,"Total":2,"Messages":[{"ID":"m-1","Time":10,"Order":4},"#,
        r#"{"ID":"m-2","Time":10,"Order":4}]}"#,
    );
    let observed = ObservedMessageListResponse::parse("GET", url, body)
        .expect("parse synthetic tied metadata");
    let left = &observed.messages()[0];
    let right = &observed.messages()[1];
    assert!(!metadata_pair_matches_time_order(left, right, true));
    assert!(!metadata_pair_matches_time_order(left, right, false));
}

#[test]
fn message_time_sort_requires_proven_primary_or_secondary_order() {
    use super::metadata_pair_matches_time_order;
    use crate::message_list_response::ObservedMessageListResponse;

    type Case = (u64, i64, u64, i64, bool, bool);
    let url = "https://mail.proton.me/api/mail/v4/messages";
    let cases: [Case; 10] = [
        (20, 0, 10, 100, true, true),
        (10, 100, 20, 0, true, false),
        (10, 0, 20, 100, false, true),
        (20, 100, 10, 0, false, false),
        (10, 3, 10, 2, true, true),
        (10, 2, 10, 3, false, true),
        (10, 2, 10, 3, true, false),
        (10, 3, 10, 2, false, false),
        (10, 2, 10, 2, true, false),
        (10, 2, 10, 2, false, false),
    ];
    // jig-ignore-next-line: canonical rustfmt six-part synthetic sort tuple.
    for (left_time, left_order, right_time, right_order, desc, expected) in cases {
        let body = serde_json::json!({
            "Stale": 0u8,"Total": 2u8,
            "Messages":[
                {"ID":"m-1","Time":left_time,"Order":left_order},
                {"ID":"m-2","Time":right_time,"Order":right_order}
            ]
        })
        .to_string();
        let observed = ObservedMessageListResponse::parse("GET", url, &body)
            .expect("parse synthetic ordering pair");
        let pair = observed.messages();
        let actual = metadata_pair_matches_time_order(&pair[0], &pair[1], desc);
        assert_eq!(actual, expected);
    }
}

#[test]
fn outbound_cdp_frame_encoder_uses_scrub_on_drop_bytes() {
    use super::encode_cdp_request_frame;
    use crate::strict_json::SensitiveValue;
    use zeroize::Zeroizing;

    fn requires_guarded_bytes(_: &Zeroizing<Vec<u8>>) {}
    let command = SensitiveValue::from_owned(json!({
        "id": 7u64, "method":"Runtime.evaluate",
        "params":{"expression":"synthetic-private-cdp-parameter"},
        "sessionId":"synthetic-private-session"
    }));
    // jig-ignore-next-line: rustfmt canonical synthetic command encoding.
    let frame = encode_cdp_request_frame(&command).expect("synthetic CDP encoding");
    requires_guarded_bytes(&frame);
    assert_eq!(frame.last().copied(), Some(0));
    let recovered: serde_json::Value =
        serde_json::from_slice(&frame[..frame.len() - 1]).expect("parse frame");
    assert_eq!(recovered, *command);

    // Force multiple serializer growths and a final NUL append. Every
    // replaced frame allocation must pass through the guarded writer.
    let large = "synthetic-private-cdp".repeat(128);
    let large_command = SensitiveValue::from_owned(json!({
        "id": 8u64, "method": "Runtime.evaluate",
        "params": {"expression": large},
        "sessionId": "synthetic-private-session"
    }));
    // jig-ignore-next-line: canonical checked synthetic frame encoder.
    let frame = encode_cdp_request_frame(&large_command).expect("encode large synthetic CDP frame");
    requires_guarded_bytes(&frame);
    assert_eq!(frame.last(), Some(&0));
    // jig-ignore-next-line: canonical synthetic JSON comparison.
    let parsed: serde_json::Value = serde_json::from_slice(&frame[..frame.len() - 1])
        .expect("large synthetic CDP JSON survives guarded growth");
    assert_eq!(parsed, *large_command);
}

#[test]
fn oversized_outbound_cdp_frame_is_rejected_before_encoding() {
    use super::{BrowserDriverError, MAX_FRAME_BYTES, encode_cdp_request_frame};
    use crate::strict_json::SensitiveValue;

    let oversized =
        // jig-ignore-next-line: canonical oversized synthetic command length.
        "synthetic-private-command".repeat(MAX_FRAME_BYTES.div_ceil(24).saturating_add(1));
    let command = SensitiveValue::from_owned(json!({
        "id": 17u64, "method": "Runtime.evaluate",
        "params": {"expression": oversized}
    }));
    assert!(matches!(
        encode_cdp_request_frame(&command),
        Err(BrowserDriverError::Protocol)
    ));
}

#[test]
fn outbound_cdp_frame_ceiling_includes_exact_json_and_one_delimiter() {
    use super::{BrowserDriverError, MAX_FRAME_BYTES, encode_cdp_request_frame};
    use crate::strict_json::SensitiveValue;

    let template = json!({
        "id": 18u64, "method": "Runtime.evaluate",
        "params": {"expression": ""}
    });
    let overhead = serde_json::to_vec(&template)
        .expect("synthetic empty command")
        .len();
    let expression_bytes = MAX_FRAME_BYTES
        .checked_sub(overhead)
        .expect("test command header fits");
    let accepted = SensitiveValue::from_owned(json!({
        "id": 18u64, "method": "Runtime.evaluate",
        "params": {"expression": "x".repeat(expression_bytes)}
    }));
    let frame =
        // jig-ignore-next-line: canonical exact-limit frame regression.
        encode_cdp_request_frame(&accepted).expect("exact maximum synthetic outbound frame");
    assert_eq!(frame.len(), MAX_FRAME_BYTES.saturating_add(1));
    assert_eq!(frame.last(), Some(&0));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&frame[..MAX_FRAME_BYTES])
            .expect("parse maximum synthetic outbound frame"),
        *accepted
    );

    let rejected = SensitiveValue::from_owned(json!({
        "id": 18u64, "method": "Runtime.evaluate",
        "params": {"expression": "x".repeat(expression_bytes.saturating_add(1))}
    }));
    assert!(matches!(
        encode_cdp_request_frame(&rejected),
        Err(BrowserDriverError::Protocol)
    ));
}

#[test]
fn browser_command_and_runtime_returns_keep_scrub_on_drop_ownership() {
    use super::ManagedBrowser;
    use crate::strict_json::SensitiveValue;
    use serde_json::Value;

    // The result and extracted projection must remain guarded after the
    // inbound CDP message itself has been dropped.
    // jig-ignore-next-line: rustfmt canonical private call signature.
    let _: fn(&mut ManagedBrowser, &str, &Value) -> Result<SensitiveValue, BrowserDriverError> =
        ManagedBrowser::call;
    // jig-ignore-next-line: rustfmt canonical private runtime signature.
    let _: fn(&mut ManagedBrowser, &str, &str) -> Result<SensitiveValue, BrowserDriverError> =
        ManagedBrowser::runtime_value;
}

#[test]
fn decoded_cdp_notifications_scrub_parsed_private_fields_on_drop() {
    use super::decode_cdp_frame;
    use crate::strict_json::SensitiveValue;

    fn require_scrubbed(_: &SensitiveValue) {}
    let frame = br#"{"method":"Network.requestWillBeSent","params":{
        "request":{"headers":{"Cookie":"private-session-cookie"}}}}"#;
    let parsed = decode_cdp_frame(frame).expect("strict synthetic CDP frame");
    require_scrubbed(&parsed);
    let cookie = &parsed["params"]["request"]["headers"]["Cookie"];
    assert_eq!(cookie, "private-session-cookie");
    assert!(decode_cdp_frame(br#"{"id":1,"id":2}"#).is_err());
}

#[test]
fn raw_cdp_frames_are_owned_by_scrub_on_drop_buffers() {
    use super::{SensitiveFrameReader, read_frame, read_frame_waiting};
    use std::io::Write as _;
    use std::os::unix::net::UnixStream;
    use zeroize::Zeroizing;

    // Browser CDP frames can carry message metadata and provider replies.
    // The same scrub-on-drop custody must cover both reader entry points.
    fn require_scrubbed(_: &Zeroizing<Vec<u8>>) {}

    for waiting in [false, true] {
        // jig-ignore-next-line: rustfmt canonical synthetic socket pair.
        let (mut sender, receiver) = UnixStream::pair().expect("synthetic pipe");
        sender
            .write_all(b"private-CDP-payload\0")
            .expect("synthetic frame");
        let mut reader = SensitiveFrameReader::new(receiver);
        let frame = if waiting {
            read_frame_waiting(&mut reader)
                .expect("waiting read")
                .expect("frame present")
        } else {
            read_frame(&mut reader).expect("read frame")
        };
        require_scrubbed(&frame);
        assert_eq!(frame.as_slice(), b"private-CDP-payload");
    }
}

#[test]
fn both_cdp_frame_readers_preserve_multi_cache_private_payloads() {
    use super::{SensitiveFrameReader, read_frame, read_frame_waiting};
    use std::io::Write as _;
    use std::os::unix::net::UnixStream;
    use zeroize::Zeroizing;

    // Exceed the eight-KiB read cache, forcing raw frame assembly to grow.
    let private_frame = b"private-mail-metadata".repeat(600);
    for waiting in [false, true] {
        let (mut sender, receiver) = UnixStream::pair().expect("CDP pipe");
        sender.write_all(&private_frame).expect("frame payload");
        sender.write_all(&[0]).expect("NUL frame delimiter");
        let mut reader = SensitiveFrameReader::new(receiver);
        let frame = if waiting {
            read_frame_waiting(&mut reader)
                .expect("waiting read")
                .expect("frame present")
        } else {
            read_frame(&mut reader).expect("read frame")
        };
        let _: &Zeroizing<Vec<u8>> = &frame;
        assert_eq!(frame.as_slice(), private_frame);
        assert!(reader.cache[..reader.offset].iter().all(|byte| *byte == 0));
    }
}

#[test]
fn sensitive_frame_reader_scrubs_consumed_cache_before_next_frame() {
    use super::{SensitiveFrameReader, read_frame, read_frame_waiting};
    use std::io::Write as _;
    use std::os::unix::net::UnixStream;
    use zeroize::Zeroizing;

    fn require_guarded_cache(_: &Zeroizing<[u8; 8192]>) {}

    let pair = UnixStream::pair().expect("synthetic CDP pipe");
    let (mut writer, receiver) = pair;
    writer
        .write_all(b"first-private\0second-private\0")
        .expect("coalesced response frames");
    let mut reader = SensitiveFrameReader::new(receiver);
    require_guarded_cache(&reader.cache);
    assert_eq!(
        &*read_frame(&mut reader).expect("first frame"),
        b"first-private"
    );
    assert!(reader.cache[..reader.offset].iter().all(|byte| *byte == 0));
    assert_eq!(
        &*read_frame_waiting(&mut reader)
            .expect("second waiting frame")
            .expect("second frame"),
        b"second-private"
    );
    assert!(reader.cache.iter().all(|byte| *byte == 0));
}

#[test]
fn sensitive_frame_reader_resumes_after_empty_timeout_and_prior_consumption() {
    use super::{SensitiveFrameReader, read_frame, read_frame_waiting};
    use std::io::Write as _;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let pair = UnixStream::pair().expect("synthetic CDP pipe");
    let (mut writer, receiver) = pair;
    writer.write_all(b"first-private\0").expect("first frame");
    receiver
        .set_read_timeout(Some(Duration::from_millis(25)))
        .expect("set timeout");
    let mut reader = SensitiveFrameReader::new(receiver);
    assert_eq!(
        &*read_frame(&mut reader).expect("read first"),
        b"first-private"
    );
    assert!(
        read_frame_waiting(&mut reader)
            .expect("idle timeout")
            .is_none()
    );
    writer.write_all(b"second-private\0").expect("second frame");
    assert_eq!(
        &*read_frame_waiting(&mut reader)
            .expect("resumed read")
            .expect("second frame"),
        b"second-private"
    );
    assert!(reader.cache.iter().all(|byte| *byte == 0));
}

#[test]
fn sensitive_frame_reader_scrubs_cache_during_partial_deadline_failure() {
    use super::{BrowserDriverError, SensitiveFrameReader, read_frame_waiting};
    use std::io::Write as _;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let pair = UnixStream::pair().expect("synthetic CDP pipe");
    let (mut writer, receiver) = pair;
    writer
        .write_all(b"private-partial")
        .expect("partial response");
    receiver
        .set_read_timeout(Some(Duration::from_millis(30)))
        .expect("set timeout");
    let mut reader = SensitiveFrameReader::new(receiver);
    assert!(matches!(
        read_frame_waiting(&mut reader),
        Err(BrowserDriverError::PipeIo)
    ));
    assert!(reader.cache.iter().all(|byte| *byte == 0));
}

#[test]
fn cdp_frame_readers_bound_total_time_not_each_byte_interval() {
    use super::{SensitiveFrameReader, read_frame, read_frame_waiting};
    use std::io::Write as _;
    use std::os::unix::net::UnixStream;
    use std::thread;
    use std::time::{Duration, Instant};

    // The first byte is ready immediately, but later bytes arrive just before
    // each per-read timeout. A bounded frame must not wait for the terminator.
    for waiting in [false, true] {
        let pair = UnixStream::pair().expect("synthetic CDP pair");
        let (mut writer, reader) = pair;
        writer.write_all(b"x").expect("write first frame byte");
        reader
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("set synthetic read timeout");
        let producer = thread::spawn(move || {
            for _part in 0..15u8 {
                thread::sleep(Duration::from_millis(20));
                if writer.write_all(b"x").is_err() {
                    return;
                }
            }
            let _ignored = writer.write_all(&[0]);
        });
        let mut input = SensitiveFrameReader::new(reader);
        let start = Instant::now();
        let outcome = if waiting {
            read_frame_waiting(&mut input).map(|_frame| ())
        } else {
            read_frame(&mut input).map(|_frame| ())
        };
        assert_eq!(outcome, Err(BrowserDriverError::PipeIo));
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(
            input.get_ref().read_timeout().expect("read timeout"),
            Some(Duration::from_millis(100))
        );
        producer.join().expect("reap synthetic stream producer");
    }
}
