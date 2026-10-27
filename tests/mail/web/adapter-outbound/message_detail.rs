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
//   - Synthetic single-message response projection and lifecycle evidence.
// - Must-Not:
//   - Use live mailbox data, credentials, raw headers, bodies, or attachments.
// - Allows:
//   - Exercise exact detail GET gating and content-minimized metadata
//     projection.
// - Split-When:
//   - Browser integration requires separate passive detail-capture fixtures.
// - Merge-When:
//   - Read-workflow integration owns single-message coverage directly.
// - Summary:
//   - Proves single-message metadata projection is bounded and content-minimal.
// - Description:
//   - Uses synthetic decoy secrets to prove unsafe response fields do not
//     escape.
// - Usage:
//   - Run through the `mail_web_adapter` integration-test target.
// - Defaults:
//   - No network, browser, account, or filesystem interaction.
//

//! Synthetic evidence for bounded single-message metadata projection.

use mail_capability_domain::SanitizedAttachmentFilename;
use mail_web_adapter::MessageDetailNetworkCapture;
use mail_web_adapter::MessageDetailNetworkError;
use mail_web_adapter::MessageDetailResponseError;
use mail_web_adapter::ObservedMessageDetailResponse;
use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

// jig-ignore-next-line: canonical rustfmt line.
const MESSAGE_URL: &str = "https://mail.proton.me/api/mail/v4/messages/message-1";

// jig-ignore-next-line: canonical rustfmt line.
fn request_event(session: &str, request_id: &str, method: &str, url: &str) -> Value {
    json!({
        "sessionId": session,
        "method": "Network.requestWillBeSent",
        "params": {
            "requestId": request_id,
            "request": {"method": method, "url": url}
        }
    })
}

// jig-ignore-next-line: canonical rustfmt line.
fn response_event(session: &str, request_id: &str, url: &str, status: u64, mime: &str) -> Value {
    json!({
        "sessionId": session,
        "method": "Network.responseReceived",
        "params": {
            "requestId": request_id,
            "response": {"url": url, "status": status, "mimeType": mime}
        }
    })
}

fn finished_event(session: &str, request_id: &str) -> Value {
    json!({
        "sessionId": session,
        "method": "Network.loadingFinished",
        "params": {"requestId": request_id}
    })
}

fn failed_event(session: &str, request_id: &str) -> Value {
    json!({
        "sessionId": session,
        "method": "Network.loadingFailed",
        "params": {"requestId": request_id}
    })
}

fn detail_body() -> Value {
    json!({
        "Code": 1000,
        "Message": {
            "ID": "message-1",
            "ConversationID": "conversation-9",
            "Subject": "Unicode \u{2713} subject",
            // jig-ignore-next-line: canonical rustfmt line.
            "Sender": {"Name": "Sender", "Address": "sender@example.test", "ContactID": "secret-contact"},
            // jig-ignore-next-line: canonical rustfmt line.
            "ToList": [{"Name": "To", "Address": "to@example.test", "IsProton": 1}],
            "CCList": [{"Name": "Cc", "Address": "cc@example.test"}],
            "BCCList": [],
            "Time": 1_700_000_000u64,
            "Unread": 1,
            "LabelIDs": ["0", "label-a"],
            "MIMEType": "text/html",
            "Attachments": [{
                "ID": "attachment-1",
                "Name": "r\u{e9}sum\u{e9}.pdf",
                "Size": 1234,
                "MIMEType": "application/pdf",
                "KeyPackets": "SECRET-PACKET",
                "Signature": "SECRET-SIGNATURE",
                "data": "SECRET-BYTES",
                "Headers": {"X-Secret": "SECRET-HEADER"}
            }],
            "Body": "SECRET-BODY",
            "Header": "SECRET-RAW-HEADER",
            "ParsedHeaders": {"X-Secret": "SECRET-PARSED-HEADER"},
            "Password": "SECRET-PASSWORD",
            "PasswordHint": "SECRET-HINT",
            "Packages": [{"secret": "SECRET-PACKAGE"}]
        }
    })
}

#[test]
fn exact_detail_projection_keeps_only_bounded_metadata() {
    let body = detail_body().to_string();
    // jig-ignore-next-line: canonical rustfmt line.
    let observed = ObservedMessageDetailResponse::parse("GET", MESSAGE_URL, &body)
        .expect("project exact message detail");
    let message = observed.message();
    assert_eq!(message.id(), "message-1");
    assert_eq!(message.conversation_id(), "conversation-9");
    assert_eq!(message.subject(), "Unicode \u{2713} subject");
    assert_eq!(message.sender().name(), "Sender");
    assert_eq!(message.sender().address(), "sender@example.test");
    assert_eq!(message.to()[0].address(), "to@example.test");
    assert_eq!(message.cc()[0].address(), "cc@example.test");
    assert_eq!(message.bcc().len(), 0);
    assert_eq!(message.time(), 1_700_000_000);
    assert!(message.unread());
    assert_eq!(
        message.label_ids(),
        &[String::from("0"), String::from("label-a")]
    );
    assert_eq!(message.mime_type(), "text/html");
    assert_eq!(message.attachments().len(), 1);
    let attachment = &message.attachments()[0];
    assert_eq!(attachment.id(), Some("attachment-1"));
    assert_eq!(attachment.name(), Some("r\u{e9}sum\u{e9}.pdf"));
    assert_eq!(
        attachment
            .sanitized_name()
            .map(SanitizedAttachmentFilename::as_str),
        Some("r\u{e9}sum\u{e9}.pdf")
    );
    assert_eq!(attachment.size(), Some(1234));
    assert_eq!(attachment.mime_type(), Some("application/pdf"));

    let debug = format!("{observed:?}");
    for secret in [
        "message-1",
        "conversation-9",
        "Unicode \u{2713} subject",
        "sender@example.test",
        "r\u{e9}sum\u{e9}.pdf",
        "SECRET-BODY",
        "SECRET-RAW-HEADER",
        "SECRET-PASSWORD",
        "SECRET-PACKET",
        "SECRET-SIGNATURE",
    ] {
        assert!(!debug.contains(secret));
    }
}

#[test]
fn detail_projection_rejects_endpoint_identity_and_provider_drift() {
    let body = detail_body().to_string();
    for (method, url) in [
        ("POST", MESSAGE_URL),
        ("GET", "https://mail.proton.me/api/mail/v4/messages"),
        (
            "GET",
            "https://mail.proton.me/api/mail/v4/messages/message-1/receipt",
        ),
        (
            "GET",
            "https://mail.proton.me/api/mail/v4/messages/message-1?x=1",
        ),
        (
            "GET",
            "https://account.proton.me/api/mail/v4/messages/message-1",
        ),
    ] {
        assert_eq!(
            ObservedMessageDetailResponse::parse(method, url, &body),
            Err(MessageDetailResponseError::UnexpectedEndpoint)
        );
    }

    let mut wrong_id = detail_body();
    wrong_id["Message"]["ID"] = json!("message-2");
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedMessageDetailResponse::parse("GET", MESSAGE_URL, &wrong_id.to_string()),
        Err(MessageDetailResponseError::IdentityMismatch)
    );
    let mut rejected = detail_body();
    rejected["Code"] = json!(2_500u64);
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedMessageDetailResponse::parse("GET", MESSAGE_URL, &rejected.to_string()),
        Err(MessageDetailResponseError::ProviderRejected)
    );
}

#[test]
fn detail_projection_rejects_duplicates_bad_bounds_and_encoded_body() {
    let mut duplicate_label = detail_body();
    duplicate_label["Message"]["LabelIDs"] = json!(["0", "0"]);
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedMessageDetailResponse::parse("GET", MESSAGE_URL, &duplicate_label.to_string()),
        Err(MessageDetailResponseError::DuplicateIdentifier)
    );

    let mut duplicate_attachment = detail_body();
    let attachment = duplicate_attachment["Message"]["Attachments"][0].clone();
    // jig-ignore-next-line: canonical rustfmt line.
    duplicate_attachment["Message"]["Attachments"] = json!([attachment.clone(), attachment]);
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedMessageDetailResponse::parse("GET", MESSAGE_URL, &duplicate_attachment.to_string()),
        Err(MessageDetailResponseError::DuplicateIdentifier)
    );

    let mut bad_unread = detail_body();
    bad_unread["Message"]["Unread"] = json!(2u64);
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedMessageDetailResponse::parse("GET", MESSAGE_URL, &bad_unread.to_string()),
        Err(MessageDetailResponseError::Malformed)
    );

    let huge = "x".repeat(ObservedMessageDetailResponse::MAX_BODY_BYTES + 1);
    assert_eq!(
        ObservedMessageDetailResponse::parse("GET", MESSAGE_URL, &huge),
        Err(MessageDetailResponseError::BodyTooLarge)
    );

    // jig-ignore-next-line: canonical rustfmt line.
    let envelope = json!({"body": detail_body().to_string(), "base64Encoded": true});
    assert_eq!(
        ObservedMessageDetailResponse::parse_cdp_body("message-1", &envelope),
        Err(MessageDetailResponseError::UnsupportedEncoding)
    );
}

#[test]
fn detail_network_capture_tracks_only_exact_get_lifecycle() {
    let mut capture = MessageDetailNetworkCapture::new("session-a");
    capture
        .observe(&request_event(
            "other-session",
            "foreign",
            "GET",
            MESSAGE_URL,
        ))
        .expect("ignore foreign session");
    capture
        .observe(&request_event(
            "session-a",
            "list",
            "GET",
            "https://mail.proton.me/api/mail/v4/messages?Page=0",
        ))
        .expect("ignore list endpoint");
    capture
        .observe(&request_event("session-a", "mutate", "PUT", MESSAGE_URL))
        .expect("ignore mutation endpoint");
    capture
        .observe(&request_event("session-a", "detail", "GET", MESSAGE_URL))
        .expect("track exact detail GET");
    assert_eq!(capture.tracked_request_count(), 1);
    capture
        .observe(&response_event(
            "session-a",
            "detail",
            MESSAGE_URL,
            200,
            "application/json",
        ))
        .expect("accept exact response");
    capture
        .observe(&finished_event("session-a", "detail"))
        .expect("finish exact response");
    assert_eq!(
        capture.take_finished_requests(),
        vec![(String::from("detail"), String::from("message-1"))]
    );
    assert_eq!(capture.tracked_request_count(), 0);
    let debug = format!("{capture:?}");
    assert!(!debug.contains("session-a"));
    assert!(!debug.contains("message-1"));
}

#[test]
fn detail_network_capture_rejects_redirect_and_allows_app_retry() {
    let mut capture = MessageDetailNetworkCapture::new("session-a");
    capture
        .observe(&request_event("session-a", "retry", "GET", MESSAGE_URL))
        .expect("track first attempt");
    capture
        .observe(&failed_event("session-a", "retry"))
        .expect("discard app-owned failed attempt");
    assert_eq!(capture.tracked_request_count(), 0);
    capture
        .observe(&request_event("session-a", "retry-2", "GET", MESSAGE_URL))
        .expect("track app-owned retry");
    assert_eq!(
        capture.observe(&request_event(
            "session-a",
            "retry-2",
            "GET",
            "https://mail.proton.me/api/mail/v4/messages/other-message"
        )),
        Err(MessageDetailNetworkError::RedirectedAway)
    );

    let mut redirected = MessageDetailNetworkCapture::new("session-a");
    redirected
        .observe(&request_event("session-a", "redirect", "GET", MESSAGE_URL))
        .expect("track redirect source");
    assert_eq!(
        redirected.observe(&request_event(
            "session-a",
            "redirect",
            "GET",
            "https://mail.proton.me/inbox"
        )),
        Err(MessageDetailNetworkError::RedirectedAway)
    );
}

#[test]
fn detail_projection_sanitizes_provider_attachment_filename() {
    let mut body = detail_body();
    body["Message"]["Attachments"][0]["Name"] = json!("../../CON .txt");
    // jig-ignore-next-line: canonical rustfmt line.
    let observed = ObservedMessageDetailResponse::parse("GET", MESSAGE_URL, &body.to_string())
        .expect("project attachment filename safely");
    let attachment = &observed.message().attachments()[0];
    assert_eq!(attachment.name(), Some("../../CON .txt"));
    assert_eq!(
        attachment
            .sanitized_name()
            .map(SanitizedAttachmentFilename::as_str),
        Some("___.._CON .txt")
    );
    let debug = format!("{attachment:?}");
    assert!(!debug.contains("CON"));
}

#[test]
fn attachment_descriptor_accepts_unaddressable_optional_metadata() {
    let mut body = detail_body();
    // jig-ignore-next-line: canonical rustfmt line.
    body["Message"]["Attachments"] = json!([{"Name": null, "Size": null, "MIMEType": null}]);
    // jig-ignore-next-line: canonical rustfmt line.
    let observed = ObservedMessageDetailResponse::parse("GET", MESSAGE_URL, &body.to_string())
        .expect("optional attachment metadata remains representable");
    let attachment = &observed.message().attachments()[0];
    assert_eq!(attachment.id(), None);
    assert_eq!(attachment.name(), None);
    assert_eq!(attachment.sanitized_name(), None);
    assert_eq!(attachment.size(), None);
    assert_eq!(attachment.mime_type(), None);
}

#[test]
fn detail_network_capture_bounds_unfinished_requests() {
    let mut capture = MessageDetailNetworkCapture::new("session-a");
    for index in 0..16u8 {
        let request_id = format!("detail-{index}");
        // jig-ignore-next-line: canonical rustfmt line.
        let url = format!("https://mail.proton.me/api/mail/v4/messages/message-{index}");
        capture
            .observe(&request_event("session-a", &request_id, "GET", &url))
            .expect("within detail request capacity");
    }
    assert_eq!(capture.tracked_request_count(), 16);
    assert_eq!(
        capture.observe(&request_event(
            "session-a",
            "detail-overflow",
            "GET",
            "https://mail.proton.me/api/mail/v4/messages/message-overflow"
        )),
        Err(MessageDetailNetworkError::CapacityExceeded)
    );
}

#[test]
fn detail_network_response_must_preserve_message_identity_and_json_status() {
    for (url, status, mime) in [
        (
            "https://mail.proton.me/api/mail/v4/messages/message-2",
            200,
            "application/json",
        ),
        (MESSAGE_URL, 204, "application/json"),
        (MESSAGE_URL, 200, "text/html"),
    ] {
        let mut capture = MessageDetailNetworkCapture::new("session-a");
        capture
            .observe(&request_event("session-a", "detail", "GET", MESSAGE_URL))
            .expect("track exact request");
        assert_eq!(
            // jig-ignore-next-line: canonical rustfmt line.
            capture.observe(&response_event("session-a", "detail", url, status, mime)),
            Err(MessageDetailNetworkError::ResponseRejected)
        );
    }
}

static DETAIL_BROWSER_TEST_LOCK: Mutex<()> = Mutex::new(());

fn detail_browser_root(label: &str) -> PathBuf {
    use std::env;
    use std::process;

    env::temp_dir().join(format!(
        "protonmail-ai-message-detail-{label}-{}",
        process::id()
    ))
}

// jig-ignore-next-line: canonical rustfmt line.
fn fake_detail_browser(root: &Path, emit_detail: bool, late_during_disable: bool) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let script = root.join("fake-browser");
    let log = root.join("detail-log.txt");
    let template = r#"#!/usr/bin/env bash
set -eu
while IFS= read -r -d '' message <&3; do
  id=$(printf '%s' "$message" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$message" in
    *'Browser.getVersion'*)
      printf '{"id":%s,"result":{"product":"FakeChrome/1"}}\0' "$id" >&4;;
    *'Target.getTargets'*)
      target='[{"targetId":"page-1","type":"page",'
      target+='"url":"https://mail.proton.me/u/0/inbox"}]'
      printf '{"id":%s,"result":{"targetInfos":%s}}\0' "$id" "$target" >&4;;
    *'Target.attachToTarget'*)
      printf '{"id":%s,"result":{"sessionId":"session-1"}}\0' "$id" >&4;;
    *'Runtime.evaluate'*)
      value='{"protocol":"https:","hostname":"mail.proton.me","port":""}'
      printf '{"id":%s,"result":{"result":{"value":%s}}}\0' "$id" "$value" >&4;;
    *'DOM.getDocument'*)
      printf '{"id":%s,"result":{"root":{"nodeId":1}}}\0' "$id" >&4;;
    *'Accessibility.queryAXTree'*)
      case "$message" in
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        *'"role":"navigation"'*|*'"role":"search"'*) nodes='[{"ignored":false}]';;
        *'"role":"dialog"'*|*'"role":"alertdialog"'*) nodes='[]';;
        *) exit 91;;
      esac
      printf '{"id":%s,"result":{"nodes":%s}}\0' "$id" "$nodes" >&4;;
    *'Network.enable'*)
      printf 'enable\n' >> '__LOG__'
      printf '{"id":%s,"result":{}}\0' "$id" >&4
      if [ '__EMIT_DETAIL__' = 'true' ]; then
        url='https://mail.proton.me/api/mail/v4/messages/message-1'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        request='{"sessionId":"session-1","method":"Network.requestWillBeSent","params":{'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        request+='"requestId":"detail-1","request":{"method":"GET","url":"'"$url"'",'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        request+='"headers":{"Authorization":"Bearer secret","Cookie":"secret-cookie"}}}}'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        response='{"sessionId":"session-1","method":"Network.responseReceived","params":{'
        response+='"requestId":"detail-1","response":{"url":"'"$url"'",'
        response+='"status":200,"mimeType":"application/json",'
        response+='"headers":{"Set-Cookie":"secret-cookie"}}}}'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        finished='{"sessionId":"session-1","method":"Network.loadingFinished","params":{'
        finished+='"requestId":"detail-1"}}'
        printf '%s\0%s\0%s\0' "$request" "$response" "$finished" >&4
      fi;;
    *'Network.getResponseBody'*'"requestId":"detail-1"'*)
      printf 'body\n' >> '__LOG__'
      body='{"Code":1000,"Message":{"ID":"message-1",'
      body+='"ConversationID":"conversation-1","Subject":"subject",'
      body+='"Sender":{"Name":"Sender","Address":"sender@example.test"},'
      body+='"ToList":[],"CCList":[],"BCCList":[],"Time":1700000000,'
      body+='"Unread":0,"LabelIDs":["0"],"MIMEType":"text/plain",'
      body+='"Attachments":[],"Body":"SECRET-BODY","Header":"SECRET-HEADER"}}'
      printf '{"id":%s,"result":{"body":"%s","base64Encoded":false}}\0' \
        "$id" "${body//\"/\\\"}" >&4;;
    *'Network.disable'*)
      printf 'disable\n' >> '__LOG__'
      if [ '__LATE_DETAIL__' = 'true' ]; then
        url='https://mail.proton.me/api/mail/v4/messages/late-message'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        request='{"sessionId":"session-1","method":"Network.requestWillBeSent","params":{'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        request+='"requestId":"detail-late","request":{"method":"GET","url":"'"$url"'"}}}'
        printf '%s\0' "$request" >&4
      fi
      printf '{"id":%s,"result":{}}\0' "$id" >&4;;
    *'Target.detachFromTarget'*)
      printf '{"id":%s,"result":{}}\0' "$id" >&4;;
    *'Page.reload'*) exit 94;;
    *) exit 92;;
  esac
done
"#;
    let body = template
        .replace("__LOG__", &log.display().to_string())
        .replace(
            "__EMIT_DETAIL__",
            if emit_detail { "true" } else { "false" },
        )
        .replace(
            "__LATE_DETAIL__",
            if late_during_disable { "true" } else { "false" },
        );
    fs::write(&script, body).expect("write fake detail browser");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
        .expect("chmod fake detail browser");
    script
}

#[test]
fn managed_browser_passively_observes_detail_without_navigation() {
    let _guard = DETAIL_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic detail browser tests");
    let root = detail_browser_root("passive");
    fs::create_dir_all(&root).expect("create passive detail root");
    let browser = fake_detail_browser(&root, true, false);
    let plan = ManagedBrowserPlan::under_data_home(
        browser.to_str().expect("passive detail browser path UTF-8"),
        &root.join("data"),
    )
    .expect("build passive detail plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch passive detail browser");
    let page = managed.provider_page().expect("discover passive Mail page");
    let observed = managed
        .observe_passive_message_detail(&page, Duration::from_secs(1))
        .expect("observe browser-owned detail request")
        .expect("detail request should arrive");
    assert_eq!(observed.message().id(), "message-1");
    assert_eq!(observed.message().subject(), "subject");
    drop(managed);
    // jig-ignore-next-line: canonical rustfmt line.
    let log = fs::read_to_string(root.join("detail-log.txt")).expect("read passive detail log");
    assert_eq!(log, "enable\nbody\ndisable\n");
    fs::remove_dir_all(&root).expect("remove passive detail root");
}

#[test]
fn managed_browser_passive_detail_timeout_performs_no_provider_action() {
    let _guard = DETAIL_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic detail browser tests");
    let root = detail_browser_root("timeout");
    fs::create_dir_all(&root).expect("create timeout detail root");
    let browser = fake_detail_browser(&root, false, false);
    let plan = ManagedBrowserPlan::under_data_home(
        browser.to_str().expect("timeout detail browser path UTF-8"),
        &root.join("data"),
    )
    .expect("build timeout detail plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch timeout detail browser");
    let page = managed.provider_page().expect("discover timeout Mail page");
    let observed = managed
        .observe_passive_message_detail(&page, Duration::from_millis(25))
        .expect("clean passive detail timeout");
    assert_eq!(observed, None);
    assert_eq!(
        managed.observe_passive_message_detail(&page, Duration::from_secs(31)),
        Err(BrowserDriverError::MessageDetailWaitTooLong)
    );
    drop(managed);
    // jig-ignore-next-line: canonical rustfmt line.
    let log = fs::read_to_string(root.join("detail-log.txt")).expect("read timeout detail log");
    assert_eq!(log, "enable\ndisable\n");
    fs::remove_dir_all(&root).expect("remove timeout detail root");
}

#[test]
fn detail_started_during_network_disable_fails_closed() {
    let _guard = DETAIL_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic detail browser tests");
    let root = detail_browser_root("late-disable");
    fs::create_dir_all(&root).expect("create late-disable detail root");
    let browser = fake_detail_browser(&root, true, true);
    let plan = ManagedBrowserPlan::under_data_home(
        browser
            .to_str()
            .expect("late-disable detail browser path UTF-8"),
        &root.join("data"),
    )
    .expect("build late-disable detail plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch late-disable browser");
    let page = managed
        .provider_page()
        .expect("discover late-disable Mail page");
    assert_eq!(
        managed.observe_passive_message_detail(&page, Duration::from_secs(1)),
        Err(BrowserDriverError::MessageDetailAmbiguous)
    );
    drop(managed);
    let log =
        // jig-ignore-next-line: canonical rustfmt line.
        fs::read_to_string(root.join("detail-log.txt")).expect("read late-disable detail log");
    assert_eq!(log, "enable\nbody\ndisable\n");
    fs::remove_dir_all(&root).expect("remove late-disable detail root");
}

#[test]
fn consumed_detail_request_ids_reject_all_late_lifecycle_events() {
    let mut capture = MessageDetailNetworkCapture::new("session-a");
    capture
        .observe(&request_event("session-a", "detail", "GET", MESSAGE_URL))
        .expect("start app-owned read");
    capture
        .observe(&response_event(
            "session-a",
            "detail",
            MESSAGE_URL,
            200,
            "application/json",
        ))
        .expect("observe exact read response");
    capture
        .observe(&finished_event("session-a", "detail"))
        .expect("complete exact read response");
    assert_eq!(
        capture.take_finished_requests(),
        vec![(String::from("detail"), String::from("message-1"))]
    );
    assert_eq!(capture.tracked_request_count(), 0);
    let debug = format!("{capture:?}");
    assert!(!debug.contains("detail"));
    assert!(!debug.contains("message-1"));
    for late in [
        request_event("session-a", "detail", "GET", MESSAGE_URL),
        request_event("session-a", "detail", "POST", MESSAGE_URL),
        // jig-ignore-next-line: canonical rustfmt line.
        response_event("session-a", "detail", MESSAGE_URL, 200, "application/json"),
        finished_event("session-a", "detail"),
        failed_event("session-a", "detail"),
    ] {
        assert_eq!(
            capture.observe(&late),
            Err(MessageDetailNetworkError::InvalidSequence)
        );
    }
    assert_eq!(capture.take_finished_requests().len(), 0);
}

#[test]
fn consumed_detail_request_markers_count_toward_capacity() {
    let mut capture = MessageDetailNetworkCapture::new("session-a");
    for index in 0u8..16 {
        let request_id = format!("sensitive-{index}");
        capture
            // jig-ignore-next-line: canonical rustfmt line.
            .observe(&request_event("session-a", &request_id, "GET", MESSAGE_URL))
            .expect("start bounded request");
        capture
            .observe(&response_event(
                "session-a",
                &request_id,
                MESSAGE_URL,
                200,
                "application/json",
            ))
            .expect("match completed response");
        capture
            .observe(&finished_event("session-a", &request_id))
            .expect("finish bounded response");
        assert_eq!(
            capture.take_finished_requests(),
            vec![(request_id, String::from("message-1"))]
        );
        assert_eq!(capture.tracked_request_count(), 0);
    }
    assert!(!format!("{capture:?}").contains("sensitive-"));
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        capture.observe(&request_event("session-a", "overflow", "GET", MESSAGE_URL)),
        Err(MessageDetailNetworkError::CapacityExceeded)
    );
}

#[test]
fn completed_detail_id_reused_during_disable_fails_closed() {
    // jig-ignore-next-line: canonical rustfmt line.
    use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};
    let _guard = DETAIL_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic browser fixture");
    let root = detail_browser_root("reused-during-disable");
    fs::create_dir_all(&root).expect("create synthetic browser root");
    let browser = fake_detail_browser(&root, true, true);
    // jig-ignore-next-line: canonical rustfmt line.
    let script = fs::read_to_string(&browser).expect("read synthetic browser fixture");
    assert!(script.contains("detail-late"));
    fs::write(&browser, script.replace("detail-late", "detail-1"))
        .expect("install replayed synthetic CDP request ID");
    let plan = ManagedBrowserPlan::under_data_home(
        browser.to_str().expect("synthetic browser path UTF-8"),
        &root.join("data"),
    )
    .expect("build synthetic browser plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch synthetic browser");
    let page = managed.provider_page().expect("discover fake Mail page");
    assert_eq!(
        managed.observe_passive_message_detail(&page, Duration::from_secs(1)),
        Err(BrowserDriverError::MessageDetailNetwork(
            MessageDetailNetworkError::InvalidSequence,
        ))
    );
    managed
        .require_mail_shell(&page)
        .expect("safe Mail shell remains inspectable after replay rejection");
    drop(managed);
    // jig-ignore-next-line: canonical rustfmt line.
    let log = fs::read_to_string(root.join("detail-log.txt")).expect("read Network lifecycle");
    assert_eq!(log, "enable\nbody\ndisable\n");
    fs::remove_dir_all(&root).expect("remove synthetic browser root");
}

#[test]
fn exact_detail_request_id_is_bounded_before_tracking() {
    for id in [String::new(), "x".repeat(513)] {
        let mut capture = MessageDetailNetworkCapture::new("session-a");
        assert_eq!(
            // jig-ignore-next-line: canonical rustfmt line.
            capture.observe(&request_event("session-a", &id, "GET", MESSAGE_URL)),
            Err(MessageDetailNetworkError::MalformedEvent)
        );
        assert_eq!(capture.tracked_request_count(), 0);
        assert_eq!(capture.take_finished_requests().len(), 0);
    }
    let mut capture = MessageDetailNetworkCapture::new("session-a");
    capture
        .observe(&request_event(
            "session-a",
            &"x".repeat(1024),
            "GET",
            "https://mail.proton.me/api/mail/v4/messages?Page=0",
        ))
        .expect("unrelated browser traffic is ignored");
    assert_eq!(capture.tracked_request_count(), 0);
}

#[test]
fn completed_response_cannot_be_erased_by_late_failure_before_consumption() {
    let mut capture = MessageDetailNetworkCapture::new("session-a");
    capture
        .observe(&request_event("session-a", "ready", "GET", MESSAGE_URL))
        .expect("start exact GET");
    capture
        .observe(&response_event(
            "session-a",
            "ready",
            MESSAGE_URL,
            200,
            "application/json",
        ))
        .expect("match response");
    capture
        .observe(&finished_event("session-a", "ready"))
        .expect("finish response");
    assert_eq!(
        capture.observe(&failed_event("session-a", "ready")),
        Err(MessageDetailNetworkError::InvalidSequence),
    );
    assert_eq!(
        capture.take_finished_requests(),
        [(String::from("ready"), String::from("message-1"))]
    );
}

#[test]
fn detail_url_backslash_is_not_a_safe_opaque_id_separator() {
    let mut capture = MessageDetailNetworkCapture::new("session-a");
    let unsafe_url = MESSAGE_URL.replace("message-1", "message-1\\adjacent");
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        capture.observe(&request_event("session-a", "bad-path", "GET", &unsafe_url)),
        Err(MessageDetailNetworkError::MalformedEvent)
    );
    assert_eq!(capture.take_finished_requests().len(), 0);
}

#[test]
fn detail_projection_rejects_unsafe_route_bound_metadata_ids() {
    for bad in [
        "encoded%2Fslash",
        "%2e",
        "%2E%2E",
        "direction\u{202e}flip",
        "invisible\u{200b}join",
        "isolated\u{2066}id\u{2069}",
        "bad/id",
        "bad?id",
        "bad#id",
        "bad\\id",
        "bad id",
        "bad\nid",
        "bad\tid",
        "bad\rid",
        "bad\u{a0}id",
        "bad\u{7f}id",
        ".",
        "..",
    ] {
        let mut conversation = detail_body();
        conversation["Message"]["ConversationID"] = json!(bad);
        assert_eq!(
            // jig-ignore-next-line: canonical rustfmt line.
            ObservedMessageDetailResponse::parse("GET", MESSAGE_URL, &conversation.to_string()),
            Err(MessageDetailResponseError::Malformed)
        );
        let mut labels = detail_body();
        labels["Message"]["LabelIDs"] = json!([bad]);
        assert_eq!(
            // jig-ignore-next-line: canonical rustfmt line.
            ObservedMessageDetailResponse::parse("GET", MESSAGE_URL, &labels.to_string()),
            Err(MessageDetailResponseError::Malformed)
        );
        let mut attachments = detail_body();
        attachments["Message"]["Attachments"][0]["ID"] = json!(bad);
        assert_eq!(
            // jig-ignore-next-line: canonical rustfmt line.
            ObservedMessageDetailResponse::parse("GET", MESSAGE_URL, &attachments.to_string()),
            Err(MessageDetailResponseError::Malformed)
        );
        let url = format!("https://mail.proton.me/api/mail/v4/messages/{bad}");
        assert_eq!(
            // jig-ignore-next-line: canonical rustfmt line.
            ObservedMessageDetailResponse::parse("GET", &url, &detail_body().to_string()),
            Err(MessageDetailResponseError::UnexpectedEndpoint)
        );
        let mut capture = MessageDetailNetworkCapture::new("session-a");
        assert_eq!(
            capture.observe(&request_event("session-a", "bad", "GET", &url)),
            Err(MessageDetailNetworkError::MalformedEvent)
        );
    }
}

#[test]
fn detail_projection_keeps_printable_opaque_ids_and_content_fields() {
    let mut body = detail_body();
    body["Message"]["ID"] = json!("opaque+_~=");
    body["Message"]["ConversationID"] = json!("parent+_~=");
    body["Message"]["LabelIDs"] = json!(["label+_~="]);
    body["Message"]["Attachments"][0]["ID"] = json!("attach+_~=");
    let url = "https://mail.proton.me/api/mail/v4/messages/opaque+_~=";
    // jig-ignore-next-line: canonical rustfmt line.
    let projected = ObservedMessageDetailResponse::parse("GET", url, &body.to_string())
        .expect("valid opaque detail identities remain available");
    assert_eq!(projected.message().id(), "opaque+_~=");
    assert_eq!(projected.message().conversation_id(), "parent+_~=");
    assert_eq!(projected.message().label_ids(), ["label+_~="]);
    assert_eq!(
        projected.message().attachments()[0].id(),
        Some("attach+_~=")
    );
    assert_eq!(projected.message().subject(), "Unicode \u{2713} subject");
}

#[test]
fn message_and_attachment_mime_metadata_reject_header_controls() {
    for invalid in ["text/plain\r\nX-Test: injected", "not-a-media-type"] {
        for field in ["message", "attachment"] {
            let mut body = detail_body();
            if field == "message" {
                body["Message"]["MIMEType"] = json!(invalid);
            } else {
                body["Message"]["Attachments"][0]["MIMEType"] = json!(invalid);
            }
            let observed =
                // jig-ignore-next-line: canonical rustfmt metadata parser call.
                ObservedMessageDetailResponse::parse("GET", MESSAGE_URL, &body.to_string());
            assert_eq!(observed, Err(MessageDetailResponseError::Malformed));
        }
    }
}

#[test]
fn media_type_validation_preserves_standard_mime_parameters() {
    // jig-ignore-next-line: indivisible synthetic standard MIME value.
    const MIME: &str = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    let mut body = detail_body();
    body["Message"]["MIMEType"] = json!("text/plain; charset=UTF-8");
    body["Message"]["Attachments"][0]["MIMEType"] = json!(MIME);
    let raw = body.to_string();
    // jig-ignore-next-line: canonical rustfmt projection call.
    let projected = ObservedMessageDetailResponse::parse("GET", MESSAGE_URL, &raw)
        .expect("valid message and attachment MIME values");
    assert_eq!(projected.message().mime_type(), "text/plain; charset=UTF-8");
    assert_eq!(projected.message().attachments()[0].mime_type(), Some(MIME));
}

#[test]
fn message_recipient_fields_reject_control_character_injection() {
    for (pointer, value) in [
        (
            "/Message/Sender/Address",
            "sender@example.test\r\nBcc:evil@example.test",
        ),
        ("/Message/Sender/Name", "Sender\nBcc: evil@example.test"),
        ("/Message/ToList/0/Address", "to@example.test\u{0}"),
        ("/Message/ToList/0/Name", "Recipient\u{7f}"),
    ] {
        let mut body = detail_body();
        let field = body
            .pointer_mut(pointer)
            .expect("synthetic recipient field");
        *field = json!(value);
        let raw = body.to_string();
        // jig-ignore-next-line: canonical rustfmt read-boundary call.
        let observed = ObservedMessageDetailResponse::parse("GET", MESSAGE_URL, &raw);
        assert_eq!(observed, Err(MessageDetailResponseError::Malformed));
    }
}

#[test]
fn message_detail_body_envelope_rejects_unexpected_cdp_fields() {
    let mut result = json!({
        "body":detail_body().to_string(),"base64Encoded":false
    });
    // jig-ignore-next-line: canonical rustfmt detail envelope test.
    assert!(ObservedMessageDetailResponse::parse_cdp_body("message-1", &result).is_ok());
    result["unrecognized"] = json!(true);
    assert_eq!(
        ObservedMessageDetailResponse::parse_cdp_body("message-1", &result),
        Err(MessageDetailResponseError::Malformed)
    );
}
