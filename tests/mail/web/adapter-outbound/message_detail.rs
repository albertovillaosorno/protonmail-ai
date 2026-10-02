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
    assert!(message.bcc().is_empty());
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
