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
use serde_json::{Value, json};

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
