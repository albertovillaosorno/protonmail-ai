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
//   - Synthetic complete-conversation membership projection evidence.
// - Must-Not:
//   - Use live mailbox data, bodies, headers, credentials, or network access.
// - Allows:
//   - Prove exact conversation/member identity and count completeness.
// - Split-When:
//   - Browser orchestration or plaintext thread reading needs separate
//     fixtures.
// - Merge-When:
//   - One thread acceptance suite owns membership and content evidence.
// - Summary:
//   - Proves exact unparameterized conversation responses fail closed.
// - Description:
//   - Uses synthetic secret-bearing fields to verify content minimization.
// - Usage:
//   - Run through the `mail_web_adapter` integration-test target.
// - Defaults:
//   - Synthetic JSON only; no filesystem, browser, account, or network access.
//

//! Synthetic evidence for complete bounded conversation membership.

use mail_web_adapter::ConversationDetailNetworkCapture;
use mail_web_adapter::ConversationDetailNetworkError;
use mail_web_adapter::ConversationDetailResponseError;
use mail_web_adapter::ObservedConversationDetailResponse;
use serde_json::{Value, json};

// jig-ignore-next-line: canonical rustfmt line.
const URL: &str = "https://mail.proton.me/api/mail/v4/conversations/conversation-1";

// jig-ignore-next-line: canonical rustfmt line.
fn request_event(session: &str, request_id: &str, method: &str, url: &str) -> Value {
    json!({
        "sessionId": session,
        "method": "Network.requestWillBeSent",
        "params": {
            "requestId": request_id,
            "request": {
                "method": method,
                "url": url,
                // jig-ignore-next-line: canonical rustfmt line.
                "headers": {"Authorization": "Bearer SECRET", "Cookie": "SECRET"}
            }
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
            "response": {
                "url": url,
                "status": status,
                "mimeType": mime,
                "headers": {"Set-Cookie": "SECRET"}
            }
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

fn conversation_body() -> Value {
    json!({
        "Code": 1000,
        "Conversation": {
            "ID": "conversation-1",
            "Subject": "SECRET SUBJECT",
            "NumMessages": 2,
            "Senders": [{"Address": "secret@example.test"}]
        },
        "Messages": [
            {
                "ID": "message-2",
                "ConversationID": "conversation-1",
                "Time": 1_700_000_002u64,
                "Subject": "SECRET MESSAGE 2",
                "Body": "SECRET BODY 2",
                "Header": "SECRET HEADER 2",
                "ParsedHeaders": {"X-Secret": "SECRET PARSED 2"},
                "Attachments": [{"data": "SECRET ATTACHMENT 2"}],
                "Password": "SECRET PASSWORD 2"
            },
            {
                "ID": "message-1",
                "ConversationID": "conversation-1",
                "Time": 1_700_000_001u64,
                "Subject": "SECRET MESSAGE 1",
                "Body": "SECRET BODY 1",
                "Header": "SECRET HEADER 1",
                "KeyPackets": "SECRET KEY PACKET"
            }
        ]
    })
}

#[test]
fn complete_projection_keeps_only_identity_count_and_provider_order() {
    let observed =
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedConversationDetailResponse::parse("GET", URL, &conversation_body().to_string())
            .expect("project complete conversation membership");
    let conversation = observed.conversation();
    assert_eq!(conversation.conversation_id(), "conversation-1");
    assert_eq!(conversation.reported_message_count(), 2);
    assert_eq!(conversation.members()[0].message_id(), "message-2");
    assert_eq!(conversation.members()[0].time(), 1_700_000_002);
    assert_eq!(conversation.members()[1].message_id(), "message-1");
    let debug = format!("{observed:?}");
    for secret in [
        "conversation-1",
        "message-1",
        "message-2",
        "SECRET SUBJECT",
        "SECRET BODY 1",
        "SECRET HEADER 2",
        "secret@example.test",
        "SECRET ATTACHMENT 2",
        "SECRET PASSWORD 2",
        "SECRET KEY PACKET",
    ] {
        assert!(!debug.contains(secret));
    }
}

#[test]
fn projection_rejects_parameterized_neighbor_and_identity_drift() {
    let body = conversation_body().to_string();
    for (method, url) in [
        ("POST", URL),
        ("GET", "https://mail.proton.me/api/mail/v4/conversations"),
        (
            "GET",
            // jig-ignore-next-line: canonical rustfmt line.
            "https://mail.proton.me/api/mail/v4/conversations/conversation-1?MessageID=message-1",
        ),
        (
            "GET",
            // jig-ignore-next-line: canonical rustfmt line.
            "https://account.proton.me/api/mail/v4/conversations/conversation-1",
        ),
    ] {
        assert_eq!(
            ObservedConversationDetailResponse::parse(method, url, &body),
            Err(ConversationDetailResponseError::UnexpectedEndpoint)
        );
    }
    let mut wrong = conversation_body();
    wrong["Conversation"]["ID"] = json!("conversation-other");
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedConversationDetailResponse::parse("GET", URL, &wrong.to_string()),
        Err(ConversationDetailResponseError::IdentityMismatch)
    );
}

#[test]
fn projection_requires_exact_reported_member_count() {
    let mut short = conversation_body();
    short["Messages"]
        .as_array_mut()
        .expect("messages array")
        .pop();
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedConversationDetailResponse::parse("GET", URL, &short.to_string()),
        Err(ConversationDetailResponseError::IncompleteConversation)
    );
    let mut missing = conversation_body();
    missing
        .as_object_mut()
        .expect("root object")
        .remove("Messages");
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedConversationDetailResponse::parse("GET", URL, &missing.to_string()),
        Err(ConversationDetailResponseError::IncompleteConversation)
    );
}

#[test]
fn projection_rejects_duplicate_or_cross_conversation_members() {
    let mut duplicate = conversation_body();
    duplicate["Messages"][1]["ID"] = json!("message-2");
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedConversationDetailResponse::parse("GET", URL, &duplicate.to_string()),
        Err(ConversationDetailResponseError::DuplicateMessageId)
    );
    let mut wrong_parent = conversation_body();
    wrong_parent["Messages"][1]["ConversationID"] = json!("conversation-other");
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedConversationDetailResponse::parse("GET", URL, &wrong_parent.to_string()),
        Err(ConversationDetailResponseError::ParentMismatch)
    );
}

#[test]
fn projection_bounds_count_body_and_cdp_encoding() {
    let mut excessive = conversation_body();
    excessive["Conversation"]["NumMessages"] = json!(513u64);
    excessive["Messages"] = Value::Array(Vec::new());
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedConversationDetailResponse::parse("GET", URL, &excessive.to_string()),
        Err(ConversationDetailResponseError::TooManyMessages)
    );
    // jig-ignore-next-line: canonical rustfmt line.
    let huge = "x".repeat(ObservedConversationDetailResponse::MAX_BODY_BYTES + 1);
    assert_eq!(
        ObservedConversationDetailResponse::parse("GET", URL, &huge),
        Err(ConversationDetailResponseError::BodyTooLarge)
    );
    // jig-ignore-next-line: canonical rustfmt line.
    let envelope = json!({"body": conversation_body().to_string(), "base64Encoded": true});
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedConversationDetailResponse::parse_cdp_body("conversation-1", &envelope),
        Err(ConversationDetailResponseError::UnsupportedEncoding)
    );
}

#[test]
fn network_capture_tracks_only_exact_unparameterized_get() {
    let mut capture = ConversationDetailNetworkCapture::new("session-a");
    capture
        .observe(&request_event("other", "foreign", "GET", URL))
        .expect("ignore foreign session");
    capture
        .observe(&request_event(
            "session-a",
            "parameterized",
            "GET",
            // jig-ignore-next-line: canonical rustfmt line.
            "https://mail.proton.me/api/mail/v4/conversations/conversation-1?MessageID=message-1",
        ))
        .expect_err("parameterized conversation shape fails closed");
    let mut capture = ConversationDetailNetworkCapture::new("session-a");
    capture
        .observe(&request_event("session-a", "detail", "GET", URL))
        .expect("track exact conversation GET");
    capture
        .observe(&response_event(
            "session-a",
            "detail",
            URL,
            200,
            "application/json",
        ))
        .expect("accept exact response");
    capture
        .observe(&finished_event("session-a", "detail"))
        .expect("finish exact response");
    assert_eq!(
        capture.take_finished_requests(),
        vec![(String::from("detail"), String::from("conversation-1"))]
    );
    assert_eq!(capture.tracked_request_count(), 0);
    assert!(!format!("{capture:?}").contains("conversation-1"));
}

#[test]
fn network_capture_allows_failed_app_retry_and_rejects_redirect() {
    let mut capture = ConversationDetailNetworkCapture::new("session-a");
    capture
        .observe(&request_event("session-a", "retry", "GET", URL))
        .expect("track first attempt");
    capture
        .observe(&failed_event("session-a", "retry"))
        .expect("discard failed app attempt");
    assert_eq!(capture.tracked_request_count(), 0);
    capture
        .observe(&request_event("session-a", "retry-2", "GET", URL))
        .expect("track retry");
    assert_eq!(
        capture.observe(&request_event(
            "session-a",
            "retry-2",
            "GET",
            // jig-ignore-next-line: canonical rustfmt line.
            "https://mail.proton.me/api/mail/v4/conversations/conversation-other"
        )),
        Err(ConversationDetailNetworkError::RedirectedAway)
    );
}

#[test]
fn network_response_requires_identity_status_and_json() {
    for (url, status, mime) in [
        (
            // jig-ignore-next-line: canonical rustfmt line.
            "https://mail.proton.me/api/mail/v4/conversations/conversation-other",
            200,
            "application/json",
        ),
        (URL, 204, "application/json"),
        (URL, 200, "text/html"),
    ] {
        let mut capture = ConversationDetailNetworkCapture::new("session-a");
        capture
            .observe(&request_event("session-a", "detail", "GET", URL))
            .expect("track exact request");
        assert_eq!(
            // jig-ignore-next-line: canonical rustfmt line.
            capture.observe(&response_event("session-a", "detail", url, status, mime)),
            Err(ConversationDetailNetworkError::ResponseRejected)
        );
    }
}

#[test]
fn network_capture_bounds_unfinished_requests() {
    let mut capture = ConversationDetailNetworkCapture::new("session-a");
    for index in 0..16u8 {
        let request_id = format!("detail-{index}");
        // jig-ignore-next-line: canonical rustfmt line.
        let url = format!("https://mail.proton.me/api/mail/v4/conversations/conversation-{index}");
        capture
            .observe(&request_event("session-a", &request_id, "GET", &url))
            .expect("within conversation request capacity");
    }
    assert_eq!(capture.tracked_request_count(), 16);
    assert_eq!(
        capture.observe(&request_event(
            "session-a",
            "overflow",
            "GET",
            "https://mail.proton.me/api/mail/v4/conversations/overflow"
        )),
        Err(ConversationDetailNetworkError::CapacityExceeded)
    );
}
