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
//   - Synthetic conversation-list response and lifecycle evidence.
// - Must-Not:
//   - Use live mailbox data, search terms, credentials, or network access.
// - Allows:
//   - Exercise exact list GET binding and content-minimized metadata
//     projection.
// - Split-When:
//   - Public thread paging/search gains separately proven cursor semantics.
// - Merge-When:
//   - One thread-list acceptance suite owns transport and public mapping.
// - Summary:
//   - Proves conversation list metadata is bounded and content-minimal.
// - Description:
//   - Uses decoy secrets to verify request/body content does not escape.
// - Usage:
//   - Run through the `mail_web_adapter` integration-test target.
// - Defaults:
//   - Synthetic JSON/CDP only; no browser, account, or network interaction.
//

//! Synthetic conversation-list response boundary tests.

use mail_web_adapter::ConversationListNetworkCapture;
use mail_web_adapter::ConversationListNetworkError;
use mail_web_adapter::ConversationListResponseError;
use mail_web_adapter::ObservedConversationListResponse;
use serde_json::{Value, json};

const URL: &str = concat!(
    "https://mail.proton.me/api/mail/v4/conversations",
    "?Page=0&PageSize=50&Limit=50&Sort=Time&Desc=1&Keyword=SECRET"
);

// jig-ignore-next-line: canonical rustfmt line.
fn request_event(session: &str, request_id: &str, method: &str, url: &str) -> Value {
    json!({
        "sessionId": session,
        "method": "Network.requestWillBeSent",
        "params": {"requestId": request_id, "request": {
            "method": method, "url": url,
            "headers": {"Authorization": "Bearer SECRET", "Cookie": "SECRET"}
        }}
    })
}

// jig-ignore-next-line: canonical rustfmt line.
fn response_event(session: &str, request_id: &str, url: &str, status: u64, mime: &str) -> Value {
    json!({
        "sessionId": session,
        "method": "Network.responseReceived",
        "params": {"requestId": request_id, "response": {
            "url": url, "status": status, "mimeType": mime,
            "headers": {"Set-Cookie": "SECRET"}
        }}
    })
}

fn finished_event(session: &str, request_id: &str) -> Value {
    json!({"sessionId":session,"method":"Network.loadingFinished",
        "params":{"requestId":request_id}})
}

fn failed_event(session: &str, request_id: &str) -> Value {
    json!({"sessionId":session,"method":"Network.loadingFailed",
        "params":{"requestId":request_id}})
}

const fn body() -> &'static str {
    r#"{
      "Code":1000,"Stale":0,"TasksRunning":[],"Total":2,
      "Conversations":[
        {"ID":"c-2","Time":200,"Order":20,"NumMessages":4,
         "Subject":"SECRET TWO","Senders":[{"Address":"secret@example.test"}]},
        {"ID":"c-1","Time":100,"Order":10,"NumMessages":1,
         "Subject":"SECRET ONE","AttachmentsMetadata":[{"Name":"secret.pdf"}]}
      ]
    }"#
}

#[test]
fn exact_list_projects_only_bounded_thread_metadata() {
    let observed = ObservedConversationListResponse::parse("GET", URL, body())
        .expect("project synthetic conversation list");
    assert_eq!(observed.total(), 2);
    assert_eq!(observed.conversations().len(), 2);
    assert_eq!(observed.conversations()[0].id(), "c-2");
    assert_eq!(observed.conversations()[0].time(), 200);
    assert_eq!(observed.conversations()[0].order(), 20);
    assert_eq!(observed.conversations()[0].message_count(), 4);
    let debug = format!("{observed:?}");
    for secret in [
        "c-2",
        "200",
        "SECRET TWO",
        "secret@example.test",
        "secret.pdf",
    ] {
        assert!(!debug.contains(secret));
    }
}

#[test]
fn projection_rejects_neighbor_endpoint_stale_and_tasks() {
    assert_eq!(
        ObservedConversationListResponse::parse(
            "GET",
            "https://mail.proton.me/api/mail/v4/conversations/count",
            body(),
        ),
        Err(ConversationListResponseError::UnexpectedEndpoint)
    );
    assert_eq!(
        ObservedConversationListResponse::parse(
            "GET",
            URL,
            r#"{"Code":1000,"Stale":1,"Total":0,"Conversations":[]}"#,
        ),
        Err(ConversationListResponseError::StaleResponse)
    );
    assert_eq!(
        ObservedConversationListResponse::parse(
            "GET",
            URL,
            // jig-ignore-next-line: indivisible synthetic JSON fixture.
            r#"{"Code":1000,"Stale":0,"TasksRunning":{"0":{}},"Total":0,"Conversations":[]}"#,
        ),
        Err(ConversationListResponseError::TasksRunning)
    );
}

#[test]
fn projection_rejects_missing_duplicate_or_bad_metadata() {
    for invalid in [
        // jig-ignore-next-line: indivisible synthetic JSON fixture.
        r#"{"Code":1000,"Stale":0,"Total":1,"Conversations":[{"ID":"","Time":1,"Order":1,"NumMessages":1}]}"#,
        // jig-ignore-next-line: indivisible synthetic JSON fixture.
        r#"{"Code":1000,"Stale":0,"Total":1,"Conversations":[{"ID":"c","Time":"1","Order":1,"NumMessages":1}]}"#,
        // jig-ignore-next-line: indivisible synthetic JSON fixture.
        r#"{"Code":1000,"Stale":0,"Total":1,"Conversations":[{"ID":"c","Time":1,"NumMessages":1}]}"#,
        // jig-ignore-next-line: indivisible synthetic JSON fixture.
        r#"{"Code":1000,"Stale":0,"Total":0,"Conversations":[{"ID":"c","Time":1,"Order":1,"NumMessages":1}]}"#,
    ] {
        assert_eq!(
            ObservedConversationListResponse::parse("GET", URL, invalid),
            Err(ConversationListResponseError::Malformed)
        );
    }
    // jig-ignore-next-line: indivisible synthetic JSON fixture.
    let duplicate = r#"{"Code":1000,"Stale":0,"Total":2,"Conversations":[{"ID":"c","Time":2,"Order":2,"NumMessages":1},{"ID":"c","Time":1,"Order":1,"NumMessages":1}]}"#;
    assert_eq!(
        ObservedConversationListResponse::parse("GET", URL, duplicate),
        Err(ConversationListResponseError::DuplicateConversationId)
    );
}

#[test]
fn cdp_projection_rejects_encoded_and_oversized_bodies() {
    let envelope = json!({"body":body(),"base64Encoded":true});
    assert_eq!(
        ObservedConversationListResponse::parse_cdp_body(&envelope),
        Err(ConversationListResponseError::UnsupportedEncoding)
    );
    let huge = "x".repeat(ObservedConversationListResponse::MAX_BODY_BYTES + 1);
    assert_eq!(
        ObservedConversationListResponse::parse("GET", URL, &huge),
        Err(ConversationListResponseError::BodyTooLarge)
    );
}

#[test]
fn network_capture_binds_request_and_response_url_without_retaining_it() {
    let mut capture = ConversationListNetworkCapture::new("session-a");
    capture
        .observe(&request_event("session-a", "list", "GET", URL))
        .expect("track exact list request");
    capture
        .observe(&response_event(
            "session-a",
            "list",
            URL,
            200,
            "application/json",
        ))
        .expect("accept matching response");
    capture
        .observe(&finished_event("session-a", "list"))
        .expect("finish list response");
    assert_eq!(
        capture.take_finished_request_ids(),
        vec![String::from("list")]
    );
    let debug = format!("{capture:?}");
    assert!(!debug.contains("SECRET"));
    assert!(!debug.contains("Keyword"));
}

#[test]
fn network_capture_rejects_url_drift_bad_response_and_failure() {
    let changed = URL.replace("SECRET", "DIFFERENT");
    let mut capture = ConversationListNetworkCapture::new("session-a");
    capture
        .observe(&request_event("session-a", "list", "GET", URL))
        .expect("track list request");
    assert_eq!(
        capture.observe(&response_event(
            "session-a",
            "list",
            &changed,
            200,
            "application/json",
        )),
        Err(ConversationListNetworkError::ResponseRejected)
    );

    let mut failed = ConversationListNetworkCapture::new("session-a");
    failed
        .observe(&request_event("session-a", "list", "GET", URL))
        .expect("track list request");
    assert_eq!(
        failed.observe(&failed_event("session-a", "list")),
        Err(ConversationListNetworkError::RequestFailed)
    );
}

#[test]
fn network_capture_ignores_neighbor_traffic_and_bounds_capacity() {
    let mut capture = ConversationListNetworkCapture::new("session-a");
    capture
        .observe(&request_event(
            "session-a",
            "count",
            "GET",
            "https://mail.proton.me/api/mail/v4/conversations/count",
        ))
        .expect("ignore count endpoint");
    assert_eq!(capture.tracked_request_count(), 0);
    for index in 0..128u16 {
        let request_id = format!("list-{index}");
        // jig-ignore-next-line: canonical rustfmt line.
        let url = format!("https://mail.proton.me/api/mail/v4/conversations?Limit=1&Page={index}");
        capture
            .observe(&request_event("session-a", &request_id, "GET", &url))
            .expect("within list request capacity");
    }
    assert_eq!(capture.tracked_request_count(), 128);
    assert_eq!(
        capture.observe(&request_event(
            "session-a",
            "overflow",
            "GET",
            "https://mail.proton.me/api/mail/v4/conversations?Limit=1&Page=999",
        )),
        Err(ConversationListNetworkError::CapacityExceeded)
    );
}
