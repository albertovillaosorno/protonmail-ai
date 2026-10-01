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
//   - Synthetic legacy Mail core-event response projection evidence.
// - Must-Not:
//   - Use live account data, credentials, or retain event payload content.
// - Allows:
//   - Exercise exact endpoint, watermark, change-presence, and refresh rules.
// - Split-When:
//   - Event Network capture gains a distinct browser integration suite.
// - Merge-When:
//   - Snapshot-pagination acceptance owns watermark projection directly.
// - Summary:
//   - Proves event response projection is bounded and content-minimizing.
// - Description:
//   - Synthetic payloads contain decoy event content that cannot escape Debug.
// - Usage:
//   - Run through the mail_web_adapter integration-test target.
// - Defaults:
//   - No browser, network, account, or filesystem interaction.
//

//! Mail core-event watermark projection regression tests.

use mail_web_adapter::MailboxEventWatermarkError;
use mail_web_adapter::ObservedMailboxEventWatermark;

const URL: &str = concat!(
    "https://mail.proton.me/api/core/v5/events/event-7",
    "?ConversationCounts=1&MessageCounts=1&CalledFrom=Foreground"
);

#[test]
fn settled_same_watermark_projects_no_mailbox_change() {
    let body = r#"{
        "EventID":"event-7","More":0,"Refresh":0,
        "Messages":[],"Conversations":[],
        "MessageCounts":[],"ConversationCounts":[]
    }"#;
    let event = ObservedMailboxEventWatermark::parse("GET", URL, body)
        .expect("parse settled synthetic event poll");
    assert!(event.settled());
    assert!(!event.mailbox_changes());
    assert!(event.unchanged_watermark());
    assert_eq!(event.response_event_id(), "event-7");
    let debug = format!("{event:?}");
    assert!(!debug.contains("event-7"));
}

#[test]
fn event_content_is_reduced_to_change_presence() {
    let body = r#"{
        "EventID":"event-8","More":0,
        "Messages":[{"ID":"secret-message","Subject":"secret subject"}],
        "Conversations":null,"MessageCounts":[],"ConversationCounts":[]
    }"#;
    let event = ObservedMailboxEventWatermark::parse("GET", URL, body)
        .expect("parse changed synthetic event poll");
    assert!(event.settled());
    assert!(event.mailbox_changes());
    assert!(!event.unchanged_watermark());
    let debug = format!("{event:?}");
    assert!(!debug.contains("secret-message"));
    assert!(!debug.contains("secret subject"));
    assert!(!debug.contains("event-8"));
}

#[test]
fn more_and_refresh_are_not_settled() {
    for body in [
        r#"{"EventID":"event-8","More":1}"#,
        r#"{"EventID":"event-8","More":0,"Refresh":1}"#,
    ] {
        let event = ObservedMailboxEventWatermark::parse("GET", URL, body)
            .expect("parse unsettled event poll");
        assert!(!event.settled());
    }
}

#[test]
fn mailbox_count_changes_are_conservative_change_signals() {
    let body = r#"{
        "EventID":"event-8","More":0,
        "MessageCounts":[{"LabelID":"inbox","Total":4}]
    }"#;
    let event = ObservedMailboxEventWatermark::parse("GET", URL, body)
        .expect("parse count-changing event poll");
    assert!(event.mailbox_changes());
}

#[test]
fn wrong_endpoint_or_method_is_rejected() {
    let body = r#"{"EventID":"event-7","More":0}"#;
    for url in [
        "https://mail.proton.me/api/core/v4/events/latest",
        "https://mail.proton.me/api/core/v5/events/",
        "https://mail.proton.me/api/core/v5/events/event-7/extra",
        "https://account.proton.me/api/core/v5/events/event-7",
        "https://mail.proton.me.evil.test/api/core/v5/events/event-7",
    ] {
        assert_eq!(
            ObservedMailboxEventWatermark::parse("GET", url, body),
            Err(MailboxEventWatermarkError::UnexpectedEndpoint)
        );
    }
    assert_eq!(
        ObservedMailboxEventWatermark::parse("POST", URL, body),
        Err(MailboxEventWatermarkError::UnexpectedEndpoint)
    );
}

#[test]
fn malformed_event_metadata_fails_closed() {
    for body in [
        r#"{"EventID":"","More":0}"#,
        r#"{"EventID":"event-7","More":2}"#,
        r#"{"EventID":"event-7","More":0,"Refresh":"yes"}"#,
        r#"{"EventID":"event-7","More":0,"Messages":{}}"#,
    ] {
        assert_eq!(
            ObservedMailboxEventWatermark::parse("GET", URL, body),
            Err(MailboxEventWatermarkError::Malformed)
        );
    }
}

#[test]
fn oversized_event_body_is_rejected() {
    let body = format!(
        r#"{{"EventID":"event-7","More":0,"padding":"{}"}}"#,
        "x".repeat(262_145)
    );
    assert_eq!(
        ObservedMailboxEventWatermark::parse("GET", URL, &body),
        Err(MailboxEventWatermarkError::BodyTooLarge)
    );
}

#[test]
fn network_capture_tracks_exact_event_get_lifecycle() {
    use mail_web_adapter::MailboxEventNetworkCapture;
    use serde_json::json;

    let mut capture = MailboxEventNetworkCapture::new("session-1");
    let url = URL;
    capture
        .observe(&json!({
            "sessionId":"session-1",
            "method":"Network.requestWillBeSent",
            "params":{"requestId":"event-request-1","request":{
                "method":"GET","url":url
            }}
        }))
        .expect("track event request");
    capture
        .observe(&json!({
            "sessionId":"session-1",
            "method":"Network.responseReceived",
            "params":{"requestId":"event-request-1","response":{
                "url":url,"status":200u16,"mimeType":"application/json"
            }}
        }))
        .expect("accept event response");
    capture
        .observe(&json!({
            "sessionId":"session-1",
            "method":"Network.loadingFinished",
            "params":{"requestId":"event-request-1"}
        }))
        .expect("finish event request");
    assert_eq!(
        capture.take_finished_request_ids(),
        [String::from("event-request-1")]
    );
    let debug = format!("{capture:?}");
    assert!(!debug.contains("session-1"));
    assert!(!debug.contains("event-7"));
}

#[test]
fn network_capture_ignores_other_sessions_and_non_event_traffic() {
    use mail_web_adapter::MailboxEventNetworkCapture;
    use serde_json::json;

    let mut capture = MailboxEventNetworkCapture::new("session-1");
    for event in [
        json!({"sessionId":"session-2","method":"Network.requestWillBeSent"}),
        json!({
            "sessionId":"session-1",
            "method":"Network.requestWillBeSent",
            "params":{"requestId":"latest","request":{
                "method":"GET",
                "url":"https://mail.proton.me/api/core/v4/events/latest"
            }}
        }),
        json!({
            "sessionId":"session-1",
            "method":"Network.requestWillBeSent",
            "params":{"requestId":"post","request":{
                "method":"POST","url":URL
            }}
        }),
    ] {
        capture.observe(&event).expect("ignore unrelated traffic");
    }
    assert!(capture.take_finished_request_ids().is_empty());
}

#[test]
fn network_capture_rejects_redirect_failure_and_bad_response() {
    // jig-ignore-next-line: indivisible synthetic JSON fixture.
    use mail_web_adapter::{MailboxEventNetworkCapture, MailboxEventNetworkError};
    use serde_json::json;

    let request = |id: &str| {
        json!({
            "sessionId":"session-1",
            "method":"Network.requestWillBeSent",
            "params":{"requestId":id,"request":{"method":"GET","url":URL}}
        })
    };

    let mut bad = MailboxEventNetworkCapture::new("session-1");
    bad.observe(&request("bad"))
        .expect("track bad response request");
    assert_eq!(
        bad.observe(&json!({
            "sessionId":"session-1","method":"Network.responseReceived",
            "params":{"requestId":"bad","response":{
                "url":URL,"status":500u16,"mimeType":"application/json"
            }}
        })),
        Err(MailboxEventNetworkError::ResponseRejected)
    );

    let mut redirect = MailboxEventNetworkCapture::new("session-1");
    redirect
        .observe(&request("redirect"))
        .expect("track redirect request");
    assert_eq!(
        redirect.observe(&json!({
            "sessionId":"session-1","method":"Network.requestWillBeSent",
            "params":{"requestId":"redirect","request":{
                "method":"GET","url":"https://mail.proton.me/u/0/inbox"
            }}
        })),
        Err(MailboxEventNetworkError::RedirectedAway)
    );

    let mut failed = MailboxEventNetworkCapture::new("session-1");
    failed
        .observe(&request("failed"))
        .expect("track failed request");
    assert_eq!(
        failed.observe(&json!({
            "sessionId":"session-1","method":"Network.loadingFailed",
            "params":{"requestId":"failed"}
        })),
        Err(MailboxEventNetworkError::RequestFailed)
    );
}

#[test]
fn network_capture_bounds_unfinished_event_requests() {
    // jig-ignore-next-line: indivisible synthetic JSON fixture.
    use mail_web_adapter::{MailboxEventNetworkCapture, MailboxEventNetworkError};
    use serde_json::json;

    let mut capture = MailboxEventNetworkCapture::new("session-1");
    for index in 0u16..32u16 {
        let id = format!("event-request-{index}");
        capture
            .observe(&json!({
                "sessionId":"session-1","method":"Network.requestWillBeSent",
                "params":{"requestId":id,"request":{"method":"GET","url":URL}}
            }))
            .expect("track bounded event request");
    }
    assert_eq!(
        capture.observe(&json!({
            "sessionId":"session-1","method":"Network.requestWillBeSent",
            "params":{"requestId":"overflow","request":{
                "method":"GET","url":URL
            }}
        })),
        Err(MailboxEventNetworkError::CapacityExceeded)
    );
}
