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
//   - Synthetic message-list response projection and endpoint-gating evidence.
// - Must-Not:
//   - Use live mailbox data, credentials, request headers, or message content.
// - Allows:
//   - Exercise exact GET endpoint checks and metadata-only projection.
// - Split-When:
//   - Browser Network capture gains its own end-to-end fixture suite.
// - Merge-When:
//   - Read-workflow integration owns response projection coverage directly.
// - Summary:
//   - Proves message-list response parsing is bounded and content-minimizing.
// - Description:
//   - Uses synthetic JSON with decoy content to prove metadata-only escape.
// - Usage:
//   - Run through the `mail_web_adapter` integration-test target.
// - Defaults:
//   - No network, browser, account, or filesystem interaction.
//

//! Message-list HTTP response projection regression tests.

use mail_web_adapter::{MessageListResponseError, ObservedMessageListResponse};

const URL: &str = concat!(
    "https://mail.proton.me/api/mail/v4/messages",
    "?Page=0&PageSize=50"
);

#[test]
fn exact_get_list_response_projects_only_required_metadata() {
    let body = r#"{
        "Code":1000,
        "Total":2,
        "Messages":[
            {"ID":"m-2","Time":1790840002,"Order":22,
             "Subject":"secret two","Sender":{"Address":"two@example.test"}},
            {"ID":"m-1","Time":1790840001,"Order":11,
             "Subject":"secret one","Body":"must not escape"}
        ]
    }"#;
    let response =
    // jig-ignore-next-line: canonical rustfmt line.
        ObservedMessageListResponse::parse("GET", URL, body).expect("parse synthetic response");
    assert_eq!(response.total(), 2);
    assert_eq!(response.messages().len(), 2);
    assert_eq!(response.messages()[0].id(), "m-2");
    assert_eq!(response.messages()[0].time(), 1_790_840_002);
    assert_eq!(response.messages()[0].order(), 22);
    let debug = format!("{response:?}");
    assert!(!debug.contains("secret"));
    assert!(!debug.contains("m-2"));
    assert!(!debug.contains("1790840002"));
}

#[test]
fn mutation_and_neighbor_endpoints_are_rejected() {
    let body = r#"{"Total":0,"Messages":[]}"#;
    assert_eq!(
        ObservedMessageListResponse::parse("POST", URL, body),
        Err(MessageListResponseError::UnexpectedEndpoint)
    );
    for url in [
        "https://account.proton.me/api/mail/v4/messages",
        "https://mail.proton.me/api/mail/v4/messages/count",
        "https://mail.proton.me/api/mail/v4/messages/m-1",
        "https://mail.proton.me/api/mail/v4/messages/",
        "https://mail.proton.me.evil.test/api/mail/v4/messages",
    ] {
        assert_eq!(
            ObservedMessageListResponse::parse("GET", url, body),
            Err(MessageListResponseError::UnexpectedEndpoint)
        );
    }
}

#[test]
fn malformed_or_duplicate_metadata_fails_closed() {
    for body in [
        r#"{"Total":1,"Messages":[{"ID":"","Time":1,"Order":1}]}"#,
        r#"{"Total":1,"Messages":[{"ID":"m-1","Time":"1","Order":1}]}"#,
        r#"{"Total":1,"Messages":[{"ID":"m-1","Time":1}]}"#,
        r#"{"Messages":[]}"#,
    ] {
        assert_eq!(
            ObservedMessageListResponse::parse("GET", URL, body),
            Err(MessageListResponseError::Malformed)
        );
    }

    let duplicate = concat!(
        r#"{"Total":2,"Messages":[{"ID":"m-1","Time":2,"Order":2},"#,
        r#"{"ID":"m-1","Time":1,"Order":1}]}"#,
    );
    assert_eq!(
        ObservedMessageListResponse::parse("GET", URL, duplicate),
        Err(MessageListResponseError::DuplicateMessageId)
    );
}

#[test]
fn oversized_page_is_rejected() {
    let messages = (0u16..101u16)
        // jig-ignore-next-line: canonical rustfmt line.
        .map(|index| format!(r#"{{"ID":"m-{index}","Time":1,"Order":{index}}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let body = format!(r#"{{"Total":101,"Messages":[{messages}]}}"#);
    assert_eq!(
        ObservedMessageListResponse::parse("GET", URL, &body),
        Err(MessageListResponseError::TooManyMessages)
    );
}

#[test]
fn network_capture_tracks_only_exact_get_list_lifecycle() {
    use mail_web_adapter::MessageListNetworkCapture;
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    let unrelated = json!({
        "sessionId":"session-2",
        "method":"Network.requestWillBeSent",
        "params":{"requestId":"secret-other","request":{
            "method":"GET","url":URL
        }}
    });
    capture.observe(&unrelated).expect("ignore other session");
    let mutation = json!({
        "sessionId":"session-1",
        "method":"Network.requestWillBeSent",
        "params":{"requestId":"mutation","request":{
            "method":"POST","url":URL
        }}
    });
    capture
        .observe(&mutation)
        .expect("ignore mutation endpoint");
    let request = json!({
        "sessionId":"session-1",
        "method":"Network.requestWillBeSent",
        "params":{"requestId":"list-1","request":{
            "method":"GET","url":URL
        }}
    });
    capture.observe(&request).expect("track list request");
    let response = json!({
        "sessionId":"session-1",
        "method":"Network.responseReceived",
        "params":{"requestId":"list-1","response":{
            "url":URL,"status":200u16,"mimeType":"application/json"
        }}
    });
    capture.observe(&response).expect("accept list response");
    let finished = json!({
        "sessionId":"session-1",
        "method":"Network.loadingFinished",
        "params":{"requestId":"list-1"}
    });
    capture.observe(&finished).expect("finish list request");
    assert_eq!(capture.take_finished_request_ids(), ["list-1"]);
    assert!(capture.take_finished_request_ids().is_empty());
    let debug = format!("{capture:?}");
    assert!(!debug.contains("session-1"));
    assert!(!debug.contains(URL));
}

#[test]
fn network_capture_fails_closed_on_redirect_failure_and_bad_response() {
    use mail_web_adapter::{MessageListNetworkCapture, MessageListNetworkError};
    use serde_json::json;

    let request = |id: &str| {
        json!({
            "sessionId":"session-1",
            "method":"Network.requestWillBeSent",
            "params":{"requestId":id,"request":{"method":"GET","url":URL}}
        })
    };
    let mut capture = MessageListNetworkCapture::new("session-1");
    capture
        .observe(&request("redirect"))
        .expect("track request");
    let redirected = json!({
        "sessionId":"session-1",
        "method":"Network.requestWillBeSent",
        "params":{"requestId":"redirect","request":{
            // jig-ignore-next-line: canonical rustfmt line.
            "method":"GET","url":"https://mail.proton.me/api/mail/v4/messages/count"
        }}
    });
    assert_eq!(
        capture.observe(&redirected),
        Err(MessageListNetworkError::RedirectedAway)
    );

    let mut capture = MessageListNetworkCapture::new("session-1");
    capture.observe(&request("failed")).expect("track request");
    let failed = json!({
        "sessionId":"session-1",
        "method":"Network.loadingFailed",
        "params":{"requestId":"failed"}
    });
    assert_eq!(
        capture.observe(&failed),
        Err(MessageListNetworkError::RequestFailed)
    );

    let mut capture = MessageListNetworkCapture::new("session-1");
    capture.observe(&request("bad-url")).expect("track request");
    let bad_url = json!({
        "sessionId":"session-1",
        "method":"Network.responseReceived",
        "params":{"requestId":"bad-url","response":{
            "url":"https://mail.proton.me/api/mail/v4/messages/count",
            "status":200u16,"mimeType":"application/json"
        }}
    });
    assert_eq!(
        capture.observe(&bad_url),
        Err(MessageListNetworkError::ResponseRejected)
    );

    let mut capture = MessageListNetworkCapture::new("session-1");
    capture
        .observe(&request("bad-status"))
        .expect("track request");
    let bad_response = json!({
        "sessionId":"session-1",
        "method":"Network.responseReceived",
        "params":{"requestId":"bad-status","response":{
            "url":URL,"status":500u16,"mimeType":"application/json"
        }}
    });
    assert_eq!(
        capture.observe(&bad_response),
        Err(MessageListNetworkError::ResponseRejected)
    );
}

#[test]
fn network_capture_bounds_unfinished_list_requests() {
    use mail_web_adapter::{MessageListNetworkCapture, MessageListNetworkError};
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    for index in 0u16..128u16 {
        let request = json!({
            "sessionId":"session-1",
            "method":"Network.requestWillBeSent",
            "params":{"requestId":format!("list-{index}"),"request":{
                "method":"GET","url":URL
            }}
        });
        capture.observe(&request).expect("within request bound");
    }
    let overflow = json!({
        "sessionId":"session-1",
        "method":"Network.requestWillBeSent",
        "params":{"requestId":"list-overflow","request":{
            "method":"GET","url":URL
        }}
    });
    assert_eq!(
        capture.observe(&overflow),
        Err(MessageListNetworkError::CapacityExceeded)
    );
}
