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

use mail_web_adapter::MessageListReconciliationError;
use mail_web_adapter::ReconciledVisibleMessageMetadata;
use mail_web_adapter::{MessageListResponseError, ObservedMessageListResponse};

const URL: &str = concat!(
    "https://mail.proton.me/api/mail/v4/messages",
    "?Page=0&PageSize=50&Limit=50&Sort=Time&Desc=1"
);

#[test]
fn exact_get_list_response_projects_only_required_metadata() {
    let body = r#"{
        "Code":1000,
        "Stale":0,"TasksRunning":[],"Total":2,
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
    let body = r#"{"Stale":0,"Total":0,"Messages":[]}"#;
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
        r#"{"Stale":0,"Total":1,"Messages":[{"ID":"","Time":1,"Order":1}]}"#,
        // jig-ignore-next-line: indivisible synthetic JSON fixture.
        r#"{"Stale":0,"Total":1,"Messages":[{"ID":"m-1","Time":"1","Order":1}]}"#,
        r#"{"Stale":0,"Total":1,"Messages":[{"ID":"m-1","Time":1}]}"#,
        r#"{"Messages":[]}"#,
        r#"{"Stale":0,"Total":0,"Messages":[{"ID":"m-1","Time":1,"Order":1}]}"#,
    ] {
        assert_eq!(
            ObservedMessageListResponse::parse("GET", URL, body),
            Err(MessageListResponseError::Malformed)
        );
    }

    let duplicate = concat!(
        r#"{"Stale":0,"Total":2,"Messages":[{"ID":"m-1","Time":2,"Order":2},"#,
        r#"{"ID":"m-1","Time":1,"Order":1}]}"#,
    );
    assert_eq!(
        ObservedMessageListResponse::parse("GET", URL, duplicate),
        Err(MessageListResponseError::DuplicateMessageId)
    );
}

#[test]
fn stale_response_is_rejected() {
    assert_eq!(
        // jig-ignore-next-line: indivisible synthetic JSON fixture.
        ObservedMessageListResponse::parse("GET", URL, r#"{"Stale":1,"Total":0,"Messages":[]}"#,),
        Err(MessageListResponseError::StaleResponse)
    );
}

#[test]
fn active_or_malformed_task_state_is_rejected() {
    for tasks in [r#"["label-1"]"#, r#"{"label-1":{}}"#, "true"] {
        // jig-ignore-next-line: indivisible synthetic JSON fixture.
        let body = format!(r#"{{"Stale":0,"TasksRunning":{tasks},"Total":0,"Messages":[]}}"#);
        assert_eq!(
            ObservedMessageListResponse::parse("GET", URL, &body),
            Err(MessageListResponseError::TasksRunning)
        );
    }
    assert_eq!(
        ObservedMessageListResponse::parse(
            "GET",
            URL,
            r#"{"Stale":0,"TasksRunning":"busy","Total":0,"Messages":[]}"#,
        ),
        Err(MessageListResponseError::Malformed)
    );
}

#[test]
fn oversized_page_is_rejected() {
    let messages = (0u16..101u16)
        // jig-ignore-next-line: canonical rustfmt line.
        .map(|index| format!(r#"{{"ID":"m-{index}","Time":1,"Order":{index}}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let body = format!(r#"{{"Stale":0,"Total":101,"Messages":[{messages}]}}"#);
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
        .observe(&request("query-drift"))
        .expect("track request");
    let query_drift = json!({
        "sessionId":"session-1",
        "method":"Network.responseReceived",
        "params":{"requestId":"query-drift","response":{
            // jig-ignore-next-line: indivisible synthetic URL fixture.
            "url":"https://mail.proton.me/api/mail/v4/messages?Page=0&PageSize=50&Limit=50&Sort=Time&Desc=0",
            "status":200u16,"mimeType":"application/json"
        }}
    });
    assert_eq!(
        capture.observe(&query_drift),
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

#[test]
fn cdp_body_projection_requires_decoded_bounded_json() {
    use serde_json::json;

    // jig-ignore-next-line: indivisible synthetic JSON fixture.
    let body = r#"{"Stale":0,"Total":1,"Messages":[{"ID":"m-1","Time":7,"Order":3}]}"#;
    let response = ObservedMessageListResponse::parse_cdp_body(&json!({
        "body":body,"base64Encoded":false
    }))
    .expect("project decoded CDP body");
    assert_eq!(response.messages()[0].id(), "m-1");
    assert_eq!(response.messages()[0].time(), 7);
    assert_eq!(response.messages()[0].order(), 3);

    assert_eq!(
        ObservedMessageListResponse::parse_cdp_body(&json!({
            "body":"e30=","base64Encoded":true
        })),
        Err(MessageListResponseError::UnsupportedEncoding)
    );
    assert_eq!(
        ObservedMessageListResponse::parse_cdp_body(&json!({"body":body})),
        Err(MessageListResponseError::Malformed)
    );

    let oversized = "x".repeat(262_145);
    assert_eq!(
        ObservedMessageListResponse::parse("GET", URL, &oversized),
        Err(MessageListResponseError::BodyTooLarge)
    );
}

#[test]
fn visible_ids_reconcile_across_non_overlapping_prefetch_batches() {
    let first = ObservedMessageListResponse::parse(
        "GET",
        URL,
        concat!(
            // jig-ignore-next-line: indivisible synthetic JSON fixture.
            r#"{"Stale":0,"Total":4,"Messages":[{"ID":"m-4","Time":40,"Order":4},"#,
            r#"{"ID":"m-3","Time":30,"Order":3}]}"#,
        ),
    )
    .expect("parse first batch");
    let second = ObservedMessageListResponse::parse(
        "GET",
        URL,
        concat!(
            // jig-ignore-next-line: indivisible synthetic JSON fixture.
            r#"{"Stale":0,"Total":4,"Messages":[{"ID":"m-2","Time":20,"Order":2},"#,
            r#"{"ID":"m-1","Time":10,"Order":1}]}"#,
        ),
    )
    .expect("parse second batch");
    // jig-ignore-next-line: canonical rustfmt line.
    let reconciled = ReconciledVisibleMessageMetadata::reconcile(&["m-3", "m-2"], &[first, second])
        .expect("reconcile visible IDs");
    assert_eq!(reconciled.messages().len(), 2);
    assert_eq!(reconciled.messages()[0].id(), "m-3");
    assert_eq!(reconciled.messages()[0].time(), 30);
    assert_eq!(reconciled.messages()[1].id(), "m-2");
    assert_eq!(reconciled.messages()[1].time(), 20);
    let debug = format!("{reconciled:?}");
    assert!(!debug.contains("m-3"));
    assert!(!debug.contains("30"));
}

#[test]
fn visible_metadata_reconciliation_fails_closed_on_coverage_drift() {
    let first = ObservedMessageListResponse::parse(
        "GET",
        URL,
        // jig-ignore-next-line: indivisible synthetic JSON fixture.
        r#"{"Stale":0,"Total":2,"Messages":[{"ID":"m-2","Time":20,"Order":2}]}"#,
    )
    .expect("parse first batch");
    assert_eq!(
        ReconciledVisibleMessageMetadata::reconcile(&["m-2", "m-1"], &[first]),
        Err(MessageListReconciliationError::MissingVisibleMessage)
    );

    let overlap_a = ObservedMessageListResponse::parse(
        "GET",
        URL,
        // jig-ignore-next-line: indivisible synthetic JSON fixture.
        r#"{"Stale":0,"Total":2,"Messages":[{"ID":"m-2","Time":20,"Order":2}]}"#,
    )
    .expect("parse overlap a");
    let overlap_b = ObservedMessageListResponse::parse(
        "GET",
        URL,
        // jig-ignore-next-line: indivisible synthetic JSON fixture.
        r#"{"Stale":0,"Total":2,"Messages":[{"ID":"m-2","Time":20,"Order":2}]}"#,
    )
    .expect("parse overlap b");
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ReconciledVisibleMessageMetadata::reconcile(&["m-2"], &[overlap_a, overlap_b]),
        Err(MessageListReconciliationError::DuplicateObservedId)
    );

    assert_eq!(
        ReconciledVisibleMessageMetadata::reconcile(&["m-1", "m-1"], &[]),
        Err(MessageListReconciliationError::DuplicateVisibleId)
    );
}

#[test]
fn explicit_empty_reconciliation_rejects_observed_messages() {
    let nonempty = ObservedMessageListResponse::parse(
        "GET",
        URL,
        // jig-ignore-next-line: indivisible synthetic JSON fixture.
        r#"{"Stale":0,"Total":1,"Messages":[{"ID":"m-1","Time":10,"Order":1}]}"#,
    )
    .expect("parse nonempty response");
    assert_eq!(
        ReconciledVisibleMessageMetadata::reconcile(&[], &[nonempty]),
        Err(MessageListReconciliationError::UnexpectedObservedMessage)
    );
    let empty = ReconciledVisibleMessageMetadata::reconcile(&[], &[])
        .expect("empty page without observations is consistent");
    assert!(empty.messages().is_empty());
}

#[test]
fn network_capture_accepts_initial_and_continuation_batch_shapes() {
    use mail_web_adapter::MessageListNetworkCapture;
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    for (id, url) in [
        (
            "initial",
            // jig-ignore-next-line: indivisible synthetic JSON fixture.
            "https://mail.proton.me/api/mail/v4/messages?Page=0&PageSize=50&Limit=50&Sort=Time&Desc=1&LabelID=sent",
        ),
        (
            "continuation",
            // jig-ignore-next-line: indivisible synthetic JSON fixture.
            "https://mail.proton.me/api/mail/v4/messages?Limit=50&Anchor=7&AnchorID=m-50&Sort=Time&Desc=1&LabelID=sent",
        ),
    ] {
        capture
            .observe(&json!({
                "sessionId":"session-1",
                "method":"Network.requestWillBeSent",
                "params":{"requestId":id,"request":{"method":"GET","url":url}}
            }))
            .expect("accept safe batch request shape");
        capture
            .observe(&json!({
                "sessionId":"session-1",
                "method":"Network.responseReceived",
                "params":{"requestId":id,"response":{
                    "url":url,"status":200u16,"mimeType":"application/json"
                }}
            }))
            .expect("accept safe batch response");
        capture
            .observe(&json!({
                "sessionId":"session-1",
                "method":"Network.loadingFinished",
                "params":{"requestId":id}
            }))
            .expect("finish safe batch");
    }
    assert_eq!(
        capture.take_finished_request_ids(),
        vec![String::from("continuation"), String::from("initial")]
    );
}

#[test]
fn network_capture_rejects_query_context_drift_without_retaining_terms() {
    use mail_web_adapter::{MessageListNetworkCapture, MessageListNetworkError};
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    for (id, url, expected) in [
        (
            "initial",
            // jig-ignore-next-line: indivisible synthetic URL fixture.
            "https://mail.proton.me/api/mail/v4/messages?Page=0&PageSize=50&Limit=50&Sort=Time&Desc=1&LabelID=sent&Unread=1",
            Ok(()),
        ),
        (
            "continuation",
            // jig-ignore-next-line: indivisible synthetic URL fixture.
            "https://mail.proton.me/api/mail/v4/messages?Limit=50&Anchor=7&AnchorID=m-50&Sort=Time&Desc=1&LabelID=drafts&Unread=1",
            Err(MessageListNetworkError::QueryContextChanged),
        ),
    ] {
        assert_eq!(
            capture.observe(&json!({
                "sessionId":"session-1",
                "method":"Network.requestWillBeSent",
                "params":{"requestId":id,"request":{"method":"GET","url":url}}
            })),
            expected
        );
    }
    let debug = format!("{capture:?}");
    assert!(!debug.contains("sent"));
    assert!(!debug.contains("drafts"));
}

#[test]
fn network_capture_ignores_non_batch_list_queries_and_rejects_bad_limits() {
    use mail_web_adapter::{MessageListNetworkCapture, MessageListNetworkError};
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    for url in [
        "https://mail.proton.me/api/mail/v4/messages?ID=m-1",
        // jig-ignore-next-line: indivisible synthetic URL fixture.
        "https://mail.proton.me/api/mail/v4/messages?Page=0&PageSize=50&Limit=50&Sort=Time&Desc=1&ID=m-1",
        // Encrypted-search recovery traffic is not visible-list pagination.
        // jig-ignore-next-line: indivisible synthetic URL fixture.
        "https://mail.proton.me/api/mail/v4/messages?Page=0&PageSize=50&Limit=50&Sort=Time&Desc=1&End=7&EndID=m-7",
        // jig-ignore-next-line: indivisible synthetic URL fixture.
        "https://mail.proton.me/api/mail/v4/messages?Page=0&PageSize=50&Limit=50&Sort=Time&Desc=1&BeginID=m-1",
        "https://mail.proton.me/api/mail/v4/messages?Page=0&PageSize=50",
        "https://mail.proton.me/api/mail/v4/messages?Limit=50&AnchorID=m-50",
    ] {
        capture
            .observe(&json!({
                "sessionId":"session-1",
                "method":"Network.requestWillBeSent",
                // jig-ignore-next-line: indivisible synthetic JSON fixture.
                "params":{"requestId":"ignored","request":{"method":"GET","url":url}}
            }))
            .expect("ignore list request outside WebClients batch shape");
    }
    assert!(capture.take_finished_request_ids().is_empty());

    for url in [
        // jig-ignore-next-line: indivisible synthetic URL fixture.
        "https://mail.proton.me/api/mail/v4/messages?Page=0&PageSize=0&Limit=0&Sort=Time&Desc=1",
        // jig-ignore-next-line: indivisible synthetic JSON fixture.
        "https://mail.proton.me/api/mail/v4/messages?Page=0&PageSize=101&Limit=101&Sort=Time&Desc=1",
        // jig-ignore-next-line: indivisible synthetic JSON fixture.
        "https://mail.proton.me/api/mail/v4/messages?Page=0&PageSize=50&Limit=nope&Sort=Time&Desc=1",
        // jig-ignore-next-line: indivisible synthetic URL fixture.
        "https://mail.proton.me/api/mail/v4/messages?Page=4294967296&PageSize=50&Limit=50&Sort=Time&Desc=1",
        // jig-ignore-next-line: indivisible synthetic URL fixture.
        "https://mail.proton.me/api/mail/v4/messages?Limit=50&Anchor=nope&AnchorID=m-50&Sort=Time&Desc=1",
        // jig-ignore-next-line: indivisible synthetic JSON fixture.
        "https://mail.proton.me/api/mail/v4/messages?Page=0&PageSize=50&Limit=50&Sort=Time&Desc=1&Limit=50",
    ] {
        assert_eq!(
            capture.observe(&json!({
                "sessionId":"session-1",
                "method":"Network.requestWillBeSent",
                // jig-ignore-next-line: indivisible synthetic JSON fixture.
                "params":{"requestId":"bad","request":{"method":"GET","url":url}}
            })),
            Err(MessageListNetworkError::MalformedEvent)
        );
    }
}
