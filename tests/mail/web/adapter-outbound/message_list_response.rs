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

use mail_web_adapter::MessageListNetworkCapture;
use mail_web_adapter::MessageListReconciliationError;
use mail_web_adapter::ReconciledVisibleMessageMetadata;
use mail_web_adapter::{MessageListResponseError, ObservedMessageListResponse};

const URL: &str = concat!(
    "https://mail.proton.me/api/mail/v4/messages",
    "?Page=0&PageSize=50&Limit=50&Sort=Time&Desc=1"
);

#[test]
fn retained_message_list_response_values_require_drop_custody() {
    use mail_web_adapter::ObservedMessageMetadata;

    #[expect(drop_bounds, reason = "require metadata scrubbing")]
    fn requires_scrub_on_drop<T>()
    where
        T: Drop,
    {
    }
    requires_scrub_on_drop::<ObservedMessageMetadata>();
}

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
fn redirected_into_exact_message_list_get_is_not_fresh_evidence() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    // Chromium reuses a request ID when an unrelated GET redirects into the
    // exact list URL. The intermediate request may have been ignored.
    let redirected = json!({
        "sessionId":"session-1",
        "method":"Network.requestWillBeSent",
        "params":{
            "requestId":"redirected-list",
            "request":{"method":"GET","url":URL},
            "redirectResponse":{
                "url":"https://mail.proton.me/elsewhere",
                "status":302u16
            }
        }
    });
    assert_eq!(
        capture.observe(&redirected),
        Err(MessageListNetworkError::RedirectedAway)
    );
    assert!(capture.take_finished_request_ids().is_empty());
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
fn network_capture_equality_excludes_randomized_fingerprint_state() {
    let left = MessageListNetworkCapture::new("session-1");
    let right = MessageListNetworkCapture::new("session-1");
    assert_eq!(left, right);
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
    let untracked_response = json!({
        "sessionId":"session-1",
        "method":"Network.responseReceived",
        "params":{"requestId":"untracked","response":{
            // jig-ignore-next-line: indivisible synthetic URL fixture.
            "url":"https://mail.proton.me/","status":200u16,"mimeType":"text/html"
        }}
    });
    capture
        .observe(&untracked_response)
        .expect("ignore untracked response before URL inspection");
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
    assert_eq!(capture.take_finished_request_ids().len(), 0);
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
    assert_eq!(empty.messages().len(), 0);
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
            "https://mail.proton.me/api/mail/v4/messages?LabelID=sent&Desc=1&Sort=Time&AnchorID=m-50&Anchor=7&Limit=50",
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
    assert_eq!(capture.take_finished_request_ids().len(), 0);

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

#[test]
fn consumed_message_list_id_rejects_late_network_lifecycle_events() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;
    let request = json!({
        "sessionId":"session-1",
        "method":"Network.requestWillBeSent",
        "params":{"requestId":"list-1","request":{"method":"GET","url":URL}}
    });
    let response = json!({
        "sessionId":"session-1",
        "method":"Network.responseReceived",
        "params":{"requestId":"list-1","response":{
            "url":URL,"status":200u16,"mimeType":"application/json"}}
    });
    let finished = json!({
        "sessionId":"session-1", "method":"Network.loadingFinished",
        "params":{"requestId":"list-1"}
    });
    let failure = json!({
        "sessionId":"session-1", "method":"Network.loadingFailed",
        "params":{"requestId":"list-1"}
    });
    let changed_method = json!({
        "sessionId":"session-1", "method":"Network.requestWillBeSent",
        "params":{"requestId":"list-1","request":{"method":"POST","url":URL}}
    });
    let mut capture = MessageListNetworkCapture::new("session-1");
    capture.observe(&request).expect("observe exact request");
    capture
        .observe(&response)
        .expect("observe matching response");
    capture
        .observe(&finished)
        .expect("finish matching response");
    assert_eq!(capture.take_finished_request_ids(), ["list-1"]);
    let mut untouched = MessageListNetworkCapture::new("session-1");
    untouched
        .observe(&request)
        .expect("observe still-pending request");
    untouched
        .observe(&response)
        .expect("observe still-pending response");
    assert_ne!(capture, untouched);
    for late in [request, changed_method, response, finished, failure] {
        assert_eq!(
            capture.observe(&late),
            Err(MessageListNetworkError::InvalidSequence)
        );
    }
    assert_eq!(capture.take_finished_request_ids().len(), 0);
    assert!(!format!("{capture:?}").contains("list-1"));
}

#[test]
fn completed_message_list_ids_are_bounded_across_consumption() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;
    let mut capture = MessageListNetworkCapture::new("session-1");
    for index in 0u16..128u16 {
        let request_id = format!("sensitive-list-{index}");
        let request = json!({
            "sessionId":"session-1", "method":"Network.requestWillBeSent",
            // jig-ignore-next-line: canonical rustfmt line.
            "params":{"requestId":request_id,"request":{"method":"GET","url":URL}}
        });
        let response = json!({
            "sessionId":"session-1", "method":"Network.responseReceived",
            "params":{"requestId":request_id,"response":{
                "url":URL,"status":200u16,"mimeType":"application/json"}}
        });
        let finished = json!({
            "sessionId":"session-1", "method":"Network.loadingFinished",
            "params":{"requestId":request_id}
        });
        capture
            .observe(&request)
            .expect("track bounded list request");
        capture
            .observe(&response)
            .expect("match bounded list response");
        capture
            .observe(&finished)
            .expect("finish bounded list response");
        assert_eq!(capture.take_finished_request_ids(), [request_id]);
    }
    let overflow = json!({
        "sessionId":"session-1", "method":"Network.requestWillBeSent",
        "params":{"requestId":"overflow","request":{"method":"GET","url":URL}}
    });
    assert_eq!(
        capture.observe(&overflow),
        Err(MessageListNetworkError::CapacityExceeded)
    );
    assert!(!format!("{capture:?}").contains("sensitive-list-"));
}

#[test]
fn exact_message_list_request_ids_are_bounded_before_tracking() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;
    for id in [String::new(), "x".repeat(513)] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        let event = json!({
            "sessionId":"session-1", "method":"Network.requestWillBeSent",
            "params":{"requestId":id,"request":{"method":"GET","url":URL}}
        });
        assert_eq!(
            capture.observe(&event),
            Err(MessageListNetworkError::MalformedEvent)
        );
        assert_eq!(capture.take_finished_request_ids().len(), 0);
    }
    let mut capture = MessageListNetworkCapture::new("session-1");
    let unrelated = json!({
        "sessionId":"session-1", "method":"Network.requestWillBeSent",
        "params":{"requestId":"x".repeat(1024), "request":{
            // jig-ignore-next-line: canonical rustfmt line.
            "method":"GET", "url":"https://mail.proton.me/api/mail/v4/messages/count"
        }}
    });
    capture
        .observe(&unrelated)
        .expect("ignore unrelated browser traffic");
    assert_eq!(capture.take_finished_request_ids().len(), 0);
}

#[test]
fn message_list_cdp_url_length_is_bounded_before_query_hashing() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;
    const CEILING: usize = 16_384;
    let make_event = |url: &str| {
        json!({
            "sessionId":"session-1", "method":"Network.requestWillBeSent",
            // jig-ignore-next-line: canonical rustfmt line.
            "params":{"requestId":"bounded","request":{"method":"GET","url":url}}
        })
    };
    let prefix = format!("{URL}&Filter=");
    let accepted = format!("{prefix}{}", "x".repeat(CEILING - prefix.len()));
    assert_eq!(accepted.len(), CEILING);
    let mut capture = MessageListNetworkCapture::new("session-1");
    capture
        .observe(&make_event(&accepted))
        .expect("accept bounded exact URL");
    let oversized = format!("{accepted}x");
    let mut rejected = MessageListNetworkCapture::new("session-1");
    assert_eq!(
        rejected.observe(&make_event(&oversized)),
        Err(MessageListNetworkError::MalformedEvent)
    );
    let response = json!({
        "sessionId":"session-1", "method":"Network.responseReceived",
        "params":{"requestId":"bounded","response":{
            "url":oversized,"status":200u16,"mimeType":"application/json"
        }}
    });
    assert_eq!(
        capture.observe(&response),
        Err(MessageListNetworkError::ResponseRejected)
    );
    let unrelated = json!({
        "sessionId":"session-1", "method":"Network.requestWillBeSent",
        "params":{"requestId":"background","request":{"method":"GET","url":
            // jig-ignore-next-line: canonical rustfmt line.
            format!("https://mail.proton.me/api/mail/v4/messages/count?{}", "x".repeat(20000))
        }}
    });
    rejected
        .observe(&unrelated)
        .expect("ignore oversized unrelated GET");
    assert_eq!(rejected.take_finished_request_ids().len(), 0);
}

#[test]
fn fragment_bearing_message_list_urls_are_not_exact_network_gets() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;
    let fragment = format!("{URL}#synthetic-fragment");
    assert_eq!(
        ObservedMessageListResponse::parse(
            "GET",
            &fragment,
            r#"{"Stale":0,"Total":0,"Messages":[]}"#
        ),
        Err(MessageListResponseError::UnexpectedEndpoint)
    );
    let mut capture = MessageListNetworkCapture::new("session-1");
    let untracked = json!({
        "sessionId":"session-1", "method":"Network.requestWillBeSent",
        // jig-ignore-next-line: canonical rustfmt line.
        "params":{"requestId":"fragment","request":{"method":"GET","url":fragment}}
    });
    capture
        .observe(&untracked)
        .expect("ignore non-network fragment GET");
    let valid = json!({
        "sessionId":"session-1", "method":"Network.requestWillBeSent",
        "params":{"requestId":"tracked","request":{"method":"GET","url":URL}}
    });
    capture.observe(&valid).expect("track exact network GET");
    let redirect = json!({
        "sessionId":"session-1", "method":"Network.requestWillBeSent",
        // jig-ignore-next-line: canonical rustfmt line.
        "params":{"requestId":"tracked","request":{"method":"GET","url":fragment}}
    });
    assert_eq!(
        capture.observe(&redirect),
        Err(MessageListNetworkError::RedirectedAway)
    );
}

#[test]
fn repeated_message_list_filter_order_remains_part_of_query_identity() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;
    let initial = concat!(
        "https://mail.proton.me/api/mail/v4/messages?",
        "Page=0&PageSize=50&Limit=50&Sort=Time&Desc=1&",
        "LabelID=alpha&LabelID=beta&Unread=1"
    );
    let continued = concat!(
        "https://mail.proton.me/api/mail/v4/messages?",
        "Unread=1&Desc=1&Sort=Time&Limit=50&Anchor=7&AnchorID=m-50&",
        "LabelID=alpha&LabelID=beta"
    );
    let reordered_values = concat!(
        "https://mail.proton.me/api/mail/v4/messages?",
        "Unread=1&Desc=1&Sort=Time&Limit=50&Anchor=7&AnchorID=m-50&",
        "LabelID=beta&LabelID=alpha"
    );
    let request = |id: &str, url: &str| {
        json!({
            "sessionId":"session-1", "method":"Network.requestWillBeSent",
            "params":{"requestId":id,"request":{"method":"GET","url":url}}
        })
    };
    let mut safe = MessageListNetworkCapture::new("session-1");
    safe.observe(&request("first", initial))
        .expect("observe initial list");
    safe.observe(&request("second", continued))
        .expect("different key order preserves equivalent filter sequence");
    let mut unsafe_capture = MessageListNetworkCapture::new("session-1");
    unsafe_capture
        .observe(&request("first", initial))
        .expect("observe initial filtered list");
    assert_eq!(
        unsafe_capture.observe(&request("second", reordered_values)),
        Err(MessageListNetworkError::QueryContextChanged)
    );
    for secret in ["LabelID", "alpha", "beta", "Unread"] {
        assert!(!format!("{unsafe_capture:?}").contains(secret));
    }
}

#[test]
fn direct_list_projector_refuses_oversized_request_urls() {
    let prefix = format!("{URL}&Synthetic=");
    let accepted = format!("{prefix}{}", "x".repeat(16_384 - prefix.len()));
    assert_eq!(accepted.len(), 16_384);
    assert!(
        ObservedMessageListResponse::parse(
            "GET",
            &accepted,
            r#"{"Stale":0,"Total":0,"Messages":[]}"#
        )
        .is_ok()
    );
    let oversized = format!("{accepted}x");
    assert_eq!(
        ObservedMessageListResponse::parse(
            "GET",
            &oversized,
            r#"{"Stale":0,"Total":0,"Messages":[]}"#
        ),
        Err(MessageListResponseError::UnexpectedEndpoint)
    );
}

#[test]
// jig-ignore-next-line: canonical rustfmt line.
fn completed_message_list_get_cannot_be_turned_into_failed_list_before_consumption() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;
    let mut capture = MessageListNetworkCapture::new("session-1");
    capture
        .observe(&json!({
            "sessionId":"session-1", "method":"Network.requestWillBeSent",
            // jig-ignore-next-line: canonical rustfmt line.
            "params":{"requestId":"done-secret","request":{"method":"GET","url":URL}}
        }))
        .expect("track app-owned GET");
    capture
        .observe(&json!({
            "sessionId":"session-1", "method":"Network.responseReceived",
            "params":{"requestId":"done-secret","response":{
                "url":URL,"status":200u16,"mimeType":"application/json"
            }}
        }))
        .expect("match exact list response");
    capture
        .observe(&json!({
            "sessionId":"session-1", "method":"Network.loadingFinished",
            "params":{"requestId":"done-secret"}
        }))
        .expect("complete app-owned GET");
    assert_eq!(
        capture.observe(&json!({
            "sessionId":"session-1", "method":"Network.loadingFailed",
            "params":{"requestId":"done-secret"}
        })),
        Err(MessageListNetworkError::InvalidSequence)
    );
    assert_eq!(capture.take_finished_request_ids(), ["done-secret"]);
    assert_eq!(capture.take_finished_request_ids().len(), 0);
    assert!(!format!("{capture:?}").contains("done-secret"));
}

#[test]
fn list_projection_rejects_unsafe_message_route_ids() {
    use serde_json::json;
    let bad_ids = [
        "encoded%2Fslash",
        "%2e",
        "%2E%2E",
        "direction\u{202e}flip",
        "invisible\u{200b}join",
        "isolated\u{2066}id\u{2069}",
        "soft\u{ad}hyphen",
        "combining\u{34f}joiner",
        "mongolian\u{180e}separator",
        "format\u{070f}control",
        "format\u{fff9}annotation",
        "format\u{13430}joiner",
        "invisible\u{2061}function",
        "deprecated\u{206a}direction",
        "unicode\u{e0020}tag",
        "with/slash",
        "with?query",
        "with#fragment",
        "with\\backslash",
        "with space",
        "with\nnewline",
        "with\ttab",
        "with\rreturn",
        "with\u{a0}nbsp",
        "with\u{7f}del",
        "",
        ".",
        "..",
    ];
    for bad in bad_ids {
        let body = json!({
            "Stale":0u8,"Total":1u8,
            "Messages":[{"ID":bad,"Time":1u64,"Order":2i64}]
        })
        .to_string();
        assert_eq!(
            ObservedMessageListResponse::parse("GET", URL, &body),
            Err(MessageListResponseError::Malformed)
        );
    }
    for valid in ["opaque+_~=", &"x".repeat(512)] {
        let body = json!({
            "Stale":0u8,"Total":1u8,
            "Messages":[{"ID":valid,"Time":1u64,"Order":2i64}]
        })
        .to_string();
        let result = ObservedMessageListResponse::parse("GET", URL, &body)
            .expect("accept safe bounded opaque provider ID");
        assert_eq!(result.messages()[0].id(), valid);
    }
}

#[test]
fn visible_message_ids_are_checked_before_metadata_lookup() {
    use std::slice::from_ref;
    let good = ObservedMessageListResponse::parse(
        "GET",
        URL,
        r#"{"Stale":0,"Total":1,"Messages":[{"ID":"m-1","Time":1,"Order":1}]}"#,
    )
    .expect("parse synthetic metadata");
    for id in ["", "m/1", "m?1", "m#1", "m\\1", "m 1", "m\n1", "m\u{a0}1"] {
        assert_eq!(
            ReconciledVisibleMessageMetadata::reconcile(&[id], from_ref(&good)),
            Err(MessageListReconciliationError::InvalidVisibleId)
        );
    }
    let oversized = "x".repeat(513);
    assert_eq!(
        ReconciledVisibleMessageMetadata::reconcile(&[&oversized], &[good]),
        Err(MessageListReconciliationError::InvalidVisibleId)
    );
}

#[test]
fn message_list_anchor_id_rejects_unsafe_route_components() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;
    let request = |url: &str| {
        json!({
            "sessionId":"session-1", "method":"Network.requestWillBeSent",
            // jig-ignore-next-line: canonical rustfmt line.
            "params":{"requestId":"next-page","request":{"method":"GET","url":url}}
        })
    };
    for bad in [
        "encoded%2Fslash",
        "%2e",
        "%2E%2E",
        "direction\u{202e}flip",
        "invisible\u{200b}join",
        "isolated\u{2066}id\u{2069}",
        "bad/id",
        "bad?id",
        "bad\\id",
        "bad id",
        "bad\nid",
        "bad\tid",
        "bad\rid",
        "bad\u{a0}id",
        "bad\u{85}id",
        "bad\u{2003}id",
        ".",
        "..",
    ] {
        let url = format!(
            // jig-ignore-next-line: canonical rustfmt line.
            "https://mail.proton.me/api/mail/v4/messages?Limit=50&Anchor=7&AnchorID={bad}&Sort=Time&Desc=1"
        );
        let mut capture = MessageListNetworkCapture::new("session-1");
        assert_eq!(
            capture.observe(&request(&url)),
            Err(MessageListNetworkError::MalformedEvent)
        );
        assert_eq!(capture.take_finished_request_ids().len(), 0);
    }
    let safe = concat!(
        "https://mail.proton.me/api/mail/v4/messages?Limit=50&Anchor=7&",
        "AnchorID=opaque+_~=&Sort=Time&Desc=1"
    );
    let mut capture = MessageListNetworkCapture::new("session-1");
    capture
        .observe(&request(safe))
        .expect("safe opaque anchor remains valid");
}

#[test]
fn numeric_message_list_query_fields_require_bounded_decimal_evidence() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;
    for (field, invalid) in [
        ("Page", "00"),
        ("Page", "01"),
        ("PageSize", "050"),
        ("Limit", "050"),
        ("Desc", "01"),
        ("Anchor", "007"),
        ("Page", "+1"),
        ("Page", " 1"),
        ("Page", "%31"),
        ("PageSize", "+50"),
        ("Limit", "+50"),
        ("Desc", "+1"),
        ("Desc", "1.0"),
        ("Anchor", "-1"),
        ("Anchor", "+1"),
        ("Anchor", "1e5"),
        ("Anchor", "18446744073709551616"),
    ] {
        let initial = "Page=0&PageSize=50&Limit=50&Sort=Time&Desc=1";
        // jig-ignore-next-line: canonical rustfmt line.
        let continuation = "Anchor=7&AnchorID=opaque+_~=&Limit=50&Sort=Time&Desc=1";
        let source = if field == "Anchor" {
            continuation
        } else {
            initial
        };
        let needle = format!(
            "{field}={}",
            match field {
                "Page" => "0",
                "PageSize" | "Limit" => "50",
                "Desc" => "1",
                _ => "7",
            }
        );
        let query = source.replacen(&needle, &format!("{field}={invalid}"), 1);
        // jig-ignore-next-line: canonical rustfmt line.
        let url = format!("https://mail.proton.me/api/mail/v4/messages?{query}");
        let mut capture = MessageListNetworkCapture::new("session-1");
        assert_eq!(
            capture.observe(&json!({
                "sessionId":"session-1", "method":"Network.requestWillBeSent",
                // jig-ignore-next-line: canonical rustfmt line.
                "params":{"requestId":"bad-decimal","request":{"method":"GET","url":url}}
            })),
            Err(MessageListNetworkError::MalformedEvent)
        );
        assert_eq!(capture.take_finished_request_ids().len(), 0);
    }
}

#[test]
fn explicitly_rejected_message_list_code_cannot_become_read_metadata() {
    use serde_json::json;
    for invalid in [
        json!(0u64),
        json!(2001u64),
        json!("1000"),
        json!(-1i32),
        json!(null),
        json!(true),
    ] {
        let body = json!({
            "Code":invalid,"Stale":0u8,"Total":1u8,
            "Messages":[{"ID":"synthetic-message","Time":1u8,"Order":1i8}]
        })
        .to_string();
        assert_eq!(
            ObservedMessageListResponse::parse("GET", URL, &body),
            Err(MessageListResponseError::ProviderRejected)
        );
    }
    for success in [None, Some(json!(1000u64))] {
        let mut body = json!({"Stale":0u8,"Total":0u8,"Messages":[]});
        if let Some(code) = success {
            body["Code"] = code;
        }
        // jig-ignore-next-line: canonical rustfmt line.
        let parsed = ObservedMessageListResponse::parse("GET", URL, &body.to_string())
            .expect("valid or absent Code remains compatible");
        assert_eq!(parsed.total(), 0);
        assert_eq!(parsed.messages().len(), 0);
    }
}

#[test]
fn message_reconciliation_rejects_total_contradictions() {
    let empty_positive =
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedMessageListResponse::parse("GET", URL, r#"{"Stale":0,"Total":3,"Messages":[]}"#)
            // jig-ignore-next-line: canonical rustfmt line.
            .expect("fresh empty batch may be a continuation beyond current rows");
    assert_eq!(
        ReconciledVisibleMessageMetadata::reconcile(&[], &[empty_positive]),
        Err(MessageListReconciliationError::UnexpectedObservedMessage)
    );
    let first = ObservedMessageListResponse::parse(
        "GET",
        URL,
        r#"{"Stale":0,"Total":2,"Messages":[{"ID":"m-2","Time":2,"Order":2}]}"#,
    )
    .expect("parse first synthetic batch");
    let changed = ObservedMessageListResponse::parse(
        "GET",
        URL,
        r#"{"Stale":0,"Total":3,"Messages":[{"ID":"m-1","Time":1,"Order":1}]}"#,
    )
    .expect("parse changed-total synthetic batch");
    // jig-ignore-next-line: canonical rustfmt line.
    let continued = ReconciledVisibleMessageMetadata::reconcile(&["m-2", "m-1"], &[first, changed])
        .expect("anchored continuation Total is scoped to the remainder");
    assert_eq!(continued.messages().len(), 2);
    let zero =
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedMessageListResponse::parse("GET", URL, r#"{"Stale":0,"Total":0,"Messages":[]}"#)
            .expect("parse actually empty catalog");
    let empty = ReconciledVisibleMessageMetadata::reconcile(&[], &[zero])
        // jig-ignore-next-line: canonical rustfmt line.
        .expect("explicit empty page with zero provider total remains consistent");
    assert_eq!(empty.messages().len(), 0);
}

#[test]
fn encoded_query_key_aliases_cannot_establish_provider_sort_evidence() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;
    // jig-ignore-next-line: canonical alias fixture.
    let aliases = ["%53ort=Size", "So%72t=Size", "%42eginID=hidden", "Pa%67e=2"];
    for alias in aliases {
        let mut capture = MessageListNetworkCapture::new("synthetic-session");
        let url = format!("{URL}&{alias}");
        let result = capture.observe(&json!({
            "sessionId":"synthetic-session",
            "method":"Network.requestWillBeSent",
            "params":{"requestId":"synthetic",
                "request":{"method":"GET","url":url}}
        }));
        assert_eq!(result, Err(MessageListNetworkError::MalformedEvent));
    }
}

#[test]
fn message_list_body_envelope_rejects_unexpected_cdp_fields() {
    use serde_json::json;
    let mut response = json!({
        "body":r#"{"Stale":0,"Total":0,"Messages":[]}"#,
        "base64Encoded":false
    });
    assert!(ObservedMessageListResponse::parse_cdp_body(&response).is_ok());
    response["unrecognized"] = json!(true);
    assert_eq!(
        ObservedMessageListResponse::parse_cdp_body(&response),
        Err(MessageListResponseError::Malformed)
    );
}

#[test]
fn case_aliases_of_message_list_query_selectors_fail_closed() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    for alias in ["sort=Size", "desc=0", "page=2", "limit=1", "beginid=decoy"] {
        let mut capture = MessageListNetworkCapture::new("synthetic-session");
        let url = format!("{URL}&{alias}");
        let event = json!({
            "sessionId":"synthetic-session",
            "method":"Network.requestWillBeSent",
            "params":{"requestId":"synthetic",
                "request":{"method":"GET","url":url}}
        });
        assert_eq!(
            capture.observe(&event),
            Err(MessageListNetworkError::MalformedEvent)
        );
    }
}

#[test]
fn explicit_empty_reconciliation_rejects_later_positive_total() {
    let empty_body = r#"{"Stale":0,"Total":0,"Messages":[]}"#;
    let positive_body = r#"{"Stale":0,"Total":2,"Messages":[]}"#;
    let zero = ObservedMessageListResponse::parse("GET", URL, empty_body)
        .expect("parse initial empty response");
    let positive = ObservedMessageListResponse::parse("GET", URL, positive_body)
        .expect("parse inconsistent later empty response");
    let batches = [zero, positive];
    let result = ReconciledVisibleMessageMetadata::reconcile(&[], &batches);
    let rejected = MessageListReconciliationError::UnexpectedObservedMessage;
    assert_eq!(result, Err(rejected));
}

#[test]
fn message_metadata_reconciliation_rejects_unbounded_batch_chain() {
    let body = r#"{"Stale":0,"Total":0,"Messages":[]}"#;
    let parsed = ObservedMessageListResponse::parse("GET", URL, body);
    let response = parsed.expect("parse synthetic empty batch");
    let responses = [response.clone(), response.clone(), response];
    // jig-ignore-next-line: canonical rustfmt bounded-batch call.
    let reconciled = ReconciledVisibleMessageMetadata::reconcile(&[], &responses);
    assert_eq!(
        reconciled,
        Err(MessageListReconciliationError::TooManyObservedBatches)
    );
}

#[test]
fn rejected_private_continuation_selector_never_reaches_capture_diagnostics() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let request = |id: &str, url: &str| {
        json!({
            "sessionId":"session-1", "method":"Network.requestWillBeSent",
            "params":{"requestId":id,"request":{"method":"GET","url":url}}
        })
    };
    let mut capture = MessageListNetworkCapture::new("session-1");
    let initial = concat!(
        "https://mail.proton.me/api/mail/v4/messages?",
        "Page=0&PageSize=50&Limit=50&Sort=Time&Desc=1&LabelID=inbox"
    );
    capture
        .observe(&request("initial", initial))
        .expect("initial batch");

    let malformed = concat!(
        "https://mail.proton.me/api/mail/v4/messages?",
        "Limit=50&Anchor=7&AnchorID=synthetic-private-anchor&",
        "PageSize=50&Sort=Time&Desc=1&LabelID=inbox"
    );
    assert_eq!(capture.observe(&request("bad-shape", malformed)), Ok(()));

    let drifted = concat!(
        "https://mail.proton.me/api/mail/v4/messages?",
        "Limit=50&Anchor=7&AnchorID=synthetic-private-anchor&",
        "Sort=Time&Desc=1&LabelID=other-folder"
    );
    let result = capture.observe(&request("drifted", drifted));
    assert_eq!(result, Err(MessageListNetworkError::QueryContextChanged));
    let diagnostic = format!("{capture:?} {result:?}");
    assert!(!diagnostic.contains("synthetic-private-anchor"));
    assert!(!diagnostic.contains("other-folder"));
}
