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
fn detached_redirect_has_extra_info_cannot_authorize_list_read() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    let event = json!({
        "sessionId":"session-1", "method":"Network.requestWillBeSent",
        "params":{"requestId":"redirect-hint", "type":"Fetch",
            "redirectHasExtraInfo":false,
            "request":{"method":"GET", "url":URL}}
    });
    assert_eq!(
        capture.observe(&event),
        Err(MessageListNetworkError::MalformedEvent)
    );
    assert!(capture.take_finished_request_ids().is_empty());
}

#[test]
fn parser_or_signed_exchange_cannot_initiate_passive_mail_ajax_read() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let invalid_initiators = [("XHR", "parser"), ("Fetch", "SignedExchange")];
    for (resource, initiator) in invalid_initiators {
        let event = json!({
            "sessionId":"session-1", "method":"Network.requestWillBeSent",
            "params":{"requestId":"non-ajax-list", "type":resource,
                "initiator":{"type":initiator},
                "request":{"method":"GET", "url":URL}}
        });
        let mut capture = MessageListNetworkCapture::new("session-1");
        assert_eq!(
            capture.observe(&event),
            Err(MessageListNetworkError::MalformedEvent),
            "non-AJAX initiator {initiator} cannot authorize a list read"
        );
        assert!(capture.take_finished_request_ids().is_empty());
    }
}

#[test]
fn speculative_event_initiator_hint_cannot_authorize_mail_list_capture() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    for source in ["event", "initiator"] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        let mut request = json!({
            "sessionId": "session-1", "method": "Network.requestWillBeSent",
            "params": {"requestId": "synthetic-list", "type": "Fetch",
                "initiator": {"type": "script"},
                "request": {"method": "GET", "url": URL}}
        });
        if source == "event" {
            request["params"]["isPrefetch"] = json!(true);
        } else {
            request["params"]["initiator"]["wasPreloaded"] = json!(false);
        }
        assert_eq!(
            capture.observe(&request),
            Err(MessageListNetworkError::MalformedEvent)
        );
        assert!(capture.take_finished_request_ids().is_empty());
    }
}

#[test]
fn unreviewed_request_speculation_cannot_authorize_message_list_capture() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    let request = json!({
        "sessionId": "session-1", "method": "Network.requestWillBeSent",
        "params": {"requestId": "prefetched-list", "type": "Fetch",
            "initiator": {"type": "script"}, "request": {
                "method": "GET", "url": URL, "isLinkPreload": false,
                "IsLinkPreload": true
            }}
    });
    assert_eq!(
        capture.observe(&request),
        Err(MessageListNetworkError::MalformedEvent)
    );
    assert!(capture.take_finished_request_ids().is_empty());
}

#[test]
fn foreign_origin_header_cannot_authorize_mail_list_capture() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    let request = json!({
        "sessionId": "session-1", "method": "Network.requestWillBeSent",
        "params": {"requestId": "synthetic-list", "type": "Fetch",
            "initiator": {"type": "script"}, "request": {
                "method": "GET", "url": URL,
                "headers": {"Origin": "https://evil.invalid"}
            }}
    });
    assert_eq!(
        capture.observe(&request),
        Err(MessageListNetworkError::MalformedEvent)
    );
    assert!(capture.take_finished_request_ids().is_empty());
}

#[test]
fn cross_site_request_hint_cannot_authorize_mail_message_list_capture() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    let request = json!({
        "sessionId": "session-1", "method": "Network.requestWillBeSent",
        "params": {"requestId": "synthetic-list", "type": "Fetch",
            "initiator": {"type": "script"}, "request": {
                "method": "GET", "url": URL, "isSameSite": false
            }}
    });
    assert_eq!(
        capture.observe(&request),
        Err(MessageListNetworkError::MalformedEvent)
    );
    assert!(capture.take_finished_request_ids().is_empty());
}

#[test]
fn method_override_header_cannot_authorize_mail_message_list_capture() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    let request = json!({
        "sessionId": "session-1", "method": "Network.requestWillBeSent",
        "params": {"requestId": "synthetic-list", "type": "Fetch",
            "initiator": {"type": "script"}, "request": {
                "method": "GET", "url": URL,
                "headers": {"X-HTTP-Method-Override": "POST"}
            }}
    });
    assert_eq!(
        capture.observe(&request),
        Err(MessageListNetworkError::MalformedEvent)
    );
    assert!(capture.take_finished_request_ids().is_empty());
}

#[test]
fn only_if_cached_get_cannot_authorize_message_list_capture() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    let request = json!({
        "sessionId": "session-1", "method": "Network.requestWillBeSent",
        "params": {"requestId": "synthetic-list", "type": "Fetch",
            "initiator": {"type": "script"}, "request": {
                "method": "GET", "url": URL,
                "headers": {"Cache-Control": "only-if-cached"}
            }}
    });
    assert_eq!(
        capture.observe(&request),
        Err(MessageListNetworkError::MalformedEvent)
    );
    assert!(capture.take_finished_request_ids().is_empty());
}

#[test]
fn duplicate_host_alias_cannot_authorize_mail_message_list_capture() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    let request = json!({
        "sessionId": "session-1", "method": "Network.requestWillBeSent",
        "params": {"requestId": "synthetic-list", "type": "Fetch",
            "initiator": {"type": "script"}, "request": {
                "method": "GET", "url": URL,
                "headers": {"Host": "mail.proton.me", "host": "mail.proton.me"}
            }}
    });
    assert_eq!(
        capture.observe(&request),
        Err(MessageListNetworkError::MalformedEvent)
    );
    assert!(capture.take_finished_request_ids().is_empty());
}

#[test]
fn unreviewed_method_override_alias_cannot_authorize_list_get() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let event = json!({
        "sessionId":"session-1", "method":"Network.requestWillBeSent",
        "params":{"requestId":"method-alias", "type":"Fetch",
            "request":{"method":"GET", "url":URL,
                "headers":{"Host":"mail.proton.me",
                    "X-Override-Method":"DELETE"}}}
    });
    let mut capture = MessageListNetworkCapture::new("session-1");
    assert_eq!(
        capture.observe(&event),
        Err(MessageListNetworkError::MalformedEvent)
    );
    assert!(capture.take_finished_request_ids().is_empty());
}

#[test]
fn forwarded_authority_cannot_authorize_mail_message_list_capture() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    let request = json!({
        "sessionId": "session-1", "method": "Network.requestWillBeSent",
        "params": {"requestId": "synthetic-list", "type": "Fetch",
            "initiator": {"type": "script"}, "request": {
                "method": "GET", "url": URL,
                "headers": {"Host": "mail.proton.me",
                    "X-Forwarded-Host": "foreign.invalid"}
            }}
    });
    assert_eq!(
        capture.observe(&request),
        Err(MessageListNetworkError::MalformedEvent)
    );
    assert!(capture.take_finished_request_ids().is_empty());
}

#[test]
fn forwarded_path_family_cannot_authorize_message_list_capture() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let event = json!({
        "sessionId":"session-1", "method":"Network.requestWillBeSent",
        "params":{"requestId":"forwarded-path", "type":"Fetch",
            "request":{"method":"GET", "url":URL,
                "headers":{"Host":"mail.proton.me",
                    "X-Forwarded-Path":"/rewritten"}}}
    });
    let mut capture = MessageListNetworkCapture::new("session-1");
    assert_eq!(
        capture.observe(&event),
        Err(MessageListNetworkError::MalformedEvent)
    );
    assert!(capture.take_finished_request_ids().is_empty());
}

#[test]
fn forwarded_prefix_cannot_authorize_mail_message_list_capture() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let request = json!({
        "sessionId":"session-1", "method":"Network.requestWillBeSent",
        "params":{"requestId":"forwarded-prefix", "type":"Fetch",
            "request":{"method":"GET", "url":URL,
                "headers":{"Host":"mail.proton.me",
                    "X-Forwarded-Prefix":"/rewritten"}}}
    });
    let mut capture = MessageListNetworkCapture::new("session-1");
    assert_eq!(
        capture.observe(&request),
        Err(MessageListNetworkError::MalformedEvent)
    );
    assert!(capture.take_finished_request_ids().is_empty());
}

#[test]
fn foreign_host_header_cannot_authorize_mail_message_list_capture() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    let request = json!({
        "sessionId": "session-1", "method": "Network.requestWillBeSent",
        "params": {"requestId": "synthetic-list", "type": "Fetch",
            "initiator": {"type": "script"}, "request": {
                "method": "GET", "url": URL,
                "headers": {"Host": "evil.invalid"}
            }}
    });
    assert_eq!(
        capture.observe(&request),
        Err(MessageListNetworkError::MalformedEvent)
    );
    assert!(capture.take_finished_request_ids().is_empty());
}

#[test]
fn foreign_referer_cannot_authorize_mail_message_list_capture() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    let request = json!({
        "sessionId": "session-1", "method": "Network.requestWillBeSent",
        "params": {"requestId": "synthetic-list", "type": "Fetch",
            "initiator": {"type": "script"}, "request": {
                "method": "GET", "url": URL,
                "headers": {"Referer": "https://foreign.invalid/frame"}
            }}
    });
    assert_eq!(
        capture.observe(&request),
        Err(MessageListNetworkError::MalformedEvent)
    );
    assert!(capture.take_finished_request_ids().is_empty());
}

#[test]
fn navigation_fetch_headers_cannot_authorize_message_list_capture() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    for (name, value) in [
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Mode", "no-cors"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Site", "cross-site"),
    ] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        let mut request = json!({
            "sessionId": "session-1", "method": "Network.requestWillBeSent",
            "params": {"requestId": "synthetic-list", "type": "Fetch",
                "initiator": {"type": "script"}, "request": {
                    "method": "GET", "url": URL,
                    "headers": {"Sec-Fetch-Mode": "cors"}
                }}
        });
        request["params"]["request"]["headers"][name] = json!(value);
        assert_eq!(
            capture.observe(&request),
            Err(MessageListNetworkError::MalformedEvent)
        );
        assert!(capture.take_finished_request_ids().is_empty());
    }
}

#[test]
fn speculative_purpose_header_cannot_authorize_message_list_capture() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    let request = json!({
        "sessionId": "session-1", "method": "Network.requestWillBeSent",
        "params": {"requestId": "prefetched-list", "type": "Fetch",
            "initiator": {"type": "script"}, "request": {
                "method": "GET", "url": URL, "isLinkPreload": false,
                "headers": {"Sec-Purpose": "prefetch"}
            }}
    });
    assert_eq!(
        capture.observe(&request),
        Err(MessageListNetworkError::MalformedEvent)
    );
    assert!(capture.take_finished_request_ids().is_empty());
}

#[test]
fn malformed_header_metadata_cannot_authorize_message_list_capture() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    for invalid in [
        json!(null),
        json!({"nested": "value"}),
        json!("ok\r\nInjected: x"),
    ] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        let request = json!({
            "sessionId": "session-1", "method": "Network.requestWillBeSent",
            "params": {"requestId": "synthetic-list", "request": {
                "method": "GET", "url": URL,
                "headers": {"Accept": invalid}
            }}
        });
        assert_eq!(
            capture.observe(&request),
            Err(MessageListNetworkError::MalformedEvent)
        );
        assert!(capture.take_finished_request_ids().is_empty());
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
fn network_capture_equality_excludes_randomized_fingerprint_state() {
    let left = MessageListNetworkCapture::new("session-1");
    let right = MessageListNetworkCapture::new("session-1");
    assert_eq!(left, right);
}

#[test]
fn refined_wire_headers_cannot_contradict_passive_message_list_get() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    capture
        .observe(&json!({
            "sessionId": "session-1", "method": "Network.requestWillBeSent",
            "params": {"requestId": "synthetic-list", "type": "Fetch",
                "request": {"method": "GET", "url": URL,
                    "headers": {"Host": "mail.proton.me"}}}
        }))
        .expect("track exact Mail GET");
    let response = json!({
        "sessionId": "session-1", "method": "Network.responseReceived",
        "params": {"requestId": "synthetic-list", "type": "Fetch",
            "response": {"url": URL, "status": 200u16,
                "mimeType": "application/json",
                "requestHeaders": {"Host": "foreign.invalid"}}
        }
    });
    assert_eq!(
        capture.observe(&response),
        Err(MessageListNetworkError::ResponseRejected)
    );
    assert!(capture.take_finished_request_ids().is_empty());
}

#[test]
fn raw_refined_request_headers_cannot_launder_mail_list_get() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let path = URL
        .strip_prefix("https://mail.proton.me")
        .expect("Mail URL");
    let request = json!({
        "sessionId":"session-1", "method":"Network.requestWillBeSent",
        "params":{"requestId":"raw-refined", "type":"Fetch",
            "request":{"method":"GET", "url":URL}}
    });
    let valid_raw =
        // jig-ignore-next-line: synthetic HTTP/1 wire fixture.
        format!("GET {path} HTTP/1.1\r\nHost: mail.proton.me\r\nCookie: private=test\r\n\r\n");
    for wire in [
        format!("POST {path} HTTP/1.1\r\nHost: mail.proton.me\r\n\r\n"),
        format!("GET {path} HTTP/1.1\r\nHost: foreign.invalid\r\n\r\n"),
        format!(
            // jig-ignore-next-line: synthetic HTTP/1 wire fixture.
            "GET {path} HTTP/1.1\r\nHost: mail.proton.me\r\nTransfer-Encoding: chunked\r\n\r\n"
        ),
    ] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        capture.observe(&request).expect("tracked Mail GET");
        let response = json!({
            "sessionId":"session-1", "method":"Network.responseReceived",
            "params":{"requestId":"raw-refined", "type":"Fetch",
                "response":{"url":URL, "status":200u16,
                    "mimeType":"application/json",
                    "requestHeaders":{"Host":"mail.proton.me"},
                    "requestHeadersText":wire}}
        });
        assert_eq!(
            capture.observe(&response),
            Err(MessageListNetworkError::ResponseRejected)
        );
        assert!(capture.take_finished_request_ids().is_empty());
    }
    let mut capture = MessageListNetworkCapture::new("session-1");
    capture.observe(&request).expect("tracked Mail GET");
    let response = json!({
        "sessionId":"session-1", "method":"Network.responseReceived",
        "params":{"requestId":"raw-refined", "type":"Fetch",
            "response":{"url":URL, "status":200u16,
                "mimeType":"application/json",
                "requestHeaders":{"Host":"mail.proton.me"},
                "requestHeadersText":valid_raw}}
    });
    capture.observe(&response).expect("consistent raw wire GET");
    capture
        .observe(&json!({
            "sessionId":"session-1", "method":"Network.loadingFinished",
            "params":{"requestId":"raw-refined"}
        }))
        .expect("finish matching request");
    assert_eq!(capture.take_finished_request_ids(), ["raw-refined"]);
}

#[test]
fn non_utf8_browser_charset_cannot_complete_mail_list_capture() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let request = json!({
        "sessionId":"session-1", "method":"Network.requestWillBeSent",
        "params":{"requestId":"charset", "type":"Fetch", "request":{
            "method":"GET", "url":URL}}
    });
    for charset in ["iso-8859-1", "utf-16", "x-user-defined"] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        capture.observe(&request).expect("track exact Mail GET");
        let response = json!({
            "sessionId":"session-1", "method":"Network.responseReceived",
            "params":{"requestId":"charset", "type":"Fetch", "response":{
                "url":URL, "status":200u16, "mimeType":"application/json",
                "headers":{"Content-Type":"application/json; charset=utf-8"},
                "charset":charset}}
        });
        assert_eq!(
            capture.observe(&response),
            Err(MessageListNetworkError::ResponseRejected)
        );
        assert!(capture.take_finished_request_ids().is_empty());
    }
}

#[test]
fn non_http_response_protocol_cannot_complete_mail_list_capture() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    for protocol in ["data", "file", "ws", "h2c"] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        capture
            .observe(&json!({
                "sessionId":"session-1", "method":"Network.requestWillBeSent",
                "params":{"requestId":"protocol", "type":"Fetch", "request":{
                    "method":"GET", "url":URL}}
            }))
            .expect("track canonical Mail GET");
        let response = json!({
            "sessionId":"session-1", "method":"Network.responseReceived",
            "params":{"requestId":"protocol", "type":"Fetch", "response":{
                "url":URL, "status":200u16, "mimeType":"application/json",
                "protocol":protocol}}
        });
        assert_eq!(
            capture.observe(&response),
            Err(MessageListNetworkError::ResponseRejected),
            "non-HTTP protocol must not prove Mail list capture"
        );
        assert!(capture.take_finished_request_ids().is_empty());
    }
}

#[test]
fn raw_initial_response_headers_cannot_launder_list_capture() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    capture
        .observe(&json!({
            "sessionId":"session-1", "method":"Network.requestWillBeSent",
            "params":{"requestId":"raw-response", "request":{
                "method":"GET", "url":URL}}
        }))
        .expect("track exact Mail GET");
    let response = json!({
        "sessionId":"session-1", "method":"Network.responseReceived",
        "params":{"requestId":"raw-response", "response":{
            "url":URL, "status":200u16, "mimeType":"application/json",
            "headers":{"Content-Type":"application/json"},
            // jig-ignore-next-line: synthetic HTTP/1 response CRLF fixture.
            "headersText":"HTTP/1.1 304 Not Modified\r\nContent-Type: application/json\r\n\r\n"}}
    });
    assert_eq!(
        capture.observe(&response),
        Err(MessageListNetworkError::ResponseRejected)
    );
}

#[test]
fn duplicate_mime_extension_parameters_cannot_complete_mail_list_capture() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    capture
        .observe(&json!({
            "sessionId":"session-1", "method":"Network.requestWillBeSent",
            "params":{"requestId":"duplicate-mime", "request":{
                "method":"GET", "url":URL}}
        }))
        .expect("canonical Mail GET");
    let duplicate_type = "application/json; profile=v1; PROFILE=v2";
    let event = json!({
        "sessionId":"session-1", "method":"Network.responseReceived",
        "params":{"requestId":"duplicate-mime", "response":{
            "url":URL, "status":200u16, "mimeType":"application/json",
            "headers":{"Content-Type":duplicate_type}}}
    });
    assert_eq!(
        capture.observe(&event),
        Err(MessageListNetworkError::ResponseRejected)
    );
}

#[test]
fn malformed_mime_parameter_cannot_complete_mail_list_capture() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    capture
        .observe(&json!({
            "sessionId":"session-1", "method":"Network.requestWillBeSent",
            "params":{"requestId":"mime-params", "request":{
                "method":"GET", "url":URL}}
        }))
        .expect("canonical Mail GET");
    let event = json!({
        "sessionId":"session-1", "method":"Network.responseReceived",
        "params":{"requestId":"mime-params", "response":{
            "url":URL, "status":200u16, "mimeType":"application/json",
            "headers":{"Content-Type":"application/json; profile=bad value"}}}
    });
    assert_eq!(
        capture.observe(&event),
        Err(MessageListNetworkError::ResponseRejected)
    );
}

#[test]
fn response_headers_cannot_disagree_with_message_list_json_mime() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    for content_type in [
        "text/html",
        "application/javascript",
        "application/json; charset=utf-8, text/html",
        "application/json; charset=iso-8859-1",
        "application/json; charset=utf-8; charset=iso-8859-1",
    ] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        capture
            .observe(&json!({
                "sessionId":"session-1", "method":"Network.requestWillBeSent",
                "params":{"requestId":"response-headers", "request":{
                    "method":"GET", "url":URL}}
            }))
            .expect("track provider GET");
        let response = json!({
            "sessionId":"session-1", "method":"Network.responseReceived",
            "params":{"requestId":"response-headers", "response":{
                "url":URL, "status":200u16, "mimeType":"application/json",
                "headers":{"Content-Type":content_type}}}
        });
        assert_eq!(
            capture.observe(&response),
            Err(MessageListNetworkError::ResponseRejected)
        );
    }
}

#[test]
fn conflicting_response_extra_content_type_rejects_mail_list_get() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    capture
        .observe(&json!({
            "sessionId":"session-1", "method":"Network.requestWillBeSent",
            "params":{"requestId":"synthetic-extra", "type":"Fetch",
                "request":{"method":"GET", "url":URL}}
        }))
        .expect("track exact list GET");
    capture
        .observe(&json!({
            "sessionId":"session-1", "method":"Network.responseReceived",
            "params":{"requestId":"synthetic-extra", "type":"Fetch",
                "hasExtraInfo":true,
                "response":{"url":URL, "status":200u16,
                    "mimeType":"application/json"}}
        }))
        .expect("preliminary JSON 200");
    let contradictory = json!({
        "sessionId":"session-1", "method":"Network.responseReceivedExtraInfo",
        "params":{"requestId":"synthetic-extra", "statusCode":200u16,
            "headers":{"Content-Type":"text/html"}}
    });
    assert_eq!(
        capture.observe(&contradictory),
        Err(MessageListNetworkError::ResponseRejected)
    );
    assert!(capture.take_finished_request_ids().is_empty());
}

#[test]
fn private_response_address_space_cannot_complete_mail_list_get() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let request = json!({"sessionId":"session-1",
        "method":"Network.requestWillBeSent", "params":{
            "requestId":"private-response", "type":"Fetch",
            "request":{"method":"GET", "url":URL}}});
    let initial = json!({"sessionId":"session-1",
        "method":"Network.responseReceived", "params":{
            "requestId":"private-response", "hasExtraInfo":true,
            "response":{"url":URL, "status":200u16,
                "mimeType":"application/json"}}});
    let extra = json!({"sessionId":"session-1",
        "method":"Network.responseReceivedExtraInfo", "params":{
            "requestId":"private-response", "statusCode":200u16,
            "resourceIPAddressSpace":"Private",
            "headers":{"Content-Type":"application/json"}}});
    for extra_first in [true, false] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        capture.observe(&request).expect("ordinary Mail GET");
        if !extra_first {
            capture.observe(&initial).expect("preliminary JSON");
        }
        assert_eq!(
            capture.observe(&extra),
            Err(MessageListNetworkError::ResponseRejected)
        );
        assert!(capture.take_finished_request_ids().is_empty());
    }
}

#[test]
fn wire_http2_path_must_match_the_observed_mail_endpoint() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let request = json!({
        "sessionId":"session-1", "method":"Network.requestWillBeSent",
        "params":{"requestId":"synthetic-h2", "type":"Fetch",
            "request":{"method":"GET", "url":URL}}
    });
    let altered_wire = json!({
        "sessionId":"session-1", "method":"Network.requestWillBeSentExtraInfo",
        "params":{"requestId":"synthetic-h2", "headers":{
            ":authority":"mail.proton.me", ":scheme":"https", ":method":"GET",
            ":path":"/api/core/v4/users"}}
    });
    for extra_first in [false, true] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        if extra_first {
            capture.observe(&altered_wire).expect("early wire header");
            assert_eq!(
                capture.observe(&request),
                Err(MessageListNetworkError::MalformedEvent)
            );
        } else {
            capture.observe(&request).expect("tracked Mail GET");
            assert_eq!(
                capture.observe(&altered_wire),
                Err(MessageListNetworkError::ResponseRejected)
            );
        }
    }
}

#[test]
fn matching_http2_wire_path_allows_both_event_orders() {
    use serde_json::json;

    let request = json!({"sessionId":"session-1",
        "method":"Network.requestWillBeSent", "params":{
            "requestId":"synthetic-h2", "type":"Fetch",
            "request":{"method":"GET", "url":URL}}
    });
    let wire = json!({"sessionId":"session-1",
        "method":"Network.requestWillBeSentExtraInfo", "params":{
            "requestId":"synthetic-h2", "headers":{
                ":method":"GET", ":scheme":"https",
                ":authority":"mail.proton.me",
                ":path":concat!(
                    "/api/mail/v4/messages?Page=0&PageSize=50",
                    "&Limit=50&Sort=Time&Desc=1"
                )}}
    });
    for early in [true, false] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        if early {
            capture
                .observe(&wire)
                .expect("canonical early H2 wire headers");
            capture
                .observe(&request)
                .expect("canonical GET after H2 headers");
        } else {
            capture
                .observe(&request)
                .expect("canonical GET before H2 headers");
            capture
                .observe(&wire)
                .expect("canonical late H2 wire headers");
        }
    }
}

#[test]
fn insecure_extra_info_initiator_rejects_both_mail_request_orders() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let request = json!({
        "sessionId":"session-1", "method":"Network.requestWillBeSent",
        "params":{"requestId":"insecure", "type":"Fetch", "request":{
            "method":"GET", "url":URL}}
    });
    let extra = json!({
        "sessionId":"session-1", "method":"Network.requestWillBeSentExtraInfo",
        "params":{"requestId":"insecure", "headers":{
            "Host":"mail.proton.me"}, "clientSecurityState":{
                "initiatorIsSecureContext":false,
                "initiatorIPAddressSpace":"Public"}}
    });
    for early in [true, false] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        if early {
            capture
                .observe(&extra)
                .expect("correlate early wire metadata");
            assert_eq!(
                capture.observe(&request),
                Err(MessageListNetworkError::MalformedEvent)
            );
        } else {
            capture
                .observe(&request)
                .expect("track preliminary Mail GET");
            assert_eq!(
                capture.observe(&extra),
                Err(MessageListNetworkError::ResponseRejected)
            );
        }
        assert!(capture.take_finished_request_ids().is_empty());
    }
}

#[test]
fn nonpublic_client_address_space_rejects_mail_list_request_orders() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let request = json!({
        "sessionId":"session-1", "method":"Network.requestWillBeSent",
        "params":{"requestId":"private-client", "type":"Fetch",
            "request":{"method":"GET", "url":URL}}
    });
    let extra = json!({
        "sessionId":"session-1", "method":"Network.requestWillBeSentExtraInfo",
        "params":{"requestId":"private-client",
            "headers":{"Host":"mail.proton.me"},
            "clientSecurityState":{"initiatorIsSecureContext":true,
                "initiatorIPAddressSpace":"Private"}}
    });
    for extra_first in [true, false] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        if extra_first {
            capture.observe(&extra).expect("early wire metadata");
            assert_eq!(
                capture.observe(&request),
                Err(MessageListNetworkError::MalformedEvent)
            );
        } else {
            capture.observe(&request).expect("preliminary GET");
            assert_eq!(
                capture.observe(&extra),
                Err(MessageListNetworkError::ResponseRejected)
            );
        }
        assert!(capture.take_finished_request_ids().is_empty());
    }
}

#[test]
fn contradictory_request_extra_info_cannot_authorize_mail_list_get() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let request = json!({
        "sessionId":"session-1", "method":"Network.requestWillBeSent",
        "params":{"requestId":"synthetic-list", "type":"Fetch",
            "request":{"method":"GET", "url":URL,
                "headers":{"Host":"mail.proton.me"}}}
    });
    let actual_headers = json!({
        "sessionId":"session-1", "method":"Network.requestWillBeSentExtraInfo",
        "params":{"requestId":"synthetic-list",
            "headers":{"Host":"foreign.invalid", "Content-Length":"13"}}
    });
    // CDP documents that the extra-info notification can precede or follow
    // requestWillBeSent. Neither ordering can authorize a contradictory GET.
    for extra_first in [false, true] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        if extra_first {
            capture
                .observe(&actual_headers)
                .expect("remember early wire evidence");
            assert_eq!(
                capture.observe(&request),
                Err(MessageListNetworkError::MalformedEvent)
            );
        } else {
            capture.observe(&request).expect("track provisional GET");
            assert_eq!(
                capture.observe(&actual_headers),
                Err(MessageListNetworkError::ResponseRejected)
            );
        }
        assert!(capture.take_finished_request_ids().is_empty());
    }
}

#[test]
fn safe_and_unrelated_extra_info_preserve_message_list_lifecycle() {
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    let unrelated = json!({
        "sessionId":"session-1", "method":"Network.requestWillBeSentExtraInfo",
        "params":{"requestId":"other-request",
            "headers":{"Host":"other.invalid"}}
    });
    capture
        .observe(&unrelated)
        .expect("unrelated request cannot block read");
    let early = json!({
        "sessionId":"session-1", "method":"Network.requestWillBeSentExtraInfo",
        "params":{"requestId":"synthetic-list",
            "headers":{"Host":"mail.proton.me", "Sec-Fetch-Mode":"cors"}}
    });
    capture.observe(&early).expect("canonical wire headers");
    capture
        .observe(&json!({
            "sessionId":"session-1", "method":"Network.requestWillBeSent",
            "params":{"requestId":"synthetic-list", "type":"Fetch",
                "request":{"method":"GET", "url":URL,
                    "headers":{"Host":"mail.proton.me"}}}
        }))
        .expect("canonical GET");
    capture
        .observe(&json!({
            "sessionId":"session-1", "method":"Network.responseReceived",
            "params":{"requestId":"synthetic-list", "type":"Fetch",
                "response":{"url":URL, "status":200u16,
                    "mimeType":"application/json"}}
        }))
        .expect("canonical response");
    capture
        .observe(&json!({
            "sessionId":"session-1", "method":"Network.loadingFinished",
            "params":{"requestId":"synthetic-list"}
        }))
        .expect("finished request");
    assert_eq!(capture.take_finished_request_ids(), vec!["synthetic-list"]);
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
fn declared_extra_status_is_required_before_completion() {
    use serde_json::json;
    let mut capture = MessageListNetworkCapture::new("session-1");
    capture
        .observe(&json!({
            "sessionId":"session-1", "method":"Network.requestWillBeSent",
            "params":{"requestId":"extra", "request":{"method":"GET","url":URL}}
        }))
        .expect("track provider GET");
    capture
        .observe(&json!({
            "sessionId":"session-1", "method":"Network.responseReceived",
            "params":{"requestId":"extra", "hasExtraInfo":true, "response":{
                "url":URL,"status":200u16,"mimeType":"application/json"}}
        }))
        .expect("accept nominal HTTP 200");
    capture
        .observe(&json!({
            "sessionId":"session-1", "method":"Network.loadingFinished",
            "params":{"requestId":"extra"}
        }))
        .expect("finish response");
    assert!(
        capture.take_finished_request_ids().is_empty(),
        "hasExtraInfo=true cannot complete without actual HTTP status"
    );
    capture
        .observe(&json!({
            // jig-ignore-next-line: synthetic CDP fixture.
            "sessionId":"session-1", "method":"Network.responseReceivedExtraInfo",
            "params":{"requestId":"extra","statusCode":200u16}
        }))
        .expect("accept actual HTTP status");
    assert_eq!(capture.take_finished_request_ids(), ["extra"]);
}

#[test]
fn contradictory_raw_wire_headers_reject_message_list_completion() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    for first_extra in [false, true] {
        for raw_headers in [
            // jig-ignore-next-line: synthetic CDP wire fixture.
            "HTTP/1.1 304 Not Modified\r\nContent-Type: application/json\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
        ] {
            let mut capture = MessageListNetworkCapture::new("session-1");
            capture
                .observe(&json!({
                    // jig-ignore-next-line: synthetic CDP wire fixture.
                    "sessionId":"session-1", "method":"Network.requestWillBeSent",
                    // jig-ignore-next-line: synthetic CDP wire fixture.
                    "params":{"requestId":"raw", "request":{"method":"GET", "url":URL}}
                }))
                .expect("track provider GET");
            let response = json!({
                "sessionId":"session-1", "method":"Network.responseReceived",
                "params":{"requestId":"raw", "hasExtraInfo":true, "response":{
                    "url":URL, "status":200u16, "mimeType":"application/json"}}
            });
            let extra = json!({
                // jig-ignore-next-line: synthetic CDP wire fixture.
                "sessionId":"session-1", "method":"Network.responseReceivedExtraInfo",
                "params":{"requestId":"raw", "statusCode":200u16,
                    "headers":{"Content-Type":"application/json"},
                    "headersText":raw_headers}
            });
            if !first_extra {
                capture.observe(&response).expect("nominal JSON HTTP 200");
            }
            assert_eq!(
                capture.observe(&extra),
                Err(MessageListNetworkError::ResponseRejected)
            );
            if first_extra {
                // Early extra info may precede responseReceived: it must be
                // rejected rather than cached as future positive evidence.
                assert!(capture.take_finished_request_ids().is_empty());
            }
        }
    }
}

#[test]
fn revalidated_cache_status_rejects_message_list_get() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    for after_response in [false, true] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        capture
            .observe(&json!({
                "sessionId":"session-1","method":"Network.requestWillBeSent",
                "params":{"requestId":"list","request":{
                    "method":"GET","url":URL
                }}
            }))
            .expect("track exact GET");
        if after_response {
            capture
                .observe(&json!({
                    "sessionId":"session-1","method":"Network.responseReceived",
                    "params":{"requestId":"list","response":{
                        "url":URL,"status":200u16,"mimeType":"application/json"
                    }}
                }))
                .expect("first report 200");
        }
        let extra = json!({
            "sessionId":"session-1",
            "method":"Network.responseReceivedExtraInfo",
            "params":{"requestId":"list","statusCode":304u16}
        });
        assert_eq!(
            capture.observe(&extra),
            Err(MessageListNetworkError::ResponseRejected)
        );
    }
}

#[test]
fn standalone_cache_hit_rejects_message_list_request() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    for after_response in [false, true] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        capture
            .observe(&json!({
                "sessionId":"session-1","method":"Network.requestWillBeSent",
                "params":{"requestId":"list-1","request":{
                    "method":"GET","url":URL
                }}
            }))
            .expect("track list GET");
        let cache = json!({
            "sessionId":"session-1",
                "method":"Network.requestServedFromCache",
            "params":{"requestId":"list-1"}
        });
        capture
            .observe(&json!({
                "sessionId":"session-1",
                "method":"Network.requestServedFromCache",
                "params":{"requestId":"unrelated"}
            }))
            .expect("ignore unrelated cache hit");
        if after_response {
            capture
                .observe(&json!({
                    "sessionId":"session-1","method":"Network.responseReceived",
                    "params":{"requestId":"list-1","response":{
                        "url":URL,"status":200u16,"mimeType":"application/json"
                    }}
                }))
                .expect("receive response before cache notification");
        }
        assert_eq!(
            capture.observe(&cache),
            Err(MessageListNetworkError::ResponseRejected)
        );
        assert!(capture.take_finished_request_ids().is_empty());
    }
}

#[test]
fn response_speculation_markers_cannot_authorize_mail_list_capture() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    for level in ["event", "response"] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        capture
            .observe(&json!({
                "sessionId": "session-1", "method": "Network.requestWillBeSent",
                "params": {"requestId": "synthetic-list", "request": {
                    "method": "GET", "url": URL}}
            }))
            .expect("track exact list GET");
        let mut response = json!({
            "sessionId": "session-1", "method": "Network.responseReceived",
            "params": {"requestId": "synthetic-list", "type": "Fetch",
                "response": {"url": URL, "status": 200u16,
                    "mimeType": "application/json"}}
        });
        if level == "event" {
            response["params"]["wasPrerendered"] = json!(false);
        } else {
            response["params"]["response"]["wasPreloaded"] = json!(false);
        }
        assert_eq!(
            capture.observe(&response),
            Err(MessageListNetworkError::ResponseRejected)
        );
        assert!(capture.take_finished_request_ids().is_empty());
    }
}

#[test]
fn cached_message_list_network_reply_is_not_fresh_evidence() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    for (flag, value) in [
        ("fromDiskCache", json!(true)),
        ("fromServiceWorker", json!(true)),
        ("fromPrefetchCache", json!(true)),
        ("fromEarlyHints", json!(true)),
        ("fromEarlyHints", json!(null)),
        ("serviceWorkerResponseSource", json!("cache-storage")),
        ("serviceWorkerResponseSource", json!("network")),
        ("serviceWorkerResponseSource", json!(null)),
        ("cacheStorageCacheName", json!("mail-cache")),
        ("cacheStorageCacheName", json!(null)),
        (
            "serviceWorkerRouterInfo",
            json!({"actualSourceType":"cache"}),
        ),
        (
            "serviceWorkerRouterInfo",
            json!({"actualSourceType":"network"}),
        ),
        ("serviceWorkerRouterInfo", json!(null)),
        ("fromDiskCache", json!(null)),
        ("fromServiceWorker", json!("false")),
        // Confusable Unicode names are not CDP response-schema fields.
        ("fromDiskCa\u{0441}he", json!(true)),
        ("securitySt\u{0430}te", json!("insecure")),
    ] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        let request = json!({
            "sessionId":"session-1","method":"Network.requestWillBeSent",
            "params":{"requestId":"list-1","request":{
                "method":"GET","url":URL
            }}
        });
        capture.observe(&request).expect("track exact list GET");
        let mut response = json!({
            "sessionId":"session-1","method":"Network.responseReceived",
            "params":{"requestId":"list-1","response":{
                "url":URL,"status":200u16,"mimeType":"application/json"
            }}
        });
        response["params"]["response"][flag] = value;
        assert_eq!(
            capture.observe(&response),
            Err(MessageListNetworkError::ResponseRejected),
            "untrusted provenance {flag} must fail closed"
        );
    }
}

#[test]
fn explicit_uncached_message_list_get_remains_observable() {
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    capture
        .observe(&json!({
            "sessionId":"session-1","method":"Network.requestWillBeSent",
            "params":{"requestId":"fresh-list","request":{
                "method":"GET","url":URL
            }}
        }))
        .expect("track fresh GET");
    capture
        .observe(&json!({
            "sessionId":"session-1","method":"Network.responseReceived",
            "params":{"requestId":"fresh-list","response":{
                "url":URL,"status":200u16,"mimeType":"application/json",
                "fromDiskCache":false,"fromServiceWorker":false,
                "fromPrefetchCache":false,"fromEarlyHints":false
            }}
        }))
        .expect("accept uncached 200 JSON");
    capture
        .observe(&json!({
            "sessionId":"session-1","method":"Network.loadingFinished",
            "params":{"requestId":"fresh-list"}
        }))
        .expect("finish exact list GET");
    assert_eq!(
        capture.take_finished_request_ids(),
        [String::from("fresh-list")]
    );
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
fn unpaired_message_range_selectors_cannot_prove_visible_list_batch() {
    use serde_json::json;

    let cases = [("begin-only", "Begin=123"), ("end-only", "End=456")];
    for (label, selector) in cases {
        let url = format!("{URL}&{selector}");
        let mut capture = MessageListNetworkCapture::new("session-1");
        capture
            .observe(&json!({
                "sessionId":"session-1", "method":"Network.requestWillBeSent",
                "params":{
                    "requestId":label,
                    "request":{"method":"GET","url":url}
                }
            }))
            .expect("ignore range-constrained provider GET");
        capture
            .observe(&json!({
                "sessionId":"session-1", "method":"Network.responseReceived",
                "params":{"requestId":label,"response":{
                    "url":url,"status":200u16,"mimeType":"application/json"
                }}
            }))
            .expect("ignore response from hidden range");
        capture
            .observe(&json!({
                "sessionId":"session-1", "method":"Network.loadingFinished",
                "params":{"requestId":label}
            }))
            .expect("ignore range GET completion");
        assert!(
            capture.take_finished_request_ids().is_empty(),
            "range selector {label} cannot prove canonical visible page"
        );
    }
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
    let extra = json!({
        "sessionId":"session-1",
        "method":"Network.responseReceivedExtraInfo",
        "params":{"requestId":"list-1","statusCode":200u16}
    });
    for late in [request, changed_method, response, finished, failure, extra] {
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
    let prefix = format!("{URL}&Keyword=");
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
        "matrix;param=value",
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
        "noncharacter\u{fdd0}id",
        "noncharacter\u{fffe}id",
        "noncharacter\u{10ffff}id",
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
fn raw_noncanonical_browser_urls_cannot_prove_message_list_reads() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let body = r#"{"Stale":0,"Total":0,"Messages":[]}"#;
    for bad in [" ", "\t", "\n", "\r", "\u{a0}", "\u{2003}", "\u{e9}"] {
        let url = format!("{URL}&Keyword=hello{bad}world");
        assert_eq!(
            ObservedMessageListResponse::parse("GET", &url, body),
            Err(MessageListResponseError::UnexpectedEndpoint),
            "noncanonical serialized URL cannot authorize a parsed response"
        );
        let mut capture = MessageListNetworkCapture::new("synthetic-session");
        assert_eq!(
            capture.observe(&json!({
                "sessionId":"synthetic-session",
                "method":"Network.requestWillBeSent",
                "params":{"requestId":"noncanonical-url",
                    "request":{"method":"GET","url":url}}
            })),
            Err(MessageListNetworkError::MalformedEvent)
        );
        assert!(capture.take_finished_request_ids().is_empty());
    }
    let encoded = format!("{URL}&Keyword=hello%20%C3%A9world");
    assert!(ObservedMessageListResponse::parse("GET", &encoded, body).is_ok());
    let mut capture = MessageListNetworkCapture::new("synthetic-session");
    capture
        .observe(&json!({
            "sessionId":"synthetic-session",
            "method":"Network.requestWillBeSent",
            "params":{"requestId":"encoded-url",
                "request":{"method":"GET","url":encoded}}
        }))
        .expect("encoded URL retains the audited request shape");
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
fn unreviewed_message_list_query_keys_cannot_prove_visible_batches() {
    use serde_json::json;

    for (label, base, selector) in [
        ("initial-extra-filter", URL, "Priority=1"),
        ("initial-extra-sort", URL, "OrderBy=Size"),
        (
            "continuation-extra-filter",
            concat!(
                "https://mail.proton.me/api/mail/v4/messages?",
                "Limit=50&Anchor=7&AnchorID=m-50&Sort=Time&Desc=1"
            ),
            "FutureFilter=1",
        ),
    ] {
        let url = format!("{base}&{selector}");
        let mut capture = MessageListNetworkCapture::new("synthetic-session");
        let request = json!({
            "sessionId":"synthetic-session",
            "method":"Network.requestWillBeSent",
            "params":{"requestId":label,
                "request":{"method":"GET","url":url}}
        });
        capture
            .observe(&request)
            .expect("ignore unreviewed selector");
        let response = json!({
            "sessionId":"synthetic-session",
            "method":"Network.responseReceived",
            "params":{"requestId":label,"response":{
                "url":url,"status":200u16,"mimeType":"application/json"
            }}
        });
        capture
            .observe(&response)
            .expect("ignore untracked response");
        capture
            .observe(&json!({
                "sessionId":"synthetic-session",
                "method":"Network.loadingFinished",
                "params":{"requestId":label}
            }))
            .expect("ignore untracked completion");
        assert!(capture.take_finished_request_ids().is_empty());
    }
    // Supported filters still select a bounded provider batch.
    let canonical = format!("{URL}&LabelID=sent&Keyword=hello&Unread=1");
    let mut capture = MessageListNetworkCapture::new("synthetic-session");
    capture
        .observe(&json!({
            "sessionId":"synthetic-session",
            "method":"Network.requestWillBeSent",
            "params":{"requestId":"canonical",
                "request":{"method":"GET","url":canonical}}
        }))
        .expect("reviewed filters remain compatible");
    capture
        .observe(&json!({
            "sessionId":"synthetic-session",
            "method":"Network.responseReceived",
            "params":{"requestId":"canonical","response":{
                "url":canonical,"status":200u16,"mimeType":"application/json"
            }}
        }))
        .expect("reviewed response evidence");
    capture
        .observe(&json!({
            "sessionId":"synthetic-session",
            "method":"Network.loadingFinished",
            "params":{"requestId":"canonical"}
        }))
        .expect("reviewed response completion");
    assert_eq!(capture.take_finished_request_ids(), ["canonical"]);
}

#[test]
fn duplicate_scalar_message_list_filters_cannot_be_batch_evidence() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    for (label, filters) in [
        ("duplicate-keyword", "Keyword=a&Keyword=b"),
        ("duplicate-unread", "Unread=1&Unread=0"),
    ] {
        let url = format!("{URL}&{filters}");
        let mut capture = MessageListNetworkCapture::new("session-1");
        let event = json!({
            "sessionId":"session-1", "method":"Network.requestWillBeSent",
            "params":{"requestId":label,"request":{"method":"GET","url":url}}
        });
        assert_eq!(
            capture.observe(&event),
            Err(MessageListNetworkError::MalformedEvent),
            "conflicting scalar filter {label} cannot prove a batch"
        );
    }
}

#[test]
fn unread_message_filter_requires_canonical_boolean_evidence() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    for value in ["", "2", "-1", "01", "true", "false", "%31", " 1", "1 "] {
        let mut capture = MessageListNetworkCapture::new("synthetic-session");
        let url = format!("{URL}&Unread={value}");
        assert_eq!(
            capture.observe(&json!({
                "sessionId":"synthetic-session",
                "method":"Network.requestWillBeSent",
                "params":{"requestId":"unread-filter",
                    "request":{"method":"GET","url":url}}
            })),
            Err(MessageListNetworkError::MalformedEvent),
            "unreviewed unread wire value cannot qualify a visible batch"
        );
    }
    for value in ["0", "1"] {
        let mut capture = MessageListNetworkCapture::new("synthetic-session");
        let url = format!("{URL}&Unread={value}");
        capture
            .observe(&json!({
                "sessionId":"synthetic-session",
                "method":"Network.requestWillBeSent",
                "params":{"requestId":"canonical-unread",
                    "request":{"method":"GET","url":url}}
            }))
            .expect("canonical unread selector remains valid");
    }
}

#[test]
fn case_aliased_message_filter_keys_cannot_enter_list_capture() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    for (label, filter) in [
        ("alias-label", "labelid=synthetic"),
        ("mixed-label", "LabelID=first&labelid=second"),
        ("alias-keyword", "keyword=synthetic"),
        ("alias-unread", "unread=1"),
    ] {
        let url = format!("{URL}&{filter}");
        let mut capture = MessageListNetworkCapture::new("synthetic-session");
        let event = json!({
            "sessionId":"synthetic-session",
            "method":"Network.requestWillBeSent",
            "params":{"requestId":label,"request":{"method":"GET","url":url}}
        });
        assert_eq!(
            capture.observe(&event),
            Err(MessageListNetworkError::MalformedEvent),
            "noncanonical {label} must never authorize a list request"
        );
    }
    // Deliberate multi-label filtering is valid with canonical key names.
    let url = format!("{URL}&LabelID=first&LabelID=second&Unread=1");
    let mut capture = MessageListNetworkCapture::new("synthetic-session");
    capture
        .observe(&json!({
            "sessionId":"synthetic-session",
            "method":"Network.requestWillBeSent",
            "params":{"requestId":"canonical-filters",
                "request":{"method":"GET","url":url}}
        }))
        .expect("canonical repeated LabelID filters remain compatible");
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

#[test]
fn apparent_message_list_get_with_body_cannot_prove_read_only_request() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    for (field, value) in [
        ("hasPostData", json!(true)),
        ("hasPostData", json!(null)),
        ("hasPostData", json!("false")),
        ("postData", json!("synthetic-payload")),
        ("postData", json!(null)),
        ("postDataEntries", json!([{"bytes":"c3ludGhldGlj"}])),
        ("postDataEntries", json!([])),
    ] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        let mut event = json!({
            "sessionId":"session-1","method":"Network.requestWillBeSent",
            "params":{"requestId":"body-bearing-get","request":{
                "method":"GET","url":URL
            }}
        });
        event["params"]["request"][field] = value;
        assert_eq!(
            capture.observe(&event),
            Err(MessageListNetworkError::MalformedEvent),
            "body-bearing GET {field} is not read-only proof"
        );
    }
    // An explicit negative flag is a normal CDP representation of a GET.
    let mut clean = MessageListNetworkCapture::new("session-1");
    let event = json!({
        "sessionId":"session-1","method":"Network.requestWillBeSent",
        "params":{"requestId":"no-body","request":{
            "method":"GET","url":URL,"hasPostData":false
        }}
    });
    assert_eq!(clean.observe(&event), Ok(()));
}

#[test]
fn speculative_get_cannot_prove_message_list_read() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    for (field, value) in [
        ("request.isLinkPreload", json!(true)),
        ("request.isLinkPreload", json!(null)),
        ("params.type", json!("Prefetch")),
        ("params.type", json!("Preflight")),
        ("params.type", json!("FedCM")),
        ("params.type", json!("prefetch")),
        ("params.initiator", json!({"type":"preload"})),
        ("params.initiator", json!({"type":"Preload"})),
        ("params.initiator", json!({"type":"FedCM"})),
        ("params.initiator", json!({"type":"preflight"})),
    ] {
        let mut event = json!({
            "sessionId":"session-1","method":"Network.requestWillBeSent",
            "params":{"requestId":"speculative-get","request":{
                "method":"GET","url":URL
            }}
        });
        if field == "request.isLinkPreload" {
            event["params"]["request"]["isLinkPreload"] = value;
        } else if field == "params.type" {
            event["params"]["type"] = value;
        } else {
            event["params"]["initiator"] = value;
        }
        let mut capture = MessageListNetworkCapture::new("session-1");
        assert_eq!(
            capture.observe(&event),
            Err(MessageListNetworkError::MalformedEvent),
            "speculative CDP GET {field} must not prove mailbox data"
        );
    }
    let mut clean = MessageListNetworkCapture::new("session-1");
    let event = json!({
        "sessionId":"session-1","method":"Network.requestWillBeSent",
        "params":{"requestId":"normal-get","type":"Fetch",
            "initiator":{"type":"script"},"request":{
                "method":"GET","url":URL,"isLinkPreload":false
            }
        }
    });
    assert_eq!(clean.observe(&event), Ok(()));
}

#[test]
fn foreign_document_get_cannot_prove_visible_mail_message_batch() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    for document in [
        json!("https://example.invalid/embedded-frame"),
        json!("https://account.proton.me/u/0/settings"),
        json!("https://mail.proton.me.evil.invalid/"),
        json!(null),
    ] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        let event = json!({
            "sessionId": "session-1",
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": "foreign-frame-list",
                "request": {"method": "GET", "url": URL},
                "documentURL": document
            }
        });
        assert_eq!(
            capture.observe(&event),
            Err(MessageListNetworkError::MalformedEvent),
            "untrusted requesting document must not establish mailbox list"
        );
        assert!(capture.take_finished_request_ids().is_empty());
    }
    let mut trusted = MessageListNetworkCapture::new("session-1");
    let request = json!({
        "sessionId": "session-1",
        "method": "Network.requestWillBeSent",
        "params": {
            "requestId": "mail-document-list",
            "request": {"method": "GET", "url": URL},
            "documentURL": "https://mail.proton.me/u/0/inbox"
        }
    });
    assert_eq!(trusted.observe(&request), Ok(()));
}

#[test]
fn speculative_response_type_cannot_prove_mail_message_read() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let request = json!({
        "sessionId": "session-1", "method": "Network.requestWillBeSent",
        "params": {"requestId": "typed-list", "type": "Fetch",
            "request": {"method": "GET", "url": URL}}
    });
    for kind in ["Prefetch", "Preflight", "FedCM", "prefetch", "future"] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        assert_eq!(capture.observe(&request), Ok(()));
        let response = json!({
            "sessionId": "session-1", "method": "Network.responseReceived",
            "params": {"requestId": "typed-list", "type": kind,
                "response": {"url": URL, "status": 200u16,
                    "mimeType": "application/json"}}
        });
        assert_eq!(
            capture.observe(&response),
            Err(MessageListNetworkError::ResponseRejected),
            "untrusted response ResourceType {kind}"
        );
        assert!(capture.take_finished_request_ids().is_empty());
    }
    for kind in ["XHR", "Fetch"] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        assert_eq!(capture.observe(&request), Ok(()));
        let response = json!({
            "sessionId": "session-1", "method": "Network.responseReceived",
            "params": {"requestId": "typed-list", "type": kind,
                "response": {"url": URL, "status": 200u16,
                    "mimeType": "application/json"}}
        });
        assert_eq!(capture.observe(&response), Ok(()));
    }
}

#[test]
fn event_level_cache_notice_cannot_prove_message_list_read() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    let mut capture = MessageListNetworkCapture::new("session-1");
    let request = json!({
        "sessionId": "session-1", "method": "Network.requestWillBeSent",
        "params": {"requestId": "cached-params-list", "type": "Fetch",
            "request": {"method": "GET", "url": URL}}
    });
    assert_eq!(capture.observe(&request), Ok(()));
    let response = json!({
        "sessionId": "session-1", "method": "Network.responseReceived",
        "params": {"requestId": "cached-params-list", "type": "Fetch",
            "fromDiskCache": true,
            "response": {"url": URL, "status": 200u16,
                "mimeType": "application/json", "fromDiskCache": false}}
    });
    assert_eq!(
        capture.observe(&response),
        Err(MessageListNetworkError::ResponseRejected)
    );
    assert!(capture.take_finished_request_ids().is_empty());
}

#[test]
fn non_ajax_resource_cannot_prove_message_list_api_read() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    for kind in ["Image", "Document", "Script", "Other"] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        let event = json!({
            "sessionId": "session-1", "method": "Network.requestWillBeSent",
            "params": {"requestId": "image-list", "type": kind,
                "request": {"method": "GET", "url": URL}}
        });
        assert_eq!(
            capture.observe(&event),
            Err(MessageListNetworkError::MalformedEvent),
            "non-AJAX request {kind} must not count as a Mail list read"
        );
    }
    let mut capture = MessageListNetworkCapture::new("session-1");
    let normal = json!({
        "sessionId": "session-1", "method": "Network.requestWillBeSent",
        "params": {"requestId": "ajax-list", "type": "XHR",
            "request": {"method": "GET", "url": URL}}
    });
    assert_eq!(capture.observe(&normal), Ok(()));
    let disguised = json!({
        "sessionId": "session-1", "method": "Network.responseReceived",
        "params": {"requestId": "ajax-list", "type": "Image",
            "response": {"url": URL, "status": 200u16,
                "mimeType": "application/json"}}
    });
    assert_eq!(
        capture.observe(&disguised),
        Err(MessageListNetworkError::ResponseRejected)
    );
}

#[test]
fn unknown_payload_get_cannot_be_promoted_to_message_list_read() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    for (field, value) in [
        ("postDataLength", json!(42u64)),
        ("requestBody", json!("private")),
        ("HasPostData", json!(false)),
    ] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        let mut request = json!({
            "sessionId": "session-1", "method": "Network.requestWillBeSent",
            "params": {"requestId": "unreviewed-payload", "type": "Fetch",
                "request": {"method": "GET", "url": URL}}
        });
        request["params"]["request"][field] = value;
        assert_eq!(
            capture.observe(&request),
            Err(MessageListNetworkError::MalformedEvent),
            "unreviewed payload hint {field} must fail closed"
        );
        assert!(capture.take_finished_request_ids().is_empty());
    }
}

#[test]
fn body_bearing_request_headers_cannot_prove_mail_list_get() {
    use mail_web_adapter::MessageListNetworkError;
    use serde_json::json;

    for (header, value) in [
        ("Content-Length", "6"),
        ("content-length", "untrusted"),
        ("Transfer-Encoding", "chunked"),
    ] {
        let mut capture = MessageListNetworkCapture::new("session-1");
        let mut event = json!({
            "sessionId": "session-1", "method": "Network.requestWillBeSent",
            "params": {"requestId": "body-header", "type": "Fetch",
                "request": {"method": "GET", "url": URL,
                    "hasPostData": false,
                    "headers": {"Accept": "application/json"}}}
        });
        event["params"]["request"]["headers"][header] = json!(value);
        assert_eq!(
            capture.observe(&event),
            Err(MessageListNetworkError::MalformedEvent),
            "body-indicating HTTP header {header} must not prove Mail GET"
        );
    }
}
