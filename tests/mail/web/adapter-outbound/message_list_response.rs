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
