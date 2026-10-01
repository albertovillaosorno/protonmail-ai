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
