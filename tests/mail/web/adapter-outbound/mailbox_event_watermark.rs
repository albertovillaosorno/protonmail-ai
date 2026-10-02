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
//   - Synthetic browser processes only; no network or account interaction.
//

//! Mail core-event watermark projection regression tests.

use std::env;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Mutex;

use mail_capability_domain::{EventCursorBindingError, EventCursorScope};
use mail_web_adapter::MailboxEventSequenceError;
use mail_web_adapter::MailboxEventWatermarkError;
use mail_web_adapter::ObservedLatestMailboxEventWatermark;
use mail_web_adapter::ObservedMailboxEventWatermark;
use mail_web_adapter::{MailboxChangeEntity, MailboxChangeKind};

static EVENT_BROWSER_TEST_LOCK: Mutex<()> = Mutex::new(());

const URL: &str = concat!(
    "https://mail.proton.me/api/core/v5/events/event-7",
    "?ConversationCounts=1&MessageCounts=1&CalledFrom=Foreground"
);

#[test]
fn latest_event_projection_retains_only_bounded_watermark() {
    let body = r#"{"EventID":"event-bootstrap","decoy":"secret"}"#;
    let latest = ObservedLatestMailboxEventWatermark::parse(
        "GET",
        "https://mail.proton.me/api/core/v4/events/latest",
        body,
    )
    .expect("project latest event watermark");
    assert_eq!(latest.event_id(), "event-bootstrap");
    let debug = format!("{latest:?}");
    assert!(!debug.contains("event-bootstrap"));
    assert!(!debug.contains("secret"));

    assert_eq!(
        ObservedLatestMailboxEventWatermark::parse(
            "GET",
            "https://mail.proton.me/api/core/v6/events/latest",
            body,
        ),
        Err(MailboxEventWatermarkError::UnexpectedEndpoint)
    );
}

#[test]
fn bootstrap_watermark_matches_only_settled_no_change_poll() {
    let latest = ObservedLatestMailboxEventWatermark::parse(
        "GET",
        "https://mail.proton.me/api/core/v4/events/latest",
        r#"{"EventID":"event-7"}"#,
    )
    .expect("project latest event watermark");
    let quiet = ObservedMailboxEventWatermark::parse(
        "GET",
        URL,
        r#"{"EventID":"event-7","More":0,"Messages":[]}"#,
    )
    .expect("project quiet poll");
    assert!(latest.matches_quiet_poll(&quiet));

    let changed = ObservedMailboxEventWatermark::parse(
        "GET",
        URL,
        // jig-ignore-next-line: indivisible synthetic JSON fixture.
        r#"{"EventID":"event-8","More":0,"Messages":[{"ID":"m-change","Action":2}]}"#,
    )
    .expect("project changed poll");
    assert!(!latest.matches_quiet_poll(&changed));

    let more =
        // jig-ignore-next-line: indivisible synthetic JSON fixture.
        ObservedMailboxEventWatermark::parse("GET", URL, r#"{"EventID":"event-7","More":1}"#)
            .expect("project unsettled poll");
    assert!(!latest.matches_quiet_poll(&more));
}

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
        "Messages":[
            {"ID":"secret-message","Action":2,
             "Message":{"Subject":"secret subject"}}
        ],
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
fn contacts_only_refresh_does_not_invalidate_mailbox_sequence() {
    let contacts = ObservedMailboxEventWatermark::parse(
        "GET",
        URL,
        r#"{"EventID":"event-8","More":0,"Refresh":2}"#,
    )
    .expect("parse contacts-only refresh");
    assert!(contacts.settled());
    // jig-ignore-next-line: canonical rustfmt line.
    let sequence = mail_web_adapter::ObservedMailboxEventSequence::start(contacts)
        .expect("contacts-only refresh must not expire mailbox cursor");
    assert!(sequence.settled());

    let all = ObservedMailboxEventWatermark::parse(
        "GET",
        URL,
        r#"{"EventID":"event-8","More":0,"Refresh":255}"#,
    )
    .expect("parse all-data refresh");
    assert_eq!(
        mail_web_adapter::ObservedMailboxEventSequence::start(all),
        Err(MailboxEventSequenceError::RefreshRequired)
    );
}

#[test]
fn event_changes_preserve_order_and_normalize_actions() {
    let body = r#"{
        "EventID":"event-8","More":0,
        "Messages":[
            {"ID":"m-created","Action":1,"Message":{"Subject":"secret-a"}},
            {"ID":"m-updated","Action":2,"Message":{"Subject":"secret-b"}},
            {"ID":"m-flags","Action":3,"Message":{"Subject":"secret-c"}},
            {"ID":"m-deleted","Action":0}
        ],
        "Conversations":[
            {"ID":"c-created","Action":1,"Conversation":{"Subject":"secret-d"}}
        ]
    }"#;
    let event = ObservedMailboxEventWatermark::parse("GET", URL, body)
        .expect("project normalized mailbox changes");
    let changes = event.changes();
    assert_eq!(changes.len(), 5);
    assert_eq!(changes[0].entity(), MailboxChangeEntity::Message);
    assert_eq!(changes[0].kind(), MailboxChangeKind::Created);
    assert_eq!(changes[0].id(), "m-created");
    assert_eq!(changes[1].kind(), MailboxChangeKind::Updated);
    assert_eq!(changes[2].kind(), MailboxChangeKind::Updated);
    assert_eq!(changes[3].kind(), MailboxChangeKind::Deleted);
    assert_eq!(changes[4].entity(), MailboxChangeEntity::Conversation);
    assert_eq!(changes[4].kind(), MailboxChangeKind::Created);
    let debug = format!("{event:?} {changes:?}");
    for secret in [
        "m-created",
        "m-updated",
        "m-flags",
        "m-deleted",
        "c-created",
        "secret-a",
        "secret-b",
        "secret-c",
        "secret-d",
    ] {
        assert!(!debug.contains(secret));
    }
}

#[test]
fn exact_duplicate_changes_coalesce_but_distinct_actions_survive() {
    let body = r#"{
        "EventID":"event-8","More":0,
        "Messages":[
            {"ID":"m-1","Action":1},
            {"ID":"m-1","Action":1},
            {"ID":"m-1","Action":2},
            {"ID":"m-1","Action":3},
            {"ID":"m-1","Action":0}
        ]
    }"#;
    let event =
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedMailboxEventWatermark::parse("GET", URL, body).expect("project duplicate changes");
    assert_eq!(event.changes().len(), 3);
    assert_eq!(event.changes()[0].kind(), MailboxChangeKind::Created);
    assert_eq!(event.changes()[1].kind(), MailboxChangeKind::Updated);
    assert_eq!(event.changes()[2].kind(), MailboxChangeKind::Deleted);
}

#[test]
fn malformed_change_id_or_action_fails_closed() {
    for body in [
        r#"{"EventID":"event-8","More":0,"Messages":[{"ID":"","Action":1}]}"#,
        r#"{"EventID":"event-8","More":0,"Messages":[{"ID":"m-1"}]}"#,
        // jig-ignore-next-line: indivisible synthetic JSON fixture.
        r#"{"EventID":"event-8","More":0,"Messages":[{"ID":"m-1","Action":4}]}"#,
        r#"{"EventID":"event-8","More":0,"Conversations":[7]}"#,
    ] {
        assert_eq!(
            ObservedMailboxEventWatermark::parse("GET", URL, body),
            Err(MailboxEventWatermarkError::Malformed)
        );
    }
}

#[test]
fn normalized_change_count_is_bounded() {
    let mut changes = String::new();
    for index in 0u16..513u16 {
        if !changes.is_empty() {
            changes.push(',');
        }
        // jig-ignore-next-line: indivisible synthetic JSON fixture.
        write!(changes, r#"{{"ID":"m-{index}","Action":1}}"#).expect("append synthetic change");
    }
    // jig-ignore-next-line: indivisible synthetic JSON fixture.
    let body = format!(r#"{{"EventID":"event-8","More":0,"Messages":[{changes}]}}"#);
    assert_eq!(
        ObservedMailboxEventWatermark::parse("GET", URL, &body),
        Err(MailboxEventWatermarkError::TooManyChanges)
    );
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
fn cdp_body_projection_requires_decoded_json_and_bounded_request_id() {
    use serde_json::json;

    let decoded = json!({
        "body":"{\"EventID\":\"event-7\",\"More\":0}",
        "base64Encoded":false
    });
    // jig-ignore-next-line: indivisible synthetic JSON fixture.
    let event = ObservedMailboxEventWatermark::parse_cdp_body("event-7", &decoded)
        .expect("project decoded event body");
    assert!(event.unchanged_watermark());

    let encoded = json!({"body":"e30=","base64Encoded":true});
    assert_eq!(
        ObservedMailboxEventWatermark::parse_cdp_body("event-7", &encoded),
        Err(MailboxEventWatermarkError::UnsupportedEncoding)
    );
    assert_eq!(
        ObservedMailboxEventWatermark::parse_cdp_body("bad/id", &decoded),
        Err(MailboxEventWatermarkError::Malformed)
    );
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

#[test]
fn event_sequence_chains_watermarks_and_coalesces_exact_duplicates() {
    use mail_web_adapter::MailboxEventSequenceError;
    use mail_web_adapter::ObservedMailboxEventSequence;

    let first = ObservedMailboxEventWatermark::parse(
        "GET",
        "https://mail.proton.me/api/core/v5/events/event-1",
        r#"{
            "EventID":"event-2","More":1,
            "Messages":[
                {"ID":"m-1","Action":1},
                {"ID":"m-2","Action":2}
            ]
        }"#,
    )
    .expect("parse first event page");
    let second = ObservedMailboxEventWatermark::parse(
        "GET",
        "https://mail.proton.me/api/core/v5/events/event-2",
        r#"{
            "EventID":"event-3","More":0,
            "Messages":[
                {"ID":"m-1","Action":1},
                {"ID":"m-1","Action":3}
            ],
            "Conversations":[{"ID":"c-1","Action":0}],
            "MessageCounts":[{"LabelID":"inbox","Total":2}]
        }"#,
    )
    .expect("parse second event page");

    let mut sequence =
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedMailboxEventSequence::start(first).expect("start resumable event sequence");
    sequence.push(second).expect("append exact continuation");
    assert!(sequence.settled());
    assert_eq!(sequence.start_event_id(), "event-1");
    assert_eq!(sequence.next_event_id(), "event-3");
    assert_eq!(sequence.page_count(), 2);
    assert!(sequence.count_changes());
    assert_eq!(sequence.changes().len(), 4);
    assert_eq!(sequence.changes()[0].id(), "m-1");
    assert_eq!(sequence.changes()[0].kind(), MailboxChangeKind::Created);
    assert_eq!(sequence.changes()[1].id(), "m-2");
    assert_eq!(sequence.changes()[1].kind(), MailboxChangeKind::Updated);
    assert_eq!(sequence.changes()[2].id(), "m-1");
    assert_eq!(sequence.changes()[2].kind(), MailboxChangeKind::Updated);
    assert_eq!(
        sequence.changes()[3].entity(),
        MailboxChangeEntity::Conversation
    );
    assert_eq!(sequence.changes()[3].kind(), MailboxChangeKind::Deleted);
    let debug = format!("{sequence:?}");
    for secret in ["event-1", "event-3", "m-1", "m-2", "c-1"] {
        assert!(!debug.contains(secret));
    }

    let settled_page = ObservedMailboxEventWatermark::parse(
        "GET",
        "https://mail.proton.me/api/core/v5/events/event-3",
        r#"{"EventID":"event-3","More":0}"#,
    )
    .expect("parse post-settlement page");
    assert_eq!(
        sequence.push(settled_page),
        Err(MailboxEventSequenceError::AlreadySettled)
    );
}

#[test]
fn event_sequence_binds_cursor_only_after_settlement() {
    let first = ObservedMailboxEventWatermark::parse(
        "GET",
        "https://mail.proton.me/api/core/v5/events/event-1",
        r#"{"EventID":"event-2","More":1}"#,
    )
    .expect("parse unsettled cursor page");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut sequence = mail_web_adapter::ObservedMailboxEventSequence::start(first)
        .expect("start unsettled cursor sequence");
    let scope = EventCursorScope::new("account-a", "web", "generation-7")
        .expect("valid event cursor scope");
    assert_eq!(
        sequence.bind_next_cursor(scope.clone()),
        Err(MailboxEventSequenceError::CursorBeforeSettlement)
    );

    let second = ObservedMailboxEventWatermark::parse(
        "GET",
        "https://mail.proton.me/api/core/v5/events/event-2",
        r#"{"EventID":"event-3","More":0}"#,
    )
    .expect("parse settled cursor page");
    sequence.push(second).expect("settle cursor sequence");
    let cursor = sequence
        .bind_next_cursor(scope.clone())
        .expect("bind settled next cursor");
    assert_eq!(cursor.state_for(&scope).map(String::as_str), Ok("event-3"));
}

#[test]
fn event_sequence_rejects_cursor_gap_refresh_and_nonadvancing_more() {
    use mail_web_adapter::MailboxEventSequenceError;
    use mail_web_adapter::ObservedMailboxEventSequence;

    let nonadvancing = ObservedMailboxEventWatermark::parse(
        "GET",
        "https://mail.proton.me/api/core/v5/events/event-1",
        r#"{"EventID":"event-1","More":1}"#,
    )
    .expect("parse nonadvancing provider page");
    assert_eq!(
        ObservedMailboxEventSequence::start(nonadvancing),
        Err(MailboxEventSequenceError::NonAdvancingContinuation)
    );

    let first = ObservedMailboxEventWatermark::parse(
        "GET",
        "https://mail.proton.me/api/core/v5/events/event-1",
        r#"{"EventID":"event-2","More":1}"#,
    )
    .expect("parse first provider page");
    let mut sequence =
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedMailboxEventSequence::start(first).expect("start resumable sequence");

    let gap = ObservedMailboxEventWatermark::parse(
        "GET",
        "https://mail.proton.me/api/core/v5/events/event-x",
        r#"{"EventID":"event-y","More":0}"#,
    )
    .expect("parse gap page");
    assert_eq!(
        sequence.push(gap),
        Err(MailboxEventSequenceError::CursorGap)
    );

    let refresh = ObservedMailboxEventWatermark::parse(
        "GET",
        "https://mail.proton.me/api/core/v5/events/event-2",
        r#"{"EventID":"event-3","More":0,"Refresh":1}"#,
    )
    .expect("parse refresh page");
    assert_eq!(
        sequence.push(refresh),
        Err(MailboxEventSequenceError::RefreshRequired)
    );

    let stuck = ObservedMailboxEventWatermark::parse(
        "GET",
        "https://mail.proton.me/api/core/v5/events/event-2",
        r#"{"EventID":"event-2","More":1}"#,
    )
    .expect("parse stuck continuation");
    assert_eq!(
        sequence.push(stuck),
        Err(MailboxEventSequenceError::NonAdvancingContinuation)
    );
}

#[test]
fn event_sequence_page_count_is_bounded() {
    use mail_web_adapter::MailboxEventSequenceError;
    use mail_web_adapter::ObservedMailboxEventSequence;

    let first = ObservedMailboxEventWatermark::parse(
        "GET",
        "https://mail.proton.me/api/core/v5/events/event-0",
        r#"{"EventID":"event-1","More":1}"#,
    )
    .expect("parse first bounded page");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut sequence = ObservedMailboxEventSequence::start(first).expect("start bounded sequence");
    for index in 1u8..32u8 {
        // jig-ignore-next-line: indivisible synthetic event URL.
        let url = format!("https://mail.proton.me/api/core/v5/events/event-{index}");
        let body = format!(r#"{{"EventID":"event-{}","More":1}}"#, index + 1);
        let page = ObservedMailboxEventWatermark::parse("GET", &url, &body)
            .expect("parse bounded continuation");
        sequence.push(page).expect("append bounded continuation");
    }
    assert_eq!(sequence.page_count(), 32);
    let overflow = ObservedMailboxEventWatermark::parse(
        "GET",
        "https://mail.proton.me/api/core/v5/events/event-32",
        r#"{"EventID":"event-33","More":0}"#,
    )
    .expect("parse overflow continuation");
    assert_eq!(
        sequence.push(overflow),
        Err(MailboxEventSequenceError::TooManyPages)
    );
}

fn event_browser_root(label: &str) -> PathBuf {
    env::temp_dir().join(format!(
        "protonmail-ai-event-browser-{label}-{}",
        process::id()
    ))
}

fn fake_event_browser(root: &Path, multi: bool, emit_event: bool) -> PathBuf {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    let script = root.join("fake-browser");
    let emit = i32::from(emit_event);
    let multi = i32::from(multi);
    let body = format!(
        r#"#!/usr/bin/env bash
set -eu
while IFS= read -r -d '' message <&3; do
  id=$(printf '%s' "$message" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$message" in
    *'Browser.getVersion'*)
      printf '{{"id":%s,"result":{{"product":"FakeChrome/1"}}}}\0' "$id" >&4;;
    *'Target.getTargets'*)
      # jig-ignore-next-line: indivisible synthetic shell fixture.
      target='[{{"targetId":"page-1","type":"page","url":"https://mail.proton.me/u/0/inbox"}}]'
      printf '{{"id":%s,"result":{{"targetInfos":%s}}}}\0' "$id" "$target" >&4;;
    *'Target.attachToTarget'*)
      printf '{{"id":%s,"result":{{"sessionId":"session-1"}}}}\0' "$id" >&4;;
    *'Runtime.evaluate'*)
      value='{{"protocol":"https:","hostname":"mail.proton.me","port":""}}'
      # jig-ignore-next-line: indivisible synthetic shell fixture.
      printf '{{"id":%s,"result":{{"result":{{"value":%s}}}}}}\0' "$id" "$value" >&4;;
    *'DOM.getDocument'*)
      printf '{{"id":%s,"result":{{"root":{{"nodeId":1}}}}}}\0' "$id" >&4;;
    *'Accessibility.queryAXTree'*)
      # jig-ignore-next-line: indivisible synthetic shell fixture.
      if [[ "$message" == *'"role":"navigation"'* || "$message" == *'"role":"search"'* ]]; then
        nodes='[{{"ignored":false}}]'
      else
        nodes='[]'
      fi
      printf '{{"id":%s,"result":{{"nodes":%s}}}}\0' "$id" "$nodes" >&4;;
    *'Network.enable'*)
      printf '{{"id":%s,"result":{{}}}}\0' "$id" >&4
      if [ {emit} -eq 1 ]; then
        (
          sleep 0.02
          # jig-ignore-next-line: indivisible synthetic shell fixture.
          url='https://mail.proton.me/api/core/v5/events/event-7?MessageCounts=1'
          # jig-ignore-next-line: indivisible synthetic shell fixture.
          request='{{"sessionId":"session-1","method":"Network.requestWillBeSent","params":{{"requestId":"event-1","request":{{"method":"GET","url":"'"$url"'"}}}}}}'
          # jig-ignore-next-line: indivisible synthetic shell fixture.
          response='{{"sessionId":"session-1","method":"Network.responseReceived","params":{{"requestId":"event-1","response":{{"url":"'"$url"'","status":200,"mimeType":"application/json"}}}}}}'
          # jig-ignore-next-line: indivisible synthetic shell fixture.
          finished='{{"sessionId":"session-1","method":"Network.loadingFinished","params":{{"requestId":"event-1"}}}}'
          printf '%s\0%s\0%s\0' "$request" "$response" "$finished" >&4
        ) &
      fi;;
    *'Network.getResponseBody'*'"requestId":"event-1"'*)
      if [ {multi} -eq 1 ]; then
        url='https://mail.proton.me/api/core/v5/events/event-8?MessageCounts=1'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        request='{{"sessionId":"session-1","method":"Network.requestWillBeSent","params":{{"requestId":"event-2","request":{{"method":"GET","url":"'"$url"'"}}}}}}'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        response='{{"sessionId":"session-1","method":"Network.responseReceived","params":{{"requestId":"event-2","response":{{"url":"'"$url"'","status":200,"mimeType":"application/json"}}}}}}'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        finished='{{"sessionId":"session-1","method":"Network.loadingFinished","params":{{"requestId":"event-2"}}}}'
        printf '%s\0%s\0%s\0' "$request" "$response" "$finished" >&4
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        body='{{\"EventID\":\"event-8\",\"More\":1,\"Messages\":[{{\"ID\":\"m-1\",\"Action\":1}}]}}'
      else
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        body='{{\"EventID\":\"event-8\",\"More\":0,\"Messages\":[{{\"ID\":\"m-1\",\"Action\":1}}]}}'
      fi
      # jig-ignore-next-line: indivisible synthetic shell fixture.
      printf '{{"id":%s,"result":{{"body":"%s","base64Encoded":false}}}}\0' "$id" "$body" >&4;;
    *'Network.getResponseBody'*'"requestId":"event-2"'*)
      # jig-ignore-next-line: indivisible synthetic shell fixture.
      body='{{\"EventID\":\"event-9\",\"More\":0,\"Messages\":[{{\"ID\":\"m-1\",\"Action\":1}},{{\"ID\":\"m-1\",\"Action\":3}}]}}'
      # jig-ignore-next-line: indivisible synthetic shell fixture.
      printf '{{"id":%s,"result":{{"body":"%s","base64Encoded":false}}}}\0' "$id" "$body" >&4;;
    *'Network.disable'*)
      printf '{{"id":%s,"result":{{}}}}\0' "$id" >&4;;
    *'Target.detachFromTarget'*)
      printf '{{"id":%s,"result":{{}}}}\0' "$id" >&4;;
    *) exit 92;;
  esac
done
"#,
    );
    fs::write(&script, body).expect("write event fake browser");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
        .expect("chmod event fake browser");
    script
}

fn with_event_browser<T>(
    label: &str,
    multi: bool,
    emit_event: bool,
    // jig-ignore-next-line: canonical rustfmt line.
    test: impl FnOnce(&mut mail_web_adapter::ManagedBrowser, &mail_web_adapter::ProviderPage) -> T,
) -> T {
    use std::fs;

    let _guard = EVENT_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic event browser tests");
    let root = event_browser_root(label);
    fs::create_dir_all(&root).expect("create event browser root");
    let browser = fake_event_browser(&root, multi, emit_event);
    let plan = mail_web_adapter::ManagedBrowserPlan::under_data_home(
        browser.to_str().expect("event browser path UTF-8"),
        &root.join("data"),
    )
    .expect("build event browser plan");
    let mut managed =
        // jig-ignore-next-line: canonical rustfmt line.
        mail_web_adapter::ManagedBrowser::launch(&plan).expect("launch event fake browser");
    let page = managed.provider_page().expect("discover event Mail page");
    let result = test(&mut managed, &page);
    drop(managed);
    fs::remove_dir_all(root).expect("remove event browser root");
    result
}

#[test]
fn browser_passively_projects_one_settled_event_poll() {
    use std::time::Duration;

    let result = with_event_browser("single", false, true, |browser, page| {
        browser.observe_mailbox_event_sequence(page, Duration::from_secs(1))
    });
    let sequence = result
        .expect("observe synthetic event sequence")
        .expect("event must arrive");
    assert!(sequence.settled());
    assert_eq!(sequence.start_event_id(), "event-7");
    assert_eq!(sequence.next_event_id(), "event-8");
    assert_eq!(sequence.changes().len(), 1);
    assert_eq!(sequence.changes()[0].id(), "m-1");
}

#[test]
fn browser_drains_immediate_more_continuation_without_injecting_api_calls() {
    use std::time::Duration;

    let result = with_event_browser("multi", true, true, |browser, page| {
        browser.observe_mailbox_event_sequence(page, Duration::from_secs(1))
    });
    let sequence = result
        .expect("observe synthetic continued event sequence")
        .expect("event must arrive");
    assert!(sequence.settled());
    assert_eq!(sequence.page_count(), 2);
    assert_eq!(sequence.next_event_id(), "event-9");
    assert_eq!(sequence.changes().len(), 2);
    assert_eq!(sequence.changes()[0].kind(), MailboxChangeKind::Created);
    assert_eq!(sequence.changes()[1].kind(), MailboxChangeKind::Updated);
}

#[test]
fn browser_event_wait_timeout_is_successful_empty_and_respects_short_bound() {
    use std::time::{Duration, Instant};

    // jig-ignore-next-line: canonical rustfmt line.
    let (result, elapsed) = with_event_browser("timeout", false, false, |browser, page| {
        let started = Instant::now();
        // jig-ignore-next-line: canonical rustfmt line.
        let result = browser.observe_mailbox_event_sequence(page, Duration::from_millis(30));
        (result, started.elapsed())
    });
    assert_eq!(result, Ok(None));
    assert!(elapsed < Duration::from_secs(1));
}

#[test]
fn browser_event_wait_rejects_more_than_thirty_seconds() {
    use std::time::Duration;

    let result = with_event_browser("too-long", false, false, |browser, page| {
        browser.observe_mailbox_event_sequence(page, Duration::from_secs(31))
    });
    assert_eq!(
        result,
        Err(mail_web_adapter::BrowserDriverError::MailboxEventWaitTooLong)
    );
}

#[test]
fn browser_resume_requires_exact_acknowledged_event_watermark() {
    use std::time::Duration;

    // jig-ignore-next-line: canonical rustfmt line.
    let matching = with_event_browser("resume-match", false, true, |browser, page| {
        // jig-ignore-next-line: canonical rustfmt line.
        browser.observe_mailbox_event_sequence_from(page, "event-7", Duration::from_secs(1))
    });
    let sequence = matching
        .expect("matching acknowledged cursor must be observed")
        .expect("matching event must arrive");
    assert_eq!(sequence.start_event_id(), "event-7");

    // jig-ignore-next-line: canonical rustfmt line.
    let drifted = with_event_browser("resume-gap", false, true, |browser, page| {
        // jig-ignore-next-line: canonical rustfmt line.
        browser.observe_mailbox_event_sequence_from(page, "event-6", Duration::from_secs(1))
    });
    assert_eq!(
        drifted,
        Err(mail_web_adapter::BrowserDriverError::MailboxEventSequence(
            MailboxEventSequenceError::CursorGap
        ))
    );
}

#[test]
fn browser_scoped_cursor_resume_requires_current_scope() {
    use std::time::Duration;

    let scope =
        // jig-ignore-next-line: canonical rustfmt line.
        EventCursorScope::new("account-a", "web", "generation-7").expect("valid current scope");
    let cursor = scope.clone().bind(String::from("event-7"));
    // jig-ignore-next-line: canonical rustfmt line.
    let matching = with_event_browser("scoped-resume", false, true, |browser, page| {
        browser.observe_mailbox_event_sequence_from_cursor(
            page,
            &cursor,
            &scope,
            Duration::from_secs(1),
        )
    });
    assert_eq!(
        matching
            .expect("matching scoped cursor must resume")
            .map(|sequence| String::from(sequence.next_event_id())),
        Some(String::from("event-8"))
    );

    let drifted_scope =
        // jig-ignore-next-line: canonical rustfmt line.
        EventCursorScope::new("account-a", "web", "generation-8").expect("valid drifted scope");
    // jig-ignore-next-line: canonical rustfmt line.
    let rejected = with_event_browser("scoped-drift", false, false, |browser, page| {
        browser.observe_mailbox_event_sequence_from_cursor(
            page,
            &cursor,
            &drifted_scope,
            Duration::from_millis(30),
        )
    });
    assert_eq!(
        rejected,
        Err(mail_web_adapter::BrowserDriverError::EventCursorBinding(
            EventCursorBindingError::ScopeMismatch
        ))
    );
}

#[test]
fn browser_resume_timeout_preserves_existing_acknowledged_watermark() {
    use std::time::Duration;

    // jig-ignore-next-line: canonical rustfmt line.
    let result = with_event_browser("resume-timeout", false, false, |browser, page| {
        // jig-ignore-next-line: canonical rustfmt line.
        browser.observe_mailbox_event_sequence_from(page, "event-7", Duration::from_millis(30))
    });
    assert_eq!(result, Ok(None));
}

#[test]
fn browser_resume_rejects_malformed_provider_watermark() {
    use std::time::Duration;

    // jig-ignore-next-line: canonical rustfmt line.
    let result = with_event_browser("resume-invalid", false, false, |browser, page| {
        // jig-ignore-next-line: canonical rustfmt line.
        browser.observe_mailbox_event_sequence_from(page, "bad/event", Duration::from_millis(30))
    });
    assert_eq!(
        result,
        Err(mail_web_adapter::BrowserDriverError::MailboxEventWatermark(
            MailboxEventWatermarkError::Malformed
        ))
    );
}
