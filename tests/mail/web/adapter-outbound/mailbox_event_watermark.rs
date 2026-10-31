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

use mail_capability_domain::EventCursorResumeFailure;
use mail_capability_domain::EventCursorScope;
use mail_web_adapter::LatestMailboxEventNetworkCapture;
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
fn encoded_event_continuation_has_scrub_on_drop_custody() {
    use mail_web_adapter::SerializedMailboxChangePage;

    #[expect(drop_bounds, reason = "require private cursor scrubbing")]
    fn requires_scrub_on_drop<T>()
    where
        T: Drop,
    {
    }
    requires_scrub_on_drop::<SerializedMailboxChangePage>();
}

#[test]
fn retained_event_watermarks_and_change_ids_require_drop_custody() {
    use mail_web_adapter::ObservedMailboxChange;
    use mail_web_adapter::ObservedMailboxEventSequence;

    #[expect(drop_bounds, reason = "require explicit event metadata scrubbing")]
    fn requires_scrub_on_drop<T>()
    where
        T: Drop,
    {
    }
    requires_scrub_on_drop::<ObservedLatestMailboxEventWatermark>();
    requires_scrub_on_drop::<ObservedMailboxEventWatermark>();
    requires_scrub_on_drop::<ObservedMailboxChange>();
    requires_scrub_on_drop::<ObservedMailboxEventSequence>();
}

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
fn latest_event_watermark_binds_provider_neutral_cursor_scope() {
    let latest = ObservedLatestMailboxEventWatermark::parse(
        "GET",
        "https://mail.proton.me/api/core/v4/events/latest",
        r#"{"EventID":"event-bootstrap"}"#,
    )
    .expect("project latest event watermark");
    let scope = EventCursorScope::new("account-a", "web", "generation-7")
        .expect("valid bootstrap cursor scope");
    let cursor = latest.bind_cursor(scope.clone());
    assert_eq!(
        cursor.state_for(&scope).map(String::as_str),
        Ok("event-bootstrap")
    );
}

#[test]
fn latest_event_cdp_projection_requires_decoded_bounded_json() {
    use serde_json::json;

    let latest = ObservedLatestMailboxEventWatermark::parse_cdp_body(&json!({
        "body":"{\"EventID\":\"event-bootstrap\"}",
        "base64Encoded":false
    }))
    .expect("project decoded latest-event CDP body");
    assert_eq!(latest.event_id(), "event-bootstrap");
    assert_eq!(
        ObservedLatestMailboxEventWatermark::parse_cdp_body(&json!({
            "body":"e30=","base64Encoded":true
        })),
        Err(MailboxEventWatermarkError::UnsupportedEncoding)
    );
    assert_eq!(
        ObservedLatestMailboxEventWatermark::parse_cdp_body(&json!({
            "body":"{}"
        })),
        Err(MailboxEventWatermarkError::Malformed)
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
fn nonadjacent_event_changes_coalesce_without_merging_other_entities() {
    let body = r#"{
        "EventID":"event-8","More":0,
        "Messages":[
            {"ID":"private-a","Action":1},
            {"ID":"private-b","Action":1},
            {"ID":"private-a","Action":1}
        ],
        "Conversations":[{"ID":"private-a","Action":1}]
    }"#;
    let observed = ObservedMailboxEventWatermark::parse("GET", URL, body)
        .expect("coalesce only matching type, action and ID");
    let changes = observed.changes();
    assert_eq!(changes.len(), 3);
    assert_eq!(changes[0].id(), "private-a");
    assert_eq!(changes[1].id(), "private-b");
    assert_eq!(changes[2].id(), "private-a");
    assert_eq!(changes[2].entity(), MailboxChangeEntity::Conversation);
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
fn latest_network_capture_tracks_only_exact_bootstrap_get() {
    use serde_json::json;

    let url = "https://mail.proton.me/api/core/v4/events/latest";
    let mut capture = LatestMailboxEventNetworkCapture::new("session-1");
    for ignored in [
        json!({
            "sessionId":"session-2","method":"Network.requestWillBeSent",
            "params":{"requestId":"other-session","request":{
                "method":"GET","url":url
            }}
        }),
        json!({
            "sessionId":"session-1","method":"Network.requestWillBeSent",
            "params":{"requestId":"v5","request":{
                "method":"GET","url":URL
            }}
        }),
        json!({
            "sessionId":"session-1","method":"Network.requestWillBeSent",
            "params":{"requestId":"post","request":{
                "method":"POST","url":url
            }}
        }),
    ] {
        capture
            .observe(&ignored)
            .expect("ignore non-bootstrap traffic");
    }
    capture
        .observe(&json!({
            "sessionId":"session-1","method":"Network.requestWillBeSent",
            "params":{"requestId":"latest","request":{
                "method":"GET","url":url,
                "headers":{"Authorization":"Bearer secret"}
            }}
        }))
        .expect("track exact latest request");
    capture
        .observe(&json!({
            "sessionId":"session-1","method":"Network.responseReceived",
            "params":{"requestId":"latest","response":{
                "url":url,"status":200u16,"mimeType":"application/json",
                "headers":{"Set-Cookie":"secret-cookie"}
            }}
        }))
        .expect("accept exact latest response");
    capture
        .observe(&json!({
            "sessionId":"session-1","method":"Network.loadingFinished",
            "params":{"requestId":"latest"}
        }))
        .expect("finish exact latest request");
    assert_eq!(
        capture.take_finished_request_ids(),
        [String::from("latest")]
    );
    let debug = format!("{capture:?}");
    for secret in ["session-1", "Bearer secret", "secret-cookie"] {
        assert!(!debug.contains(secret));
    }
}

#[test]
fn latest_network_capture_discards_failed_attempt_before_retry() {
    use serde_json::json;

    let url = "https://mail.proton.me/api/core/v4/events/latest";
    let request = || {
        json!({
            "sessionId":"session-1","method":"Network.requestWillBeSent",
            "params":{"requestId":"latest-retry","request":{
                "method":"GET","url":url
            }}
        })
    };
    let mut capture = LatestMailboxEventNetworkCapture::new("session-1");
    capture
        .observe(&request())
        .expect("track failed latest attempt");
    capture
        .observe(&json!({
            "sessionId":"session-1","method":"Network.loadingFailed",
            "params":{"requestId":"latest-retry"}
        }))
        .expect("discard failed latest attempt");
    capture.observe(&request()).expect("track latest retry");
    capture
        .observe(&json!({
            "sessionId":"session-1","method":"Network.responseReceived",
            "params":{"requestId":"latest-retry","response":{
                "url":url,"status":200u16,"mimeType":"application/json"
            }}
        }))
        .expect("accept latest retry response");
    capture
        .observe(&json!({
            "sessionId":"session-1","method":"Network.loadingFinished",
            "params":{"requestId":"latest-retry"}
        }))
        .expect("finish latest retry");
    assert_eq!(
        capture.take_finished_request_ids(),
        [String::from("latest-retry")]
    );
}

#[test]
fn actual_network_status_200_preserves_event_cursor_capture() {
    use mail_web_adapter::MailboxEventNetworkCapture;
    use serde_json::json;

    let latest = "https://mail.proton.me/api/core/v4/events/latest";
    for (is_latest, url) in [(true, latest), (false, URL)] {
        let request = json!({
            "sessionId":"session-1","method":"Network.requestWillBeSent",
            "params":{"requestId":"event","request":{
                "method":"GET","url":url
            }}
        });
        let response = json!({
            "sessionId":"session-1","method":"Network.responseReceived",
            "params":{"requestId":"event","response":{
                "url":url,"status":200u16,"mimeType":"application/json"
            }}
        });
        let extra = json!({
            "sessionId":"session-1",
            "method":"Network.responseReceivedExtraInfo",
            "params":{"requestId":"event","statusCode":200u16}
        });
        let finished = json!({
            "sessionId":"session-1","method":"Network.loadingFinished",
            "params":{"requestId":"event"}
        });
        if is_latest {
            let session = "session-1";
            let mut capture = LatestMailboxEventNetworkCapture::new(session);
            capture.observe(&request).expect("track latest GET");
            capture.observe(&extra).expect("accept actual HTTP 200");
            capture.observe(&response).expect("accept response");
            capture.observe(&finished).expect("complete latest GET");
            assert_eq!(capture.take_finished_request_ids(), ["event"]);
        } else {
            let mut capture = MailboxEventNetworkCapture::new("session-1");
            capture.observe(&request).expect("track poll GET");
            capture.observe(&extra).expect("accept actual HTTP 200");
            capture.observe(&response).expect("accept response");
            capture.observe(&finished).expect("complete poll GET");
            assert_eq!(capture.take_finished_request_ids(), ["event"]);
        }
    }
}

#[test]
fn declared_extra_status_is_required_for_both_event_cursors() {
    use mail_web_adapter::MailboxEventNetworkCapture;
    use serde_json::json;
    let latest = "https://mail.proton.me/api/core/v4/events/latest";
    for (is_latest, url) in [(true, latest), (false, URL)] {
        let request = json!({
            "sessionId":"session-1", "method":"Network.requestWillBeSent",
            "params":{"requestId":"extra", "request":{"method":"GET","url":url}}
        });
        let response = json!({
            "sessionId":"session-1", "method":"Network.responseReceived",
            "params":{"requestId":"extra", "hasExtraInfo":true, "response":{
                "url":url,"status":200u16,"mimeType":"application/json"}}
        });
        let finished = json!({
            "sessionId":"session-1", "method":"Network.loadingFinished",
            "params":{"requestId":"extra"}
        });
        let extra = json!({
            // jig-ignore-next-line: synthetic CDP fixture.
            "sessionId":"session-1", "method":"Network.responseReceivedExtraInfo",
            "params":{"requestId":"extra","statusCode":200u16}
        });
        if is_latest {
            // jig-ignore-next-line: synthetic CDP fixture.
            let mut capture = LatestMailboxEventNetworkCapture::new("session-1");
            capture.observe(&request).expect("track latest request");
            capture.observe(&response).expect("accept nominal response");
            capture.observe(&finished).expect("finish latest response");
            assert!(capture.take_finished_request_ids().is_empty());
            capture.observe(&extra).expect("accept status");
            assert_eq!(capture.take_finished_request_ids(), ["extra"]);
        } else {
            let mut capture = MailboxEventNetworkCapture::new("session-1");
            capture.observe(&request).expect("track poll request");
            capture.observe(&response).expect("accept nominal response");
            capture.observe(&finished).expect("finish poll response");
            assert!(capture.take_finished_request_ids().is_empty());
            capture.observe(&extra).expect("accept status");
            assert_eq!(capture.take_finished_request_ids(), ["extra"]);
        }
    }
}

#[test]
fn revalidated_cache_status_rejects_both_event_cursor_gets() {
    use mail_web_adapter::MailboxEventNetworkCapture;
    use mail_web_adapter::MailboxEventNetworkError;
    use serde_json::json;

    let latest = "https://mail.proton.me/api/core/v4/events/latest";
    for (is_latest, url) in [(true, latest), (false, URL)] {
        for after_response in [false, true] {
            let request = json!({
                "sessionId":"session-1","method":"Network.requestWillBeSent",
                "params":{"requestId":"event","request":{
                    "method":"GET","url":url
                }}
            });
            let response = json!({
                "sessionId":"session-1","method":"Network.responseReceived",
                "params":{"requestId":"event","response":{
                    "url":url,"status":200u16,"mimeType":"application/json"
                }}
            });
            let extra = json!({
                "sessionId":"session-1",
                "method":"Network.responseReceivedExtraInfo",
                "params":{"requestId":"event","statusCode":304u16}
            });
            if is_latest {
                let session = "session-1";
                // jig-ignore-next-line: canonical constructor call.
                let mut capture = LatestMailboxEventNetworkCapture::new(session);
                capture.observe(&request).expect("track latest request");
                if after_response {
                    capture.observe(&response).expect("first report 200");
                }
                assert_eq!(
                    capture.observe(&extra),
                    Err(MailboxEventNetworkError::ResponseRejected)
                );
            } else {
                let mut capture = MailboxEventNetworkCapture::new("session-1");
                capture.observe(&request).expect("track event request");
                if after_response {
                    capture.observe(&response).expect("first report 200");
                }
                assert_eq!(
                    capture.observe(&extra),
                    Err(MailboxEventNetworkError::ResponseRejected)
                );
            }
        }
    }
}

#[test]
fn standalone_cache_hit_rejects_both_event_watermark_requests() {
    use mail_web_adapter::MailboxEventNetworkCapture;
    use mail_web_adapter::MailboxEventNetworkError;
    use serde_json::json;

    let latest = "https://mail.proton.me/api/core/v4/events/latest";
    for (is_latest, url) in [(true, latest), (false, URL)] {
        for after_response in [false, true] {
            let request = json!({
                "sessionId":"session-1","method":"Network.requestWillBeSent",
                "params":{"requestId":"event","request":{
                    "method":"GET","url":url
                }}
            });
            let response = json!({
                "sessionId":"session-1","method":"Network.responseReceived",
                "params":{"requestId":"event","response":{
                    "url":url,"status":200u16,"mimeType":"application/json"
                }}
            });
            let cache = json!({
                "sessionId":"session-1",
                "method":"Network.requestServedFromCache",
                "params":{"requestId":"event"}
            });
            let unrelated = json!({
                "sessionId":"session-1",
                "method":"Network.requestServedFromCache",
                "params":{"requestId":"unrelated"}
            });
            if is_latest {
                let session = "session-1";
                // jig-ignore-next-line: canonical constructor call.
                let mut capture = LatestMailboxEventNetworkCapture::new(session);
                capture.observe(&request).expect("track latest GET");
                capture.observe(&unrelated).expect("ignore unrelated cache");
                if after_response {
                    capture
                        .observe(&response)
                        .expect("response before cache hit");
                }
                assert_eq!(
                    capture.observe(&cache),
                    Err(MailboxEventNetworkError::ResponseRejected)
                );
                assert!(capture.take_finished_request_ids().is_empty());
            } else {
                let mut capture = MailboxEventNetworkCapture::new("session-1");
                capture.observe(&request).expect("track event GET");
                capture.observe(&unrelated).expect("ignore unrelated cache");
                if after_response {
                    capture
                        .observe(&response)
                        .expect("response before cache hit");
                }
                assert_eq!(
                    capture.observe(&cache),
                    Err(MailboxEventNetworkError::ResponseRejected)
                );
                assert!(capture.take_finished_request_ids().is_empty());
            }
        }
    }
}

#[test]
fn core_event_watermarks_reject_cache_and_service_worker_responses() {
    use mail_web_adapter::MailboxEventNetworkCapture;
    use mail_web_adapter::MailboxEventNetworkError;
    use serde_json::json;

    let latest_url = "https://mail.proton.me/api/core/v4/events/latest";
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
        ("fromDiskCache", json!("false")),
        ("fromServiceWorker", json!(null)),
    ] {
        for (label, url) in [("latest", latest_url), ("poll", URL)] {
            let request = json!({
                "sessionId":"session-1","method":"Network.requestWillBeSent",
                "params":{
                    "requestId":"r-1","request":{"method":"GET","url":url}
                }
            });
            let mut response = json!({
                "sessionId":"session-1","method":"Network.responseReceived",
                "params":{"requestId":"r-1","response":{
                    "url":url,"status":200u16,"mimeType":"application/json"
                }}
            });
            response["params"]["response"][flag] = value.clone();
            if label == "latest" {
                let session = "session-1";
                // jig-ignore-next-line: required synthetic session constructor.
                let mut capture = LatestMailboxEventNetworkCapture::new(session);
                capture.observe(&request).expect("track latest request");
                assert_eq!(
                    capture.observe(&response),
                    Err(MailboxEventNetworkError::ResponseRejected),
                    "latest must reject {flag}"
                );
            } else {
                let mut capture = MailboxEventNetworkCapture::new("session-1");
                capture.observe(&request).expect("track poll request");
                assert_eq!(
                    capture.observe(&response),
                    Err(MailboxEventNetworkError::ResponseRejected),
                    "poll must reject {flag}"
                );
            }
        }
    }
}

#[test]
fn explicitly_uncached_core_event_responses_preserve_cursor_progress() {
    use mail_web_adapter::MailboxEventNetworkCapture;
    use serde_json::json;

    let latest = "https://mail.proton.me/api/core/v4/events/latest";
    for (label, url) in [("latest", latest), ("poll", URL)] {
        let request = json!({
            "sessionId":"session-1","method":"Network.requestWillBeSent",
            "params":{"requestId":"fresh","request":{"method":"GET","url":url}}
        });
        let response = json!({
            "sessionId":"session-1","method":"Network.responseReceived",
            "params":{"requestId":"fresh","response":{
                "url":url,"status":200u16,"mimeType":"application/json",
                "fromDiskCache":false,"fromServiceWorker":false,
                "fromPrefetchCache":false,"fromEarlyHints":false
            }}
        });
        let finished = json!({
            "sessionId":"session-1","method":"Network.loadingFinished",
            "params":{"requestId":"fresh"}
        });
        if label == "latest" {
            let session = "session-1";
            let mut capture = LatestMailboxEventNetworkCapture::new(session);
            capture.observe(&request).expect("track latest");
            capture.observe(&response).expect("accept uncached latest");
            capture.observe(&finished).expect("complete latest");
            let expected = [String::from("fresh")];
            assert_eq!(capture.take_finished_request_ids(), expected);
        } else {
            let mut capture = MailboxEventNetworkCapture::new("session-1");
            capture.observe(&request).expect("track poll");
            capture.observe(&response).expect("accept uncached poll");
            capture.observe(&finished).expect("complete poll");
            let expected = [String::from("fresh")];
            assert_eq!(capture.take_finished_request_ids(), expected);
        }
    }
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
    assert_eq!(capture.take_finished_request_ids().len(), 0);
}

#[test]
fn network_capture_rejects_redirect_failure_and_bad_response() {
    use mail_web_adapter::MailboxEventNetworkCapture;
    use mail_web_adapter::MailboxEventNetworkError;
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
    failed
        .observe(&json!({
            "sessionId":"session-1","method":"Network.loadingFailed",
            "params":{"requestId":"failed"}
        }))
        .expect("discard failed attempt while provider owns retry");
    failed
        .observe(&request("failed"))
        .expect("accept exact provider retry from same cursor");
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
fn promised_status_keeps_latest_and_poll_requests_bounded() {
    // jig-ignore-next-line: synthetic pending CDP request guard.
    use mail_web_adapter::{MailboxEventNetworkCapture, MailboxEventNetworkError};
    use serde_json::json;

    let latest_url = "https://mail.proton.me/api/core/v4/events/latest";
    let mut latest = LatestMailboxEventNetworkCapture::new("session-1");
    let mut poll = MailboxEventNetworkCapture::new("session-1");
    for index in 0u8..32u8 {
        let id = format!("pending-event-{index}");
        for (url, is_latest) in [(latest_url, true), (URL, false)] {
            // jig-ignore-next-line: synthetic pending CDP request guard.
            let request = cdp_lifecycle_event("Network.requestWillBeSent", &id, url);
            // jig-ignore-next-line: synthetic pending CDP request guard.
            let mut response = cdp_lifecycle_event("Network.responseReceived", &id, url);
            response["params"]["hasExtraInfo"] = json!(true);
            // jig-ignore-next-line: synthetic pending CDP request guard.
            let finished = cdp_lifecycle_event("Network.loadingFinished", &id, url);
            if is_latest {
                latest.observe(&request).expect("track latest event");
                latest
                    .observe(&response)
                    .expect("accept nominal latest status");
                latest.observe(&finished).expect("finish latest event");
                assert!(latest.take_finished_request_ids().is_empty());
            } else {
                poll.observe(&request).expect("track poll event");
                poll.observe(&response).expect("accept nominal poll status");
                poll.observe(&finished).expect("finish poll event");
                assert!(poll.take_finished_request_ids().is_empty());
            }
        }
    }
    // jig-ignore-next-line: synthetic pending CDP request guard.
    let late = cdp_lifecycle_event("Network.requestWillBeSent", "overflow", latest_url);
    // jig-ignore-next-line: synthetic pending CDP request guard.
    let events = cdp_lifecycle_event("Network.requestWillBeSent", "overflow", URL);
    assert_eq!(
        latest.observe(&late),
        Err(MailboxEventNetworkError::CapacityExceeded)
    );
    assert_eq!(
        poll.observe(&events),
        Err(MailboxEventNetworkError::CapacityExceeded)
    );
    assert!(!format!("{latest:?}").contains("pending-event-"));
    assert!(!format!("{poll:?}").contains("pending-event-"));
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
fn change_pages_preserve_timeout_cursor_and_project_settled_sequence() {
    use mail_web_adapter::ObservedMailboxChangePage;

    let scope =
        // jig-ignore-next-line: canonical rustfmt line.
        EventCursorScope::new("account-a", "web", "generation-7").expect("valid change-page scope");
    let bootstrap = ObservedLatestMailboxEventWatermark::parse(
        "GET",
        "https://mail.proton.me/api/core/v4/events/latest",
        r#"{"EventID":"event-1"}"#,
    )
    .expect("parse bootstrap watermark");
    // jig-ignore-next-line: canonical rustfmt line.
    let initial = ObservedMailboxChangePage::from_bootstrap(scope.clone(), &bootstrap);
    assert_eq!(initial.changes().len(), 0);
    assert_eq!(
        initial.next_cursor().state_for(&scope).map(String::as_str),
        Ok("event-1")
    );

    // jig-ignore-next-line: canonical rustfmt line.
    let timed_out = ObservedMailboxChangePage::from_timeout(initial.next_cursor().clone());
    assert_eq!(timed_out.changes().len(), 0);
    assert_eq!(timed_out.next_cursor(), initial.next_cursor());

    let event = ObservedMailboxEventWatermark::parse(
        "GET",
        "https://mail.proton.me/api/core/v5/events/event-1",
        // jig-ignore-next-line: canonical rustfmt line.
        r#"{"EventID":"event-2","More":0,"Messages":[{"ID":"m-1","Action":1}]}"#,
    )
    .expect("parse settled change page");
    let sequence = mail_web_adapter::ObservedMailboxEventSequence::start(event)
        .expect("settle one-page sequence");
    let page = ObservedMailboxChangePage::from_sequence(scope.clone(), sequence)
        .expect("project settled sequence");
    assert_eq!(page.changes().len(), 1);
    assert_eq!(page.changes()[0].id(), "m-1");
    assert_eq!(
        page.next_cursor().state_for(&scope).map(String::as_str),
        Ok("event-2")
    );
    let debug = format!("{page:?}");
    for secret in ["event-2", "m-1"] {
        assert!(!debug.contains(secret));
    }
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

// jig-ignore-next-line: canonical rustfmt line.
#[expect(clippy::too_many_lines, reason = "one synthetic CDP browser lifecycle")]
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
      reply_format='{{"id":%s,"sessionId":"session-1",'
      reply_format+='"result":{{"result":{{"value":%s}}}}}}\0'
      printf "$reply_format" "$id" "$value" >&4;;
    *'DOM.getDocument'*)
      reply_format='{{"id":%s,"sessionId":"session-1",'
      # jig-ignore-next-line: indivisible synthetic CDP document root.
      reply_format+='"result":{{"root":{{"nodeId":1,"backendNodeId":2,"nodeType":9,"nodeName":"\u0023document","localName":"","nodeValue":""}}}}}}\0'
      printf "$reply_format" "$id" >&4;;
    *'Accessibility.queryAXTree'*)
      # jig-ignore-next-line: indivisible synthetic shell fixture.
      if [[ "$message" == *'"role":"navigation"'* || "$message" == *'"role":"search"'* ]]; then
        # jig-ignore-next-line: indivisible synthetic CDP AXNode fixture.
        nodes='[{{"ignored":false,"nodeId":"ax-__AX_ROLE__","role":{{"type":"role","value":"__AX_ROLE__"}}}}]'
      else
        nodes='[]'
      fi
      # QueryAXTree commands carry one exact, reviewed role filter.
      requested_role=$(printf '%s' "$message" |
        sed -n 's/.*"role":"\([^"]*\)".*/\1/p')
      [ -n "$requested_role" ] || exit 91
      nodes=$(printf '%s' "$nodes" | sed "s/__AX_ROLE__/$requested_role/g")
      reply_format='{{"id":%s,"sessionId":"session-1",'
      reply_format+='"result":{{"nodes":%s}}}}\0'
      printf "$reply_format" "$id" "$nodes" >&4;;
    *'Network.enable'*)
      printf '{{"id":%s,"sessionId":"session-1","result":{{}}}}\0' "$id" >&4
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
    *'Page.reload'*)
      printf '{{"id":%s,"sessionId":"session-1","result":{{}}}}\0' "$id" >&4
      (
        sleep 0.02
        latest='https://mail.proton.me/api/core/v4/events/latest'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        request='{{"sessionId":"session-1","method":"Network.requestWillBeSent","params":{{"requestId":"latest-1","request":{{"method":"GET","url":"'"$latest"'","headers":{{"Authorization":"Bearer secret"}}}}}}}}'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        response='{{"sessionId":"session-1","method":"Network.responseReceived","params":{{"requestId":"latest-1","response":{{"url":"'"$latest"'","status":200,"mimeType":"application/json","headers":{{"Set-Cookie":"secret-cookie"}}}}}}}}'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        finished='{{"sessionId":"session-1","method":"Network.loadingFinished","params":{{"requestId":"latest-1"}}}}'
        printf '%s\0%s\0%s\0' "$request" "$response" "$finished" >&4
      ) &;;
    *'Network.getResponseBody'*'"requestId":"latest-1"'*)
      if [ {multi} -eq 1 ] && [ {emit} -eq 0 ]; then
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        url='https://mail.proton.me/api/core/v5/events/event-bootstrap?MessageCounts=1'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        request='{{"sessionId":"session-1","method":"Network.requestWillBeSent","params":{{"requestId":"bootstrap-event-1","request":{{"method":"GET","url":"'"$url"'"}}}}}}'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        response='{{"sessionId":"session-1","method":"Network.responseReceived","params":{{"requestId":"bootstrap-event-1","response":{{"url":"'"$url"'","status":200,"mimeType":"application/json"}}}}}}'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        finished='{{"sessionId":"session-1","method":"Network.loadingFinished","params":{{"requestId":"bootstrap-event-1"}}}}'
        printf '%s\0%s\0%s\0' "$request" "$response" "$finished" >&4
      fi
      body='{{\"EventID\":\"event-bootstrap\",\"decoy\":\"secret-body\"}}'
      reply_format='{{"id":%s,"sessionId":"session-1",'
      reply_format+='"result":{{"body":"%s","base64Encoded":false}}}}\0'
      printf "$reply_format" "$id" "$body" >&4;;
    *'Network.getResponseBody'*'"requestId":"bootstrap-event-1"'*)
      # jig-ignore-next-line: indivisible synthetic shell fixture.
      body='{{\"EventID\":\"event-bootstrap-next\",\"More\":0,\"Messages\":[{{\"ID\":\"m-bootstrap\",\"Action\":1}}]}}'
      reply_format='{{"id":%s,"sessionId":"session-1",'
      reply_format+='"result":{{"body":"%s","base64Encoded":false}}}}\0'
      printf "$reply_format" "$id" "$body" >&4;;
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
      reply_format='{{"id":%s,"sessionId":"session-1",'
      reply_format+='"result":{{"body":"%s","base64Encoded":false}}}}\0'
      printf "$reply_format" "$id" "$body" >&4;;
    *'Network.getResponseBody'*'"requestId":"event-2"'*)
      # jig-ignore-next-line: indivisible synthetic shell fixture.
      body='{{\"EventID\":\"event-9\",\"More\":0,\"Messages\":[{{\"ID\":\"m-1\",\"Action\":1}},{{\"ID\":\"m-1\",\"Action\":3}}]}}'
      reply_format='{{"id":%s,"sessionId":"session-1",'
      reply_format+='"result":{{"body":"%s","base64Encoded":false}}}}\0'
      printf "$reply_format" "$id" "$body" >&4;;
    *'Network.disable'*)
      printf '{{"id":%s,"sessionId":"session-1","result":{{}}}}\0' "$id" >&4;;
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
fn browser_initial_change_wait_bridges_bootstrap_without_network_gap() {
    use std::time::Duration;

    let scope = EventCursorScope::new("account-a", "web", "generation-7")
        .expect("valid initial change scope");
    // jig-ignore-next-line: canonical rustfmt line.
    let page = with_event_browser("initial-change", true, false, |browser, provider| {
        // jig-ignore-next-line: canonical rustfmt line.
        browser.observe_initial_mailbox_changes(provider, scope.clone(), Duration::from_secs(1))
    })
    .expect("observe initial synthetic change page");
    assert_eq!(page.changes().len(), 1);
    assert_eq!(page.changes()[0].id(), "m-bootstrap");
    assert_eq!(page.changes()[0].kind(), MailboxChangeKind::Created);
    assert_eq!(
        page.next_cursor().state_for(&scope).map(String::as_str),
        Ok("event-bootstrap-next")
    );
    let debug = format!("{page:?}");
    for secret in ["m-bootstrap", "event-bootstrap-next", "secret-body"] {
        assert!(!debug.contains(secret));
    }
}

#[test]
fn browser_serialized_change_wait_round_trips_timeout_cursor() {
    use std::time::Duration;

    let (initial, resumed, wrong_account, logical_state) = with_event_browser(
        "serialized-change-timeout",
        false,
        false,
        |browser, provider| {
            let initial = browser
                .observe_initial_mailbox_changes_serialized(
                    provider,
                    "synthetic-account-secret",
                    Duration::from_millis(30),
                )
                .expect("observe serialized initial timeout");
            let initial_token = String::from(initial.next_cursor());
            let resumed = browser
                .observe_mailbox_changes_from_token(
                    provider,
                    &initial_token,
                    "synthetic-account-secret",
                    Duration::from_millis(30),
                )
                .expect("resume serialized timeout cursor");
            let wrong_account = browser.observe_mailbox_changes_from_token(
                provider,
                &initial_token,
                "synthetic-account-other",
                Duration::from_millis(30),
            );
            let scope = browser
                .event_cursor_scope("synthetic-account-secret")
                .expect("recreate current serialized scope");
            let first = browser
                .decode_event_cursor(&initial_token, &scope)
                .expect("decode first serialized cursor");
            let second = browser
                .decode_event_cursor(resumed.next_cursor(), &scope)
                .expect("decode resumed serialized cursor");
            let logical_state = (
                String::from(
                    first
                        .state_for(&scope)
                        .expect("read first logical cursor state"),
                ),
                String::from(
                    second
                        .state_for(&scope)
                        .expect("read resumed logical cursor state"),
                ),
            );
            (initial, resumed, wrong_account, logical_state)
        },
    );
    assert_eq!(initial.changes().len(), 0);
    assert_eq!(resumed.changes().len(), 0);
    assert_ne!(initial.next_cursor(), resumed.next_cursor());
    assert_eq!(logical_state.0, logical_state.1);
    assert_eq!(logical_state.0, "event-bootstrap");
    assert_eq!(
        wrong_account,
        Err(mail_web_adapter::BrowserDriverError::EventCursorResume(
            EventCursorResumeFailure::InvalidCursor
        ))
    );
    for secret in ["synthetic-account-secret", "event-bootstrap"] {
        assert!(!initial.next_cursor().contains(secret));
        assert!(!resumed.next_cursor().contains(secret));
    }
    let debug = format!("{initial:?} {resumed:?}");
    assert!(!debug.contains("event-bootstrap"));
    assert!(!debug.contains("synthetic-account-secret"));
}

#[test]
fn browser_serialized_change_wait_honors_cancellation() {
    use std::time::Duration;

    let (initial_cancelled, resumed_cancelled) =
        // jig-ignore-next-line: canonical rustfmt line.
        with_event_browser("serialized-cancel", false, false, |browser, provider| {
            // jig-ignore-next-line: canonical rustfmt line.
            let cancellation = mail_web_adapter::MailboxEventCancellation::new();
            cancellation.cancel();
            // jig-ignore-next-line: canonical rustfmt line.
            let initial_cancelled = browser.observe_initial_mailbox_changes_serialized_cancellable(
                provider,
                "account-a",
                Duration::from_secs(1),
                &cancellation,
            );

            let initial = browser
                .observe_initial_mailbox_changes_serialized(
                    provider,
                    "account-a",
                    Duration::from_millis(30),
                )
                .expect("create serialized cursor for resumed cancellation");
            // jig-ignore-next-line: canonical rustfmt line.
            let cancellation = mail_web_adapter::MailboxEventCancellation::new();
            cancellation.cancel();
            // jig-ignore-next-line: canonical rustfmt line.
            let resumed_cancelled = browser.observe_mailbox_changes_from_token_cancellable(
                provider,
                initial.next_cursor(),
                "account-a",
                Duration::from_secs(1),
                &cancellation,
            );
            (initial_cancelled, resumed_cancelled)
        });
    assert_eq!(
        initial_cancelled,
        Err(mail_web_adapter::BrowserDriverError::MailboxEventCancelled)
    );
    assert_eq!(
        resumed_cancelled,
        Err(mail_web_adapter::BrowserDriverError::MailboxEventCancelled)
    );
}

#[test]
fn browser_initial_change_timeout_returns_bootstrap_cursor() {
    use std::time::{Duration, Instant};

    let scope = EventCursorScope::new("account-a", "web", "generation-7")
        .expect("valid initial timeout scope");
    let (result, elapsed, page_after) =
        // jig-ignore-next-line: canonical rustfmt line.
        with_event_browser("initial-timeout", false, false, |browser, provider| {
            let started = Instant::now();
            let result = browser.observe_initial_mailbox_changes(
                provider,
                scope.clone(),
                Duration::from_millis(30),
            );
            (result, started.elapsed(), browser.provider_page())
        });
    let page = result.expect("initial timeout is a successful change page");
    assert_eq!(page.changes().len(), 0);
    assert_eq!(
        page.next_cursor().state_for(&scope).map(String::as_str),
        Ok("event-bootstrap")
    );
    assert!(elapsed < Duration::from_secs(1));
    assert_eq!(
        page_after.expect("browser remains usable").origin(),
        mail_web_adapter::PageOrigin::ProtonMail
    );
}

#[test]
fn browser_initial_change_cancellation_cleans_up() {
    use std::thread;
    use std::time::{Duration, Instant};

    let scope = EventCursorScope::new("account-a", "web", "generation-7")
        .expect("valid initial cancellation scope");
    let (result, elapsed, page_after) =
        with_event_browser("initial-cancel", false, false, |browser, provider| {
            // jig-ignore-next-line: canonical rustfmt line.
            let cancellation = mail_web_adapter::MailboxEventCancellation::new();
            let canceller = cancellation.clone();
            let worker = thread::spawn(move || {
                thread::sleep(Duration::from_millis(50));
                canceller.cancel();
            });
            let started = Instant::now();
            let result = browser.observe_initial_mailbox_changes_cancellable(
                provider,
                scope.clone(),
                Duration::from_secs(1),
                &cancellation,
            );
            let elapsed = started.elapsed();
            worker.join().expect("join initial cancellation worker");
            (result, elapsed, browser.provider_page())
        });
    assert_eq!(
        result,
        Err(mail_web_adapter::BrowserDriverError::MailboxEventCancelled)
    );
    assert!(elapsed < Duration::from_secs(1));
    assert_eq!(
        page_after.expect("browser remains usable").origin(),
        mail_web_adapter::PageOrigin::ProtonMail
    );
}

#[test]
fn browser_reload_passively_captures_latest_event_bootstrap() {
    // jig-ignore-next-line: canonical rustfmt line.
    let (watermark, page_after) = with_event_browser("bootstrap", false, false, |browser, page| {
        let watermark = browser.observe_mailbox_event_bootstrap(page);
        let page_after = browser.provider_page();
        (watermark, page_after)
    });
    let watermark = watermark.expect("capture synthetic bootstrap watermark");
    assert_eq!(watermark.event_id(), "event-bootstrap");
    let debug = format!("{watermark:?}");
    for secret in [
        "event-bootstrap",
        "secret-body",
        "Bearer secret",
        "secret-cookie",
    ] {
        assert!(!debug.contains(secret));
    }
    assert_eq!(
        page_after.expect("browser remains usable").origin(),
        mail_web_adapter::PageOrigin::ProtonMail
    );
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
fn browser_event_wait_cancellation_is_prompt_and_browser_remains_usable() {
    use std::thread;
    use std::time::{Duration, Instant};

    let (result, elapsed, page_after) =
        with_event_browser("cancel", false, false, |browser, page| {
            // jig-ignore-next-line: canonical rustfmt line.
            let cancellation = mail_web_adapter::MailboxEventCancellation::new();
            let canceller = cancellation.clone();
            let worker = thread::spawn(move || {
                thread::sleep(Duration::from_millis(40));
                canceller.cancel();
            });
            let started = Instant::now();
            let result = browser.observe_mailbox_event_sequence_cancellable(
                page,
                Duration::from_secs(1),
                &cancellation,
            );
            let elapsed = started.elapsed();
            worker.join().expect("join synthetic cancellation worker");
            let page_after = browser.provider_page();
            (result, elapsed, page_after)
        });
    assert_eq!(
        result,
        Err(mail_web_adapter::BrowserDriverError::MailboxEventCancelled)
    );
    assert!(elapsed < Duration::from_secs(1));
    assert_eq!(
        page_after.expect("browser remains usable").origin(),
        mail_web_adapter::PageOrigin::ProtonMail
    );
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
        Err(mail_web_adapter::BrowserDriverError::EventCursorResume(
            EventCursorResumeFailure::CursorExpired
        ))
    );
}

#[test]
fn browser_resumed_change_page_advances_or_preserves_cursor() {
    use std::time::Duration;

    let scope = EventCursorScope::new("account-a", "web", "generation-7")
        .expect("valid resumed change scope");
    let cursor = scope.clone().bind(String::from("event-7"));
    // jig-ignore-next-line: canonical rustfmt line.
    let changed = with_event_browser("change-page-resume", false, true, |browser, page| {
        // jig-ignore-next-line: canonical rustfmt line.
        browser.observe_mailbox_changes_from_cursor(page, &cursor, &scope, Duration::from_secs(1))
    })
    .expect("resume change page from matching event cursor");
    assert_eq!(changed.changes().len(), 1);
    assert_eq!(changed.changes()[0].id(), "m-1");
    assert_eq!(
        changed.next_cursor().state_for(&scope).map(String::as_str),
        Ok("event-8")
    );

    // jig-ignore-next-line: canonical rustfmt line.
    let timed_out = with_event_browser("change-page-timeout", false, false, |browser, page| {
        browser.observe_mailbox_changes_from_cursor(
            page,
            &cursor,
            &scope,
            Duration::from_millis(30),
        )
    })
    .expect("resumed timeout is a successful empty page");
    assert_eq!(timed_out.changes().len(), 0);
    assert_eq!(timed_out.next_cursor(), &cursor);
}

#[test]
fn browser_resumed_change_page_cancellation_cleans_up() {
    use std::thread;
    use std::time::{Duration, Instant};

    let scope = EventCursorScope::new("account-a", "web", "generation-7")
        .expect("valid resumed cancellation scope");
    let cursor = scope.clone().bind(String::from("event-7"));
    let (result, elapsed, page_after) =
        with_event_browser("resume-cancel", false, false, |browser, page| {
            // jig-ignore-next-line: canonical rustfmt line.
            let cancellation = mail_web_adapter::MailboxEventCancellation::new();
            let canceller = cancellation.clone();
            let worker = thread::spawn(move || {
                thread::sleep(Duration::from_millis(40));
                canceller.cancel();
            });
            let started = Instant::now();
            // jig-ignore-next-line: canonical rustfmt line.
            let result = browser.observe_mailbox_changes_from_cursor_cancellable(
                page,
                &cursor,
                &scope,
                Duration::from_secs(1),
                &cancellation,
            );
            let elapsed = started.elapsed();
            worker.join().expect("join resumed cancellation worker");
            (result, elapsed, browser.provider_page())
        });
    assert_eq!(
        result,
        Err(mail_web_adapter::BrowserDriverError::MailboxEventCancelled)
    );
    assert!(elapsed < Duration::from_secs(1));
    assert_eq!(
        page_after.expect("browser remains usable").origin(),
        mail_web_adapter::PageOrigin::ProtonMail
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
        Err(mail_web_adapter::BrowserDriverError::EventCursorResume(
            EventCursorResumeFailure::CursorExpired
        ))
    );

    for invalid_scope in [
        EventCursorScope::new("account-b", "web", "generation-7"),
        EventCursorScope::new("account-a", "direct", "generation-7"),
    ] {
        let invalid_scope = invalid_scope.expect("valid mismatched scope");
        // jig-ignore-next-line: canonical rustfmt line.
        let rejected = with_event_browser("scoped-invalid", false, false, |browser, page| {
            browser.observe_mailbox_event_sequence_from_cursor(
                page,
                &cursor,
                &invalid_scope,
                Duration::from_millis(30),
            )
        });
        assert_eq!(
            rejected,
            Err(mail_web_adapter::BrowserDriverError::EventCursorResume(
                EventCursorResumeFailure::InvalidCursor
            ))
        );
    }
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
        Err(mail_web_adapter::BrowserDriverError::EventCursorResume(
            EventCursorResumeFailure::InvalidCursor
        ))
    );
}

// jig-ignore-next-line: canonical rustfmt line.
fn cdp_lifecycle_event(method: &str, request_id: &str, url: &str) -> serde_json::Value {
    use serde_json::json;
    let params = match method {
        "Network.requestWillBeSent" => {
            json!({"requestId":request_id,"request":{"method":"GET","url":url}})
        }
        "Network.responseReceived" => {
            json!({"requestId":request_id,"response":{
                "url":url,"status":200u16,"mimeType":"application/json"
            }})
        }
        _ => json!({"requestId":request_id}),
    };
    json!({"sessionId":"session-1","method":method,"params":params})
}

#[test]
fn latest_event_consumed_ids_reject_all_late_lifecycle_events() {
    use mail_web_adapter::MailboxEventNetworkError;
    let url = "https://mail.proton.me/api/core/v4/events/latest";
    let mut capture = LatestMailboxEventNetworkCapture::new("session-1");
    for method in [
        "Network.requestWillBeSent",
        "Network.responseReceived",
        "Network.loadingFinished",
    ] {
        capture
            .observe(&cdp_lifecycle_event(method, "latest-secret", url))
            .expect("consume complete latest-event GET");
    }
    assert_eq!(capture.take_finished_request_ids(), ["latest-secret"]);
    assert_eq!(capture.take_finished_request_ids().len(), 0);
    for method in [
        "Network.requestWillBeSent",
        "Network.responseReceived",
        "Network.loadingFinished",
        "Network.loadingFailed",
    ] {
        assert_eq!(
            capture.observe(&cdp_lifecycle_event(method, "latest-secret", url)),
            Err(MailboxEventNetworkError::InvalidSequence)
        );
    }
    assert_eq!(
        capture.observe(&serde_json::json!({
            "sessionId":"session-1",
            "method":"Network.responseReceivedExtraInfo",
            "params":{"requestId":"latest-secret","statusCode":200u16}
        })),
        Err(MailboxEventNetworkError::InvalidSequence)
    );
    assert!(!format!("{capture:?}").contains("latest-secret"));
}

#[test]
fn event_poll_consumed_ids_reject_all_late_lifecycle_events() {
    // jig-ignore-next-line: canonical rustfmt line.
    use mail_web_adapter::{MailboxEventNetworkCapture, MailboxEventNetworkError};
    let mut capture = MailboxEventNetworkCapture::new("session-1");
    for method in [
        "Network.requestWillBeSent",
        "Network.responseReceived",
        "Network.loadingFinished",
    ] {
        capture
            .observe(&cdp_lifecycle_event(method, "poll-secret", URL))
            .expect("consume complete v5 event GET");
    }
    assert_eq!(capture.take_finished_request_ids(), ["poll-secret"]);
    assert_eq!(capture.take_finished_request_ids().len(), 0);
    for method in [
        "Network.requestWillBeSent",
        "Network.responseReceived",
        "Network.loadingFinished",
        "Network.loadingFailed",
    ] {
        assert_eq!(
            capture.observe(&cdp_lifecycle_event(method, "poll-secret", URL)),
            Err(MailboxEventNetworkError::InvalidSequence)
        );
    }
    assert_eq!(
        capture.observe(&serde_json::json!({
            "sessionId":"session-1",
            "method":"Network.responseReceivedExtraInfo",
            "params":{"requestId":"poll-secret","statusCode":200u16}
        })),
        Err(MailboxEventNetworkError::InvalidSequence)
    );
    assert!(!format!("{capture:?}").contains("poll-secret"));
}

#[test]
fn latest_and_v5_event_request_ids_are_bounded_after_consumption() {
    // jig-ignore-next-line: canonical rustfmt line.
    use mail_web_adapter::{MailboxEventNetworkCapture, MailboxEventNetworkError};
    let latest_url = "https://mail.proton.me/api/core/v4/events/latest";
    let mut latest = LatestMailboxEventNetworkCapture::new("session-1");
    let mut events = MailboxEventNetworkCapture::new("session-1");
    for index in 0u8..32u8 {
        let id = format!("private-{index}");
        for method in [
            "Network.requestWillBeSent",
            "Network.responseReceived",
            "Network.loadingFinished",
        ] {
            latest
                .observe(&cdp_lifecycle_event(method, &id, latest_url))
                .expect("capture bounded latest event");
            events
                .observe(&cdp_lifecycle_event(method, &id, URL))
                .expect("capture bounded v5 event");
        }
        assert_eq!(latest.take_finished_request_ids(), [id.as_str()]);
        assert_eq!(events.take_finished_request_ids(), [id.as_str()]);
    }
    for (id, expected) in [
        (
            "overflow".to_owned(),
            MailboxEventNetworkError::CapacityExceeded,
        ),
        (String::new(), MailboxEventNetworkError::MalformedEvent),
        ("x".repeat(513), MailboxEventNetworkError::MalformedEvent),
    ] {
        // jig-ignore-next-line: canonical rustfmt line.
        let fresh = cdp_lifecycle_event("Network.requestWillBeSent", &id, latest_url);
        let poll = cdp_lifecycle_event("Network.requestWillBeSent", &id, URL);
        assert_eq!(latest.observe(&fresh), Err(expected));
        assert_eq!(events.observe(&poll), Err(expected));
    }
    assert!(!format!("{latest:?}").contains("private-"));
    assert!(!format!("{events:?}").contains("private-"));
}

#[test]
fn browser_latest_bootstrap_rejects_late_304_and_accepts_late_200() {
    use mail_web_adapter::MailboxEventNetworkError;
    // jig-ignore-next-line: synthetic CDP lifecycle fixture.
    use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};
    use serde_json::json;
    use std::fs;

    let _guard = EVENT_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic latest-event browser fixtures");
    // jig-ignore-next-line: synthetic CDP lifecycle fixture.
    for (status, label) in [(304u16, "latest-late-304"), (200u16, "latest-late-200")] {
        let root = event_browser_root(label);
        fs::create_dir_all(&root).expect("create synthetic browser root");
        let executable = fake_event_browser(&root, false, false);
        // jig-ignore-next-line: synthetic CDP lifecycle fixture.
        let mut script = fs::read_to_string(&executable).expect("read fake browser");
        let nominal = "\"requestId\":\"latest-1\",\"response\":";
        // jig-ignore-next-line: synthetic CDP lifecycle fixture.
        let declared = "\"requestId\":\"latest-1\",\"hasExtraInfo\":true,\"response\":";
        assert!(script.contains(nominal));
        script = script.replacen(nominal, declared, 1);
        // jig-ignore-next-line: synthetic CDP lifecycle fixture.
        let emitted = "printf '%s\\0%s\\0%s\\0' \"$request\" \"$response\" \"$finished\" >&4";
        // jig-ignore-next-line: synthetic CDP lifecycle fixture.
        let response_start = script.find(declared).expect("find latest response");
        let after_response = script
            .get(response_start..)
            .and_then(|rest| rest.find(emitted))
            .expect("find latest completed request stream");
        let insert_at = response_start + after_response + emitted.len();
        let extra = json!({
            "sessionId":"session-1",
            "method":"Network.responseReceivedExtraInfo",
            "params":{"requestId":"latest-1","statusCode":status}
        });
        // jig-ignore-next-line: synthetic CDP lifecycle fixture.
        let injection = format!("\n        extra='{extra}'\n        printf '%s\\0' \"$extra\" >&4");
        script.insert_str(insert_at, &injection);
        let log = root.join("body-read-log.txt");
        // jig-ignore-next-line: synthetic CDP lifecycle fixture.
        let body_marker = "    *'Network.getResponseBody'*'\"requestId\":\"latest-1\"'*)";
        assert!(script.contains(body_marker));
        let audit = format!(
            "{body_marker}\n      printf 'body\\n' >> '{}'",
            log.display()
        );
        script = script.replacen(body_marker, &audit, 1);
        fs::write(&executable, script).expect("write audited browser script");
        let plan = ManagedBrowserPlan::under_data_home(
            executable.to_str().expect("fake browser path UTF-8"),
            &root.join("data"),
        )
        .expect("create synthetic browser plan");
        // jig-ignore-next-line: synthetic CDP lifecycle fixture.
        let mut browser = ManagedBrowser::launch(&plan).expect("launch fake browser");
        let page = browser.provider_page().expect("find Mail page");
        let result = browser.observe_mailbox_event_bootstrap(&page);
        if status == 200 {
            assert_eq!(
                result
                    .expect("late valid status authorizes bootstrap")
                    .event_id(),
                "event-bootstrap"
            );
            // jig-ignore-next-line: synthetic CDP lifecycle fixture.
            assert_eq!(fs::read_to_string(&log).expect("read body audit"), "body\n");
        } else {
            assert_eq!(
                result.map(|_watermark| ()),
                Err(BrowserDriverError::MailboxEventNetwork(
                    MailboxEventNetworkError::ResponseRejected
                ))
            );
            assert!(
                !log.exists(),
                "actual HTTP 304 cannot authorize body access"
            );
        }
        browser
            .require_mail_shell(&page)
            .expect("browser remains usable");
        drop(browser);
        fs::remove_dir_all(root).expect("clean synthetic browser root");
    }
}

#[test]
fn browser_event_poll_waits_for_promised_http_status_before_body_read() {
    use mail_web_adapter::MailboxEventNetworkError;
    // jig-ignore-next-line: synthetic CDP lifecycle fixture.
    use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};
    use serde_json::json;
    use std::fs;
    use std::time::Duration;

    let _guard = EVENT_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic event browser fixtures");
    for (status, label) in [
        (None, "poll-no-status"),
        (Some(200u16), "poll-late-200"),
        (Some(304u16), "poll-late-304"),
    ] {
        let root = event_browser_root(label);
        fs::create_dir_all(&root).expect("create synthetic browser root");
        let executable = fake_event_browser(&root, false, true);
        // jig-ignore-next-line: synthetic CDP lifecycle fixture.
        let mut script = fs::read_to_string(&executable).expect("read fake browser");
        let marker = "\"requestId\":\"event-1\",\"response\":";
        // jig-ignore-next-line: synthetic CDP lifecycle fixture.
        let declared = "\"requestId\":\"event-1\",\"hasExtraInfo\":true,\"response\":";
        assert!(script.contains(marker));
        script = script.replacen(marker, declared, 1);

        // Inject actual status after loadingFinished, rather than before it.
        if let Some(status) = status {
            // jig-ignore-next-line: synthetic CDP lifecycle fixture.
            let emitted = "printf '%s\\0%s\\0%s\\0' \"$request\" \"$response\" \"$finished\" >&4";
            // jig-ignore-next-line: synthetic CDP lifecycle fixture.
            let response_start = script.find(declared).expect("find matching response");
            let after_response = script
                .get(response_start..)
                .and_then(|after| after.find(emitted))
                .expect("find matching completed event stream");
            let insert_at = response_start + after_response + emitted.len();
            let extra = json!({
                "sessionId":"session-1",
                "method":"Network.responseReceivedExtraInfo",
                "params":{"requestId":"event-1","statusCode":status}
            });
            let injection =
                // jig-ignore-next-line: synthetic CDP lifecycle fixture.
                format!("\n          extra='{extra}'\n          printf '%s\\0' \"$extra\" >&4");
            script.insert_str(insert_at, &injection);
        }

        let log = root.join("body-read-log.txt");
        // jig-ignore-next-line: synthetic CDP lifecycle fixture.
        let body_marker = "    *'Network.getResponseBody'*'\"requestId\":\"event-1\"'*)";
        assert!(script.contains(body_marker));
        let audit = format!(
            "{body_marker}\n      printf 'body\\n' >> '{}'",
            log.display()
        );
        script = script.replacen(body_marker, &audit, 1);
        fs::write(&executable, script).expect("write audited browser script");
        let plan = ManagedBrowserPlan::under_data_home(
            executable.to_str().expect("fake browser path UTF-8"),
            &root.join("data"),
        )
        .expect("create synthetic browser plan");
        // jig-ignore-next-line: synthetic CDP lifecycle fixture.
        let mut browser = ManagedBrowser::launch(&plan).expect("launch fake browser");
        let page = browser.provider_page().expect("find Mail page");
        // jig-ignore-next-line: synthetic CDP lifecycle fixture.
        let result = browser.observe_mailbox_event_sequence(&page, Duration::from_millis(250));
        match status {
            Some(200) => {
                assert!(
                    result
                        .expect("late HTTP 200 allows event capture")
                        .is_some()
                );
                // jig-ignore-next-line: synthetic CDP lifecycle fixture.
                assert_eq!(fs::read_to_string(&log).expect("read body audit"), "body\n");
            }
            Some(304) => {
                assert_eq!(
                    result,
                    Err(BrowserDriverError::MailboxEventNetwork(
                        MailboxEventNetworkError::ResponseRejected
                    ))
                );
                // jig-ignore-next-line: synthetic CDP lifecycle fixture.
                assert!(!log.exists(), "HTTP 304 revalidation cannot authorize body");
            }
            unexpected => {
                assert_eq!(unexpected, None, "only synthetic 200/304 statuses");
                assert_eq!(
                    result,
                    Err(BrowserDriverError::MailboxEventResponseAmbiguous)
                );
                // jig-ignore-next-line: synthetic CDP lifecycle fixture.
                assert!(!log.exists(), "missing actual HTTP status blocks body");
            }
        }
        browser
            .require_mail_shell(&page)
            .expect("browser remains usable");
        drop(browser);
        fs::remove_dir_all(root).expect("clean synthetic browser root");
    }
}

#[test]
fn consumed_event_ids_replayed_during_network_disable_fail_closed() {
    use mail_web_adapter::{BrowserDriverError, MailboxEventNetworkError};
    use mail_web_adapter::{ManagedBrowser, ManagedBrowserPlan};
    use serde_json::json;
    use std::fs;
    use std::time::Duration;

    let _guard = EVENT_BROWSER_TEST_LOCK
        .lock()
        .expect("lock event browser fixtures");
    for (name, request_id, event_poll) in [
        ("latest-replay", "latest-1", false),
        ("v5-replay", "event-1", true),
    ] {
        let root = event_browser_root(name);
        fs::create_dir_all(&root).expect("create synthetic event browser root");
        let executable = fake_event_browser(&root, false, event_poll);
        // jig-ignore-next-line: canonical rustfmt line.
        let script = fs::read_to_string(&executable).expect("read fake CDP browser");
        let marker = "    *'Network.disable'*)\n";
        assert!(script.contains(marker));
        let late = json!({
            "sessionId":"session-1","method":"Network.loadingFailed",
            "params":{"requestId":request_id}
        });
        // jig-ignore-next-line: canonical rustfmt line.
        let injected = format!("{marker}      late='{late}'\n      printf '%s\\0' \"$late\" >&4\n");
        fs::write(&executable, script.replacen(marker, &injected, 1))
            .expect("install replayed event request ID");
        let plan = ManagedBrowserPlan::under_data_home(
            executable.to_str().expect("synthetic browser path UTF-8"),
            &root.join("data"),
        )
        .expect("build synthetic event plan");
        // jig-ignore-next-line: canonical rustfmt line.
        let mut browser = ManagedBrowser::launch(&plan).expect("launch fake browser");
        let page = browser.provider_page().expect("find Mail test page");
        let observed = if event_poll {
            browser
                .observe_mailbox_event_sequence(&page, Duration::from_secs(1))
                .map(|_value| ())
        } else {
            browser
                .observe_mailbox_event_bootstrap(&page)
                .map(|_value| ())
        };
        assert_eq!(
            observed,
            Err(BrowserDriverError::MailboxEventNetwork(
                MailboxEventNetworkError::InvalidSequence
            )),
        );
        browser
            .require_mail_shell(&page)
            .expect("same CDP connection remains safe for shell inspection");
        drop(browser);
        fs::remove_dir_all(&root).expect("clean synthetic event browser root");
    }
}

#[test]
fn finished_mailbox_event_requests_cannot_fail_before_consumption() {
    // jig-ignore-next-line: canonical rustfmt line.
    use mail_web_adapter::{MailboxEventNetworkCapture, MailboxEventNetworkError};
    let latest_url = "https://mail.proton.me/api/core/v4/events/latest";
    let mut latest = LatestMailboxEventNetworkCapture::new("session-1");
    let mut events = MailboxEventNetworkCapture::new("session-1");
    for method in [
        "Network.requestWillBeSent",
        "Network.responseReceived",
        "Network.loadingFinished",
    ] {
        latest
            // jig-ignore-next-line: canonical rustfmt line.
            .observe(&cdp_lifecycle_event(method, "finished-latest", latest_url))
            .expect("complete latest lifecycle");
        events
            .observe(&cdp_lifecycle_event(method, "finished-v5", URL))
            .expect("complete v5 lifecycle");
    }
    assert_eq!(
        latest.observe(&cdp_lifecycle_event(
            "Network.loadingFailed",
            "finished-latest",
            latest_url
        )),
        Err(MailboxEventNetworkError::InvalidSequence)
    );
    assert_eq!(
        events.observe(&cdp_lifecycle_event(
            "Network.loadingFailed",
            "finished-v5",
            URL
        )),
        Err(MailboxEventNetworkError::InvalidSequence)
    );
    assert_eq!(latest.take_finished_request_ids(), ["finished-latest"]);
    assert_eq!(events.take_finished_request_ids(), ["finished-v5"]);
}

#[test]
fn control_and_whitespace_event_ids_never_enter_cursor_state() {
    use serde_json::json;
    let bootstrap = "https://mail.proton.me/api/core/v4/events/latest";
    let bad = [
        "encoded%2Fslash",
        "%2e",
        "%2E%2E",
        "direction\u{202e}flip",
        "invisible\u{200b}join",
        "hangul\u{115f}filler",
        "braille\u{2800}blank",
        "variation\u{fe0f}selector",
        "tag\u{e0100}selector",
        "isolated\u{2066}id\u{2069}",
        "event bad",
        "event\tbad",
        "event\nbad",
        "event\rbad",
        "event\u{7f}bad",
        "event\u{85}bad",
        "event\u{a0}bad",
        "event\u{2003}bad",
        ".",
        "..",
    ];
    for value in bad {
        let latest_body = json!({"EventID": value}).to_string();
        assert_eq!(
            // jig-ignore-next-line: canonical rustfmt line.
            ObservedLatestMailboxEventWatermark::parse("GET", bootstrap, &latest_body),
            Err(MailboxEventWatermarkError::Malformed)
        );
        let event_body = json!({"EventID": value, "More": 0u8}).to_string();
        assert_eq!(
            ObservedMailboxEventWatermark::parse("GET", URL, &event_body),
            Err(MailboxEventWatermarkError::Malformed)
        );
        // jig-ignore-next-line: canonical rustfmt line.
        let request_url = format!("https://mail.proton.me/api/core/v5/events/{value}");
        assert_eq!(
            // jig-ignore-next-line: canonical rustfmt line.
            ObservedMailboxEventWatermark::parse("GET", &request_url, &event_body),
            Err(MailboxEventWatermarkError::UnexpectedEndpoint)
        );
    }
    let good = json!({"EventID":"event-7+_~="}).to_string();
    // jig-ignore-next-line: canonical rustfmt line.
    assert!(ObservedLatestMailboxEventWatermark::parse("GET", bootstrap, &good).is_ok());
}

#[test]
fn malformed_mailbox_change_ids_are_not_exposed_from_event_projection() {
    use serde_json::json;
    for bad in [
        "encoded%2Fslash",
        "%2e",
        "%2E%2E",
        "direction\u{202e}flip",
        "invisible\u{200b}join",
        "isolated\u{2066}id\u{2069}",
        "bad id",
        "bad\tid",
        "bad\nid",
        "bad\rid",
        "bad\u{7f}id",
        "bad\u{85}id",
        "bad\u{a0}id",
        "bad\u{2003}id",
        ".",
        "..",
    ] {
        for collection in ["Messages", "Conversations"] {
            let mut body = json!({"EventID":"event-8", "More":0u8});
            body[collection] = json!([{"ID":bad,"Action":1u8}]);
            assert_eq!(
                // jig-ignore-next-line: canonical rustfmt line.
                ObservedMailboxEventWatermark::parse("GET", URL, &body.to_string()),
                Err(MailboxEventWatermarkError::Malformed)
            );
        }
    }
    let valid = json!({
        "EventID":"event-8", "More":0u8,
        "Messages":[{"ID":"synthetic+_~=-id","Action":1u8}]
    });
    // jig-ignore-next-line: canonical rustfmt line.
    let projected = ObservedMailboxEventWatermark::parse("GET", URL, &valid.to_string())
        .expect("retain printable opaque message IDs");
    assert_eq!(projected.changes()[0].id(), "synthetic+_~=-id");
}

#[test]
fn event_url_backslash_cannot_be_promoted_to_cursor_watermark() {
    let url = "https://mail.proton.me/api/core/v5/events/event-7\\neighbor";
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedMailboxEventWatermark::parse("GET", url, r#"{"EventID":"event-8","More":0}"#),
        Err(MailboxEventWatermarkError::UnexpectedEndpoint)
    );
}

#[test]
fn raw_unicode_event_poll_url_cannot_prove_mailbox_watermark() {
    use mail_web_adapter::MailboxEventNetworkCapture;
    use mail_web_adapter::MailboxEventNetworkError;

    let endpoint = "https://mail.proton.me/api/core/v5/events/";
    let method = "Network.requestWillBeSent";
    let body = r#"{"EventID":"event-8","More":0}"#;
    for raw_id in ["event-\u{e9}", "event-\u{1f680}"] {
        let url = format!("{endpoint}{raw_id}?ConversationCounts=1");
        let got = ObservedMailboxEventWatermark::parse("GET", &url, body);
        assert_eq!(got, Err(MailboxEventWatermarkError::UnexpectedEndpoint));
        let mut capture = MailboxEventNetworkCapture::new("session-1");
        let request = cdp_lifecycle_event(method, "unicode", &url);
        assert_eq!(
            capture.observe(&request),
            Err(MailboxEventNetworkError::MalformedEvent)
        );
        assert!(capture.take_finished_request_ids().is_empty());
    }
    let mut capture = MailboxEventNetworkCapture::new("session-1");
    let canonical = cdp_lifecycle_event(method, "ascii", URL);
    capture
        .observe(&canonical)
        .expect("ASCII event poll remains accepted");
}

#[test]
fn bootstrap_and_event_poll_urls_are_bounded_to_16_kib() {
    // jig-ignore-next-line: canonical rustfmt line.
    use mail_web_adapter::{MailboxEventNetworkCapture, MailboxEventNetworkError};
    const CEILING: usize = 16_384;
    let latest_url = "https://mail.proton.me/api/core/v4/events/latest";
    for (url, is_latest) in [(latest_url, true), (URL, false)] {
        let prefix = if is_latest {
            format!("{url}?Synthetic=")
        } else {
            format!("{url}&Synthetic=")
        };
        // The strict selector vocabulary is far smaller than the byte ceiling;
        // keep transport bounds covered with an explicitly unaudited long URL.
        // jig-ignore-next-line: canonical rustfmt line.
        let oversized = format!("{prefix}{}", "x".repeat(CEILING + 1 - prefix.len()));
        assert_eq!(oversized.len(), CEILING + 1);
        if is_latest {
            // jig-ignore-next-line: canonical rustfmt line.
            let mut capture = LatestMailboxEventNetworkCapture::new("session-1");
            capture
                .observe(&cdp_lifecycle_event(
                    "Network.requestWillBeSent",
                    "good",
                    url,
                ))
                .expect("capture canonical bootstrap URL");
            assert_eq!(
                capture.observe(&cdp_lifecycle_event(
                    "Network.responseReceived",
                    "good",
                    &oversized
                )),
                Err(MailboxEventNetworkError::ResponseRejected)
            );
            // jig-ignore-next-line: canonical rustfmt line.
            let mut oversize = LatestMailboxEventNetworkCapture::new("session-1");
            // An unaudited latest-event URL is ignored rather than tracked.
            // Its body cannot become trusted bootstrap evidence.
            assert_eq!(
                oversize.observe(&cdp_lifecycle_event(
                    "Network.requestWillBeSent",
                    "bad",
                    &oversized
                )),
                Ok(())
            );
            assert!(oversize.take_finished_request_ids().is_empty());
            assert_eq!(
                ObservedLatestMailboxEventWatermark::parse(
                    "GET",
                    &oversized,
                    r#"{"EventID":"event-7"}"#
                ),
                Err(MailboxEventWatermarkError::UnexpectedEndpoint)
            );
        } else {
            let mut capture = MailboxEventNetworkCapture::new("session-1");
            capture
                .observe(&cdp_lifecycle_event(
                    "Network.requestWillBeSent",
                    "good",
                    url,
                ))
                .expect("capture canonical v5 event URL");
            assert_eq!(
                capture.observe(&cdp_lifecycle_event(
                    "Network.responseReceived",
                    "good",
                    &oversized
                )),
                Err(MailboxEventNetworkError::ResponseRejected)
            );
            let mut oversize = MailboxEventNetworkCapture::new("session-1");
            assert_eq!(
                oversize.observe(&cdp_lifecycle_event(
                    "Network.requestWillBeSent",
                    "bad",
                    &oversized
                )),
                Err(MailboxEventNetworkError::MalformedEvent)
            );
            assert_eq!(
                ObservedMailboxEventWatermark::parse(
                    "GET",
                    &oversized,
                    r#"{"EventID":"event-7","More":0}"#
                ),
                Err(MailboxEventWatermarkError::UnexpectedEndpoint)
            );
        }
    }
    let unrelated = format!(
        "https://mail.proton.me/api/core/v4/users?{}",
        "x".repeat(20_000)
    );
    let mut latest = LatestMailboxEventNetworkCapture::new("session-1");
    let mut events = MailboxEventNetworkCapture::new("session-1");
    // jig-ignore-next-line: canonical rustfmt line.
    let traffic = cdp_lifecycle_event("Network.requestWillBeSent", "background", &unrelated);
    latest
        .observe(&traffic)
        .expect("ignore unrelated oversize latest traffic");
    events
        .observe(&traffic)
        .expect("ignore unrelated oversize event traffic");
    assert_eq!(latest.take_finished_request_ids().len(), 0);
    assert_eq!(events.take_finished_request_ids().len(), 0);
}

#[test]
fn event_poll_response_must_match_full_private_request_url() {
    // jig-ignore-next-line: canonical rustfmt line.
    use mail_web_adapter::{MailboxEventNetworkCapture, MailboxEventNetworkError};
    let different_counts = URL.replace("MessageCounts=1", "MessageCounts=0");
    let reordered_query = URL.replace(
        "ConversationCounts=1&MessageCounts=1",
        "MessageCounts=1&ConversationCounts=1",
    );
    for drift in [&different_counts, &reordered_query] {
        let mut capture = MailboxEventNetworkCapture::new("session-1");
        capture
            .observe(&cdp_lifecycle_event(
                "Network.requestWillBeSent",
                "event-private",
                URL,
            ))
            .expect("observe original app-owned event GET");
        assert_eq!(
            capture.observe(&cdp_lifecycle_event(
                "Network.responseReceived",
                "event-private",
                drift
            )),
            Err(MailboxEventNetworkError::ResponseRejected)
        );
        let debug = format!("{capture:?}");
        for secret in [
            "event-private",
            "ConversationCounts",
            "MessageCounts",
            "Foreground",
        ] {
            assert!(!debug.contains(secret));
        }
    }
    let mut matched = MailboxEventNetworkCapture::new("session-1");
    matched
        .observe(&cdp_lifecycle_event(
            "Network.requestWillBeSent",
            "matching",
            URL,
        ))
        .expect("observe exact event request");
    matched
        .observe(&cdp_lifecycle_event(
            "Network.responseReceived",
            "matching",
            URL,
        ))
        .expect("accept identical complete response URL");
    matched
        .observe(&cdp_lifecycle_event(
            "Network.loadingFinished",
            "matching",
            URL,
        ))
        .expect("complete exact event read");
    assert_eq!(matched.take_finished_request_ids(), ["matching"]);
}

#[test]
fn latest_bootstrap_response_must_match_full_private_request_url() {
    use mail_web_adapter::MailboxEventNetworkError;
    let endpoint = "https://mail.proton.me/api/core/v4/events/latest";
    let original = format!("{endpoint}?CalledFrom=Foreground&MessageCounts=1");
    for drift in [
        format!("{endpoint}?CalledFrom=Background&MessageCounts=1"),
        format!("{endpoint}?MessageCounts=1&CalledFrom=Foreground"),
        endpoint.to_owned(),
    ] {
        let mut capture = LatestMailboxEventNetworkCapture::new("session-1");
        capture
            .observe(&cdp_lifecycle_event(
                "Network.requestWillBeSent",
                "latest-private",
                &original,
            ))
            .expect("track exact latest GET");
        assert_eq!(
            capture.observe(&cdp_lifecycle_event(
                "Network.responseReceived",
                "latest-private",
                &drift
            )),
            Err(MailboxEventNetworkError::ResponseRejected)
        );
        let debug = format!("{capture:?}");
        for secret in [
            "latest-private",
            "CalledFrom",
            "MessageCounts",
            "Foreground",
        ] {
            assert!(!debug.contains(secret));
        }
    }
    let mut matched = LatestMailboxEventNetworkCapture::new("session-1");
    matched
        .observe(&cdp_lifecycle_event(
            "Network.requestWillBeSent",
            "latest",
            &original,
        ))
        .expect("capture original bootstrap GET");
    matched
        .observe(&cdp_lifecycle_event(
            "Network.responseReceived",
            "latest",
            &original,
        ))
        .expect("accept identical complete bootstrap URL");
    matched
        .observe(&cdp_lifecycle_event(
            "Network.loadingFinished",
            "latest",
            &original,
        ))
        .expect("finish matching bootstrap GET");
    assert_eq!(matched.take_finished_request_ids(), ["latest"]);
}

#[test]
fn browser_event_cache_notices_reject_and_disable_network() {
    use mail_web_adapter::{BrowserDriverError, MailboxEventNetworkError};
    use mail_web_adapter::{ManagedBrowser, ManagedBrowserPlan};
    use std::fs;
    use std::time::Duration;

    let _guard = EVENT_BROWSER_TEST_LOCK
        .lock()
        .expect("lock fake event browsers");
    for (poll, method, suffix, kind) in [
        (false, "Network.requestServedFromCache", "", "latest-cache"),
        (true, "Network.requestServedFromCache", "", "poll-cache"),
        (
            false,
            "Network.responseReceivedExtraInfo",
            ",\"statusCode\":304",
            "latest-304",
        ),
        (
            true,
            "Network.responseReceivedExtraInfo",
            ",\"statusCode\":304",
            "poll-304",
        ),
    ] {
        let root = event_browser_root(kind);
        fs::create_dir_all(&root).expect("create isolated browser root");
        let browser = fake_event_browser(&root, false, poll);
        // jig-ignore-next-line: rustfmt synthetic browser call.
        let script = fs::read_to_string(&browser).expect("read browser fixture");
        let branch = if poll {
            "    *'Network.enable'*)"
        } else {
            "    *'Page.reload'*)"
        };
        let head = script
            .find(branch)
            .expect("locate browser lifecycle branch");
        // jig-ignore-next-line: indivisible synthetic browser CDP fixture.
        let emission = r#"printf '%s\0%s\0%s\0' "$request" "$response" "$finished" >&4"#;
        let emitted = script
            .get(head..)
            .expect("valid shell suffix")
            .find(emission)
            .expect("find exact browser emission")
            + head;
        let id = if poll { "event-1" } else { "latest-1" };
        let notice = format!(
            // jig-ignore-next-line: indivisible synthetic browser CDP fixture.
            r#"{{"sessionId":"session-1","method":"{method}","params":{{"requestId":"{id}"{suffix}}}}}"#
        );
        let replacement = format!(
            // jig-ignore-next-line: indivisible synthetic browser CDP fixture.
            "status='{notice}'\n          printf '%s\\0%s\\0%s\\0%s\\0' \"$request\" \"$response\" \"$status\" \"$finished\" >&4"
        );
        let mut injected = script
            .get(..emitted)
            .expect("valid shell prefix")
            .to_owned();
        injected.push_str(&replacement);
        injected.push_str(
            script
                .get(emitted + emission.len()..)
                .expect("valid suffix"),
        );
        let disable = "    *'Network.disable'*)";
        assert!(injected.contains(disable));
        let audit = format!(
            "{disable}\n      printf 'disabled\\n' >> '{}'",
            root.join("network-disabled.log").display()
        );
        fs::write(&browser, injected.replacen(disable, &audit, 1))
            .expect("install cached synthetic event and Network audit");
        let plan = ManagedBrowserPlan::under_data_home(
            browser.to_str().expect("browser executable path UTF-8"),
            &root.join("data"),
        )
        .expect("isolated Mail profile");
        // jig-ignore-next-line: rustfmt synthetic browser call.
        let mut managed = ManagedBrowser::launch(&plan).expect("launch fake browser");
        let page = managed.provider_page().expect("discover Mail page");
        let observed = if poll {
            managed
                .observe_mailbox_event_sequence(&page, Duration::from_secs(1))
                .map(|_value| ())
        } else {
            managed
                .observe_mailbox_event_bootstrap(&page)
                .map(|_value| ())
        };
        assert_eq!(
            observed,
            Err(BrowserDriverError::MailboxEventNetwork(
                MailboxEventNetworkError::ResponseRejected
            ))
        );
        managed
            .require_mail_shell(&page)
            .expect("session remains usable");
        drop(managed);
        let audit = fs::read_to_string(root.join("network-disabled.log"))
            .expect("Network.disable must run on refusal");
        assert_eq!(audit, "disabled\n");
        fs::remove_dir_all(&root).expect("clean isolated browser fixture");
    }
}

#[test]
fn event_url_query_drift_during_browser_capture_stays_fail_closed() {
    use mail_web_adapter::{BrowserDriverError, MailboxEventNetworkError};
    use mail_web_adapter::{ManagedBrowser, ManagedBrowserPlan};
    use std::fs;
    use std::time::Duration;

    let _guard = EVENT_BROWSER_TEST_LOCK
        .lock()
        .expect("lock fake event browsers");
    for (label, poll, old_query, new_query) in [
        (
            "bootstrap-query-drift",
            false,
            "events/latest",
            "events/latest?Unexpected=1",
        ),
        ("v5-query-drift", true, "MessageCounts=1", "MessageCounts=0"),
    ] {
        let root = event_browser_root(label);
        fs::create_dir_all(&root).expect("create synthetic event browser root");
        let browser = fake_event_browser(&root, false, poll);
        // jig-ignore-next-line: canonical rustfmt line.
        let script = fs::read_to_string(&browser).expect("read synthetic script");
        let branch = if poll {
            "    *'Network.enable'*)"
        } else {
            "    *'Page.reload'*)"
        };
        let head = script
            .find(branch)
            .expect("find synthetic lifecycle branch");
        // jig-ignore-next-line: canonical rustfmt line.
        let emission = r#"printf '%s\0%s\0%s\0' "$request" "$response" "$finished" >&4"#;
        let emitted = script
            .get(head..)
            .expect("UTF-8 branch boundary")
            .find(emission)
            .expect("find CDP lifecycle emission")
            + head;
        let altered = format!(
            // jig-ignore-next-line: canonical rustfmt line.
            "response=$(printf '%s' \"$response\" | sed 's|{old_query}|{new_query}|')\n      "
        );
        // jig-ignore-next-line: canonical rustfmt line.
        let mut injected = String::from(script.get(..emitted).expect("UTF-8 emission prefix"));
        injected.push_str(&altered);
        // jig-ignore-next-line: canonical rustfmt line.
        injected.push_str(script.get(emitted..).expect("UTF-8 emission suffix"));
        let disable = "    *'Network.disable'*)";
        assert!(injected.contains(disable));
        let record = format!(
            "{disable}\n      printf 'disabled\\n' >> '{}'",
            root.join("network-disabled.log").display()
        );
        fs::write(&browser, injected.replacen(disable, &record, 1))
            .expect("inject response-only query drift and teardown audit");
        let plan = ManagedBrowserPlan::under_data_home(
            browser.to_str().expect("synthetic browser UTF-8 path"),
            &root.join("data"),
        )
        .expect("construct synthetic browser plan");
        // jig-ignore-next-line: canonical rustfmt line.
        let mut managed = ManagedBrowser::launch(&plan).expect("launch fake browser");
        let page = managed.provider_page().expect("discover fake Mail page");
        let observed = if poll {
            managed
                .observe_mailbox_event_sequence(&page, Duration::from_secs(1))
                .map(|_value| ())
        } else {
            managed
                .observe_mailbox_event_bootstrap(&page)
                .map(|_value| ())
        };
        assert_eq!(
            observed,
            Err(BrowserDriverError::MailboxEventNetwork(
                MailboxEventNetworkError::ResponseRejected
            ))
        );
        managed
            .require_mail_shell(&page)
            // jig-ignore-next-line: canonical rustfmt line.
            .expect("same CDP session works after rejecting response URL drift");
        drop(managed);
        let disable_log = fs::read_to_string(root.join("network-disabled.log"))
            .expect("Network.disable must run after mismatched response");
        assert_eq!(disable_log, "disabled\n");
        fs::remove_dir_all(&root).expect("clean fake event browser root");
    }
}

#[test]
fn event_capture_equality_ignores_randomized_url_hashing_keys() {
    use mail_web_adapter::MailboxEventNetworkCapture;
    let latest_url = "https://mail.proton.me/api/core/v4/events/latest";
    let first_latest = LatestMailboxEventNetworkCapture::new("session-1");
    let second_latest = LatestMailboxEventNetworkCapture::new("session-1");
    assert_eq!(first_latest, second_latest);
    let first_event = MailboxEventNetworkCapture::new("session-1");
    let second_event = MailboxEventNetworkCapture::new("session-1");
    assert_eq!(first_event, second_event);
    let mut first_latest = first_latest;
    let mut second_latest = second_latest;
    // jig-ignore-next-line: canonical rustfmt line.
    let latest_request = cdp_lifecycle_event("Network.requestWillBeSent", "bootstrap", latest_url);
    first_latest
        .observe(&latest_request)
        .expect("first independent latest capture");
    second_latest
        .observe(&latest_request)
        .expect("second independent latest capture");
    assert_eq!(first_latest, second_latest);
    let mut first_event = first_event;
    let mut second_event = second_event;
    // jig-ignore-next-line: canonical rustfmt line.
    let event_request = cdp_lifecycle_event("Network.requestWillBeSent", "event", URL);
    first_event
        .observe(&event_request)
        .expect("first independent event capture");
    second_event
        .observe(&event_request)
        .expect("second independent event capture");
    assert_eq!(first_event, second_event);
}

#[test]
fn explicit_provider_failure_cannot_become_bootstrap_or_poll_cursor() {
    use serde_json::json;
    let latest_url = "https://mail.proton.me/api/core/v4/events/latest";
    for rejected in [
        json!(0u64),
        json!(2001u64),
        json!("1000"),
        json!(-1i32),
        json!(null),
    ] {
        let latest = json!({"Code":rejected,"EventID":"event-7"}).to_string();
        assert_eq!(
            // jig-ignore-next-line: canonical rustfmt line.
            ObservedLatestMailboxEventWatermark::parse("GET", latest_url, &latest),
            Err(MailboxEventWatermarkError::ProviderRejected)
        );
        // jig-ignore-next-line: canonical rustfmt line.
        let poll = json!({"Code":rejected,"EventID":"event-8","More":0u8}).to_string();
        assert_eq!(
            ObservedMailboxEventWatermark::parse("GET", URL, &poll),
            Err(MailboxEventWatermarkError::ProviderRejected)
        );
    }
    for success in [None, Some(json!(1000u64))] {
        let mut latest = json!({"EventID":"event-7"});
        let mut poll = json!({"EventID":"event-8","More":0u8});
        if let Some(code) = success {
            latest["Code"] = code.clone();
            poll["Code"] = code;
        }
        assert!(
            // jig-ignore-next-line: canonical rustfmt line.
            ObservedLatestMailboxEventWatermark::parse("GET", latest_url, &latest.to_string())
                .is_ok()
        );
        // jig-ignore-next-line: canonical rustfmt line.
        assert!(ObservedMailboxEventWatermark::parse("GET", URL, &poll.to_string()).is_ok());
    }
}

#[test]
fn provider_rejected_event_body_never_yields_resumable_browser_cursor() {
    // jig-ignore-next-line: canonical rustfmt line.
    use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};
    use std::fs;
    use std::time::Duration;

    let _guard = EVENT_BROWSER_TEST_LOCK
        .lock()
        .expect("lock event fake browsers");
    for (label, poll, id) in [
        ("bootstrap-provider-error", false, "event-bootstrap"),
        ("v5-provider-error", true, "event-8"),
    ] {
        let root = event_browser_root(label);
        fs::create_dir_all(&root).expect("create isolated event profile");
        let browser = fake_event_browser(&root, false, poll);
        // jig-ignore-next-line: canonical rustfmt line.
        let script = fs::read_to_string(&browser).expect("read synthetic CDP fixture");
        let original = format!(r#"\"EventID\":\"{id}\""#);
        let rejected = format!(r#"\"Code\":2001,\"EventID\":\"{id}\""#);
        assert!(script.contains(&original));
        let changed = script.replace(&original, &rejected);
        let disable = "    *'Network.disable'*)";
        assert!(changed.contains(disable));
        let audit = format!(
            "{disable}\n      printf 'disabled\\n' >> '{}'",
            root.join("network-disabled.log").display()
        );
        fs::write(&browser, changed.replacen(disable, &audit, 1))
            .expect("install explicit provider rejection and Network audit");
        let plan = ManagedBrowserPlan::under_data_home(
            browser.to_str().expect("synthetic executable UTF-8"),
            &root.join("data"),
        )
        .expect("construct isolated profile plan");
        // jig-ignore-next-line: canonical rustfmt line.
        let mut managed = ManagedBrowser::launch(&plan).expect("launch fake Mail browser");
        let page = managed.provider_page().expect("discover Mail page");
        let result = if poll {
            managed
                .observe_mailbox_event_sequence(&page, Duration::from_secs(1))
                .map(|_page| ())
        } else {
            managed
                .observe_mailbox_event_bootstrap(&page)
                .map(|_event| ())
        };
        assert_eq!(
            result,
            Err(BrowserDriverError::MailboxEventWatermark(
                MailboxEventWatermarkError::ProviderRejected
            )),
            "case {label} must not produce a successful cursor"
        );
        managed
            .require_mail_shell(&page)
            .expect("same session remains safe to inspect after rejected body");
        drop(managed);
        let log = fs::read_to_string(root.join("network-disabled.log"))
            .expect("synthetic Network.disable audit");
        assert_eq!(log, "disabled\n");
        fs::remove_dir_all(&root).expect("remove isolated synthetic profile");
    }
}

#[test]
fn malformed_unsolicited_event_during_passive_wait_fails_closed() {
    // jig-ignore-next-line: canonical rustfmt line.
    use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};
    use std::fs;
    use std::time::Duration;

    let _guard = EVENT_BROWSER_TEST_LOCK
        .lock()
        .expect("lock event fake browsers");
    for (index, notification) in [
        r#"{"method":"Network.loadingFinished","params":null}"#,
        r#"{"method":"Network.loadingFinished","params":[]}"#,
        r#"{"method":"","params":{}}"#,
        r#"{"method":"Network.loadingFinished","sessionId":false}"#,
        r#"{"result":{}}"#,
    ]
    .into_iter()
    .enumerate()
    {
        let root = event_browser_root(&format!("malformed-passive-{index}"));
        fs::create_dir_all(&root).expect("create isolated fake event profile");
        let browser = fake_event_browser(&root, false, true);
        // jig-ignore-next-line: canonical rustfmt line.
        let script = fs::read_to_string(&browser).expect("read synthetic CDP fixture");
        let enable_branch = "    *'Network.enable'*)";
        // jig-ignore-next-line: canonical rustfmt line.
        let branch_start = script.find(enable_branch).expect("find event subscription");
        let (prefix, branch) = script.split_at(branch_start);
        let delayed = "          sleep 0.02\n";
        assert!(branch.contains(delayed));
        // jig-ignore-next-line: canonical rustfmt line.
        let injection = format!("{delayed}          printf '%s\\0' '{notification}' >&4\n");
        // jig-ignore-next-line: canonical rustfmt line.
        let changed = format!("{prefix}{}", branch.replacen(delayed, &injection, 1));
        let disable = "    *'Network.disable'*)";
        let audited = format!(
            "{disable}\n      printf 'disabled\\n' >> '{}'",
            root.join("disabled.log").display()
        );
        fs::write(&browser, changed.replacen(disable, &audited, 1))
            .expect("inject delayed malformed event and teardown audit");
        let plan = ManagedBrowserPlan::under_data_home(
            browser.to_str().expect("synthetic executable UTF-8"),
            &root.join("data"),
        )
        .expect("build isolated fake browser plan");
        // jig-ignore-next-line: canonical rustfmt line.
        let mut managed = ManagedBrowser::launch(&plan).expect("launch fake browser");
        let page = managed.provider_page().expect("discover fake Mail page");
        assert_eq!(
            managed
                .observe_mailbox_event_sequence(&page, Duration::from_secs(1))
                .map(|_page| ()),
            Err(BrowserDriverError::Protocol),
            "case {index} cannot be ignored during passive event wait"
        );
        managed
            .require_mail_shell(&page)
            .expect("Network cleanup keeps same-session shell inspectable");
        drop(managed);
        assert_eq!(
            // jig-ignore-next-line: canonical rustfmt line.
            fs::read_to_string(root.join("disabled.log")).expect("read Network.disable audit"),
            "disabled\n"
        );
        fs::remove_dir_all(&root).expect("delete isolated test-only profile");
    }
}

#[test]
fn oversized_event_continuation_is_atomic_and_retryable() {
    use mail_web_adapter::ObservedMailboxEventSequence;
    use serde_json::json;

    // jig-ignore-next-line: canonical rustfmt line.
    fn page(from: usize, start: usize, count: usize, more: bool) -> ObservedMailboxEventWatermark {
        // jig-ignore-next-line: canonical rustfmt line.
        let url = format!("https://mail.proton.me/api/core/v5/events/event-{from}");
        let messages = (start..start + count)
            .map(|index| json!({"ID":format!("m-{index}"),"Action":1u8}))
            .collect::<Vec<_>>();
        let body = json!({
            "EventID": format!("event-{}", from + 1),
            "More": u8::from(more),
            "Messages": messages,
        });
        ObservedMailboxEventWatermark::parse("GET", &url, &body.to_string())
            .expect("valid synthetic event page")
    }

    // jig-ignore-next-line: canonical rustfmt line.
    let mut sequence = ObservedMailboxEventSequence::start(page(0, 0, 511, true))
        .expect("start near-capacity sequence");
    for index in 1..8 {
        sequence
            .push(page(index, 511 + (index - 1) * 512, 512, true))
            .expect("append within capacity");
    }
    assert_eq!(sequence.changes().len(), 4095);
    let before = sequence.clone();
    assert_eq!(
        sequence.push(page(8, 4095, 2, false)),
        Err(MailboxEventSequenceError::TooManyChanges)
    );
    assert_eq!(sequence, before, "failure must not consume partial changes");
    sequence
        .push(page(8, 4095, 1, false))
        .expect("a valid continuation can still settle");
    assert!(sequence.settled());
    assert_eq!(sequence.changes().len(), 4096);
}

#[test]
fn event_sequence_rejects_revisited_watermarks_without_losing_progress() {
    use mail_web_adapter::ObservedMailboxEventSequence;

    fn page(from: &str, to: &str, more: u8) -> ObservedMailboxEventWatermark {
        let url = format!("https://mail.proton.me/api/core/v5/events/{from}");
        let body = format!(r#"{{"EventID":"{to}","More":{more}}}"#);
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedMailboxEventWatermark::parse("GET", &url, &body).expect("parse synthetic watermark")
    }

    let mut sequence =
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedMailboxEventSequence::start(page("ev-0", "ev-1", 1)).expect("start event sequence");
    sequence.push(page("ev-1", "ev-2", 1)).expect("advance");
    let before = sequence.clone();
    for more in [0u8, 1u8] {
        assert_eq!(
            sequence.push(page("ev-2", "ev-0", more)),
            Err(MailboxEventSequenceError::RepeatedWatermark)
        );
        assert_eq!(sequence, before, "a rejected cursor preserves state");
    }
    sequence
        .push(page("ev-2", "ev-2", 0))
        .expect("settled no-change response can keep its request watermark");
    assert!(sequence.settled());
}

#[test]
fn mailbox_event_count_collections_are_all_validated_after_first_change() {
    let body = r#"{
        "EventID":"event-9","More":0,
        "MessageCounts":[{"LabelID":"inbox","Total":1}],
        "ConversationCounts":{"unexpected":"object"}
    }"#;
    assert_eq!(
        ObservedMailboxEventWatermark::parse("GET", URL, body),
        Err(MailboxEventWatermarkError::Malformed)
    );
}

#[test]
fn unchanged_settled_event_cannot_report_new_messages() {
    use mail_web_adapter::ObservedMailboxEventSequence;

    let changed = ObservedMailboxEventWatermark::parse(
        "GET",
        "https://mail.proton.me/api/core/v5/events/ev-1",
        r#"{"EventID":"ev-1","More":0,"Messages":[{"ID":"new-1","Action":1}]}"#,
    )
    .expect("parse inconsistent provider page");
    assert_eq!(
        ObservedMailboxEventSequence::start(changed.clone()),
        Err(MailboxEventSequenceError::NonAdvancingContinuation)
    );
    let first = ObservedMailboxEventWatermark::parse(
        "GET",
        "https://mail.proton.me/api/core/v5/events/ev-0",
        r#"{"EventID":"ev-1","More":1}"#,
    )
    .expect("parse initial page");
    let mut sequence =
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedMailboxEventSequence::start(first).expect("start cursor sequence");
    let before = sequence.clone();
    assert_eq!(
        sequence.push(changed),
        Err(MailboxEventSequenceError::NonAdvancingContinuation)
    );
    assert_eq!(sequence, before);
}

#[test]
fn unchanged_settled_event_with_count_changes_is_not_an_acknowledgment() {
    use mail_web_adapter::ObservedMailboxEventSequence;

    let changed = ObservedMailboxEventWatermark::parse(
        "GET",
        "https://mail.proton.me/api/core/v5/events/ev-1",
        r#"{"EventID":"ev-1","More":0,"MessageCounts":[{"LabelID":"inbox"}]}"#,
    )
    .expect("parse count-only change");
    assert!(changed.mailbox_changes());
    assert_eq!(
        ObservedMailboxEventSequence::start(changed),
        Err(MailboxEventSequenceError::NonAdvancingContinuation)
    );
}

#[test]
fn malformed_event_count_items_cannot_be_treated_as_changes() {
    for key in ["MessageCounts", "ConversationCounts"] {
        for bad_item in ["null", "true", "7", "\"unexpected\"", "[]"] {
            // jig-ignore-next-line: canonical rustfmt line.
            let body = format!(r#"{{"EventID":"ev-2","More":0,"{key}":[{bad_item}]}}"#);
            assert_eq!(
                ObservedMailboxEventWatermark::parse(
                    "GET",
                    "https://mail.proton.me/api/core/v5/events/ev-1",
                    &body
                ),
                Err(MailboxEventWatermarkError::Malformed),
                "a count-change collection requires object entries"
            );
        }
    }
}

#[test]
fn unknown_refresh_bits_cannot_preserve_mailbox_cursor_authority() {
    use mail_web_adapter::ObservedMailboxEventSequence;

    for refresh in [4u64, 8, 1u64 << 40u32] {
        // jig-ignore-next-line: indivisible synthetic JSON event fixture.
        let body = format!(r#"{{"EventID":"event-8","More":0,"Refresh":{refresh}}}"#);
        let page = ObservedMailboxEventWatermark::parse("GET", URL, &body)
            .expect("accept well-typed refresh bitmask");
        assert_eq!(
            ObservedMailboxEventSequence::start(page),
            Err(MailboxEventSequenceError::RefreshRequired),
            "unknown refresh bits cannot retain a stale Mail cursor"
        );
    }
}

#[test]
fn unknown_refresh_bit_during_continuation_preserves_prior_cursor() {
    use mail_web_adapter::ObservedMailboxEventSequence;

    let first =
        // jig-ignore-next-line: indivisible synthetic JSON event fixture.
        ObservedMailboxEventWatermark::parse("GET", URL, r#"{"EventID":"event-8","More":1}"#)
            .expect("parse initial non-final event page");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut chain = ObservedMailboxEventSequence::start(first).expect("start valid event sequence");
    let unchanged = chain.clone();
    let next_url = URL.replace("event-7", "event-8");
    let next = ObservedMailboxEventWatermark::parse(
        "GET",
        &next_url,
        r#"{"EventID":"event-9","More":0,"Refresh":4}"#,
    )
    .expect("parse unknown typed refresh flag");
    assert_eq!(
        chain.push(next),
        Err(MailboxEventSequenceError::RefreshRequired)
    );
    assert_eq!(chain, unchanged);
    assert!(!chain.settled());
    assert_eq!(chain.next_event_id(), "event-8");
}

#[test]
fn cdp_event_envelopes_refuse_unexpected_fields() {
    use serde_json::json;
    let mut latest = json!({
        "body":"{\"EventID\":\"event-bootstrap\"}","base64Encoded":false
    });
    let first = ObservedLatestMailboxEventWatermark::parse_cdp_body(&latest);
    assert!(first.is_ok());
    latest["unexpected"] = json!("synthetic-untrusted-field");
    assert_eq!(
        ObservedLatestMailboxEventWatermark::parse_cdp_body(&latest),
        Err(MailboxEventWatermarkError::Malformed)
    );
    let mut event = json!({
        "body":"{\"EventID\":\"event-7\",\"More\":0}","base64Encoded":false
    });
    let requested = "event-7";
    // jig-ignore-next-line: canonical rustfmt event parser call.
    let first = ObservedMailboxEventWatermark::parse_cdp_body(requested, &event);
    assert!(first.is_ok());
    event["unexpected"] = json!("synthetic-untrusted-field");
    assert_eq!(
        ObservedMailboxEventWatermark::parse_cdp_body("event-7", &event),
        Err(MailboxEventWatermarkError::Malformed)
    );
}

#[test]
fn event_count_query_flags_cannot_silently_disable_mailbox_signals() {
    let body = r#"{"EventID":"event-7","More":0}"#;
    let endpoint = "https://mail.proton.me/api/core/v5/events/event-7";
    for query in [
        "MessageCounts=0",
        "ConversationCounts=0",
        "MessageCounts=1&MessageCounts=0",
        "MessageCounts=1&ConversationCounts=0",
        "%4DessageCounts=1",
        "messagecounts=1",
    ] {
        let url = format!("{endpoint}?{query}");
        assert_eq!(
            ObservedMailboxEventWatermark::parse("GET", &url, body),
            Err(MailboxEventWatermarkError::UnexpectedEndpoint)
        );
    }
    let latest = "https://mail.proton.me/api/core/v4/events/latest";
    let body = r#"{"EventID":"event-bootstrap"}"#;
    let bad = format!("{latest}?MessageCounts=0");
    assert_eq!(
        ObservedLatestMailboxEventWatermark::parse("GET", &bad, body),
        Err(MailboxEventWatermarkError::UnexpectedEndpoint)
    );
}

#[test]
fn event_queries_require_only_exact_audited_selector_vocabulary() {
    // A future provider query key can alter the scope of the returned event
    // batch. Neither latest bootstrap nor v5 polling may assume its meaning.
    let poll = "https://mail.proton.me/api/core/v5/events/event-7";
    let latest = "https://mail.proton.me/api/core/v4/events/latest";
    let poll_body = r#"{"EventID":"event-8","More":0}"#;
    let latest_body = r#"{"EventID":"event-bootstrap"}"#;
    for query in [
        "Unexpected=1",
        "MessageCounts=1&Foo=bar",
        "MessageCounts=1&CalledFrom=Foreground&FutureMode=thread",
        "CalledFrom=Foreground&CalledFrom=Background",
        "calledfrom=Foreground",
        "%43alledFrom=Foreground",
        "CalledFrom=foreground",
        "CalledFrom=Unknown",
        "CalledFrom=Foreground=extra",
        "CalledFrom=Foreground&",
        "MessageCounts=1&&ConversationCounts=1",
    ] {
        let poll_url = format!("{poll}?{query}");
        assert_eq!(
            ObservedMailboxEventWatermark::parse("GET", &poll_url, poll_body),
            Err(MailboxEventWatermarkError::UnexpectedEndpoint),
            "unsafe poll query: {query}"
        );
        let latest_url = format!("{latest}?{query}");
        assert_eq!(
            // jig-ignore-next-line: canonical rustfmt bootstrap parse call.
            ObservedLatestMailboxEventWatermark::parse("GET", &latest_url, latest_body),
            Err(MailboxEventWatermarkError::UnexpectedEndpoint),
            "unsafe bootstrap query: {query}"
        );
    }
}

#[test]
fn canonical_event_count_queries_remain_observable() {
    let endpoint = "https://mail.proton.me/api/core/v5/events/event-7";
    let body = r#"{"EventID":"event-8","More":0}"#;
    for query in [
        "MessageCounts=1",
        "ConversationCounts=1&MessageCounts=1",
        "CalledFrom=Foreground&MessageCounts=1",
        "MessageCounts=1&ConversationCounts=1&CalledFrom=Foreground",
    ] {
        let url = format!("{endpoint}?{query}");
        let parsed = ObservedMailboxEventWatermark::parse("GET", &url, body);
        assert!(parsed.is_ok());
    }
    let latest = "https://mail.proton.me/api/core/v4/events/latest";
    let latest_body = r#"{"EventID":"event-bootstrap"}"#;
    let url = format!("{latest}?CalledFrom=Foreground&MessageCounts=1");
    let parse_latest = ObservedLatestMailboxEventWatermark::parse;
    let parsed = parse_latest("GET", &url, latest_body);
    assert!(parsed.is_ok());
}

#[test]
fn disabled_count_flags_fail_before_network_capture() {
    use mail_web_adapter::MailboxEventNetworkCapture;
    use mail_web_adapter::MailboxEventNetworkError;
    let endpoint = "https://mail.proton.me/api/core/v5/events/event-7";
    for query in ["MessageCounts=0", "ConversationCounts=0"] {
        let url = format!("{endpoint}?{query}");
        let mut capture = MailboxEventNetworkCapture::new("session-1");
        let method = "Network.requestWillBeSent";
        let event = cdp_lifecycle_event(method, "poll", &url);
        assert_eq!(
            capture.observe(&event),
            Err(MailboxEventNetworkError::MalformedEvent)
        );
        let finished = capture.take_finished_request_ids();
        assert_eq!(finished, Vec::<String>::new());
    }
}

#[test]
fn redirected_into_event_gets_is_not_fresh_evidence() {
    use mail_web_adapter::MailboxEventNetworkCapture;
    use mail_web_adapter::MailboxEventNetworkError;
    use serde_json::json;

    let id = "redirected";
    let method = "Network.requestWillBeSent";
    let source = "https://mail.proton.me/other-resource";
    let latest_url = "https://mail.proton.me/api/core/v4/events/latest";
    let mut latest = LatestMailboxEventNetworkCapture::new("session-1");
    let mut poll = MailboxEventNetworkCapture::new("session-1");
    let mut latest_event = cdp_lifecycle_event(method, id, latest_url);
    latest_event["params"]["redirectResponse"] = json!({"url":source});
    let mut poll_event = cdp_lifecycle_event(method, id, URL);
    poll_event["params"]["redirectResponse"] = json!({"url":source});
    assert_eq!(
        latest.observe(&latest_event),
        Err(MailboxEventNetworkError::RedirectedAway)
    );
    assert_eq!(
        poll.observe(&poll_event),
        Err(MailboxEventNetworkError::RedirectedAway)
    );
    assert!(latest.take_finished_request_ids().is_empty());
    assert!(poll.take_finished_request_ids().is_empty());
}

#[test]
fn event_gets_with_body_metadata_cannot_establish_mailbox_watermarks() {
    use mail_web_adapter::MailboxEventNetworkCapture;
    use mail_web_adapter::MailboxEventNetworkError;
    use serde_json::json;
    let request_method = "Network.requestWillBeSent";
    let latest = "https://mail.proton.me/api/core/v4/events/latest";
    for (field, value) in [
        ("hasPostData", json!(true)),
        ("postData", json!("synthetic-event-body")),
        ("postDataEntries", json!([{"bytes":"c3ludGhldGlj"}])),
    ] {
        let mut bootstrap = LatestMailboxEventNetworkCapture::new("session-1");
        // jig-ignore-next-line: canonical rustfmt preserves this fixture call.
        let mut boot_event = cdp_lifecycle_event(request_method, "latest", latest);
        boot_event["params"]["request"][field] = value.clone();
        assert_eq!(
            bootstrap.observe(&boot_event),
            Err(MailboxEventNetworkError::MalformedEvent),
            "body-bearing latest GET {field}"
        );
        let mut poll = MailboxEventNetworkCapture::new("session-1");
        let mut poll_event = cdp_lifecycle_event(request_method, "poll", URL);
        poll_event["params"]["request"][field] = value;
        assert_eq!(
            poll.observe(&poll_event),
            Err(MailboxEventNetworkError::MalformedEvent),
            "body-bearing poll GET {field}"
        );
    }
}

#[test]
fn speculative_event_get_cannot_prove_mailbox_poll() {
    use mail_web_adapter::MailboxEventNetworkCapture;
    use mail_web_adapter::MailboxEventNetworkError;
    use serde_json::json;

    let request_method = "Network.requestWillBeSent";
    for (field, value) in [
        ("isLinkPreload", json!(true)),
        ("resourceType", json!("Prefetch")),
        ("initiator", json!({"type":"preload"})),
    ] {
        let mut poll = MailboxEventNetworkCapture::new("session-1");
        let mut event = cdp_lifecycle_event(request_method, "poll", URL);
        if field == "isLinkPreload" {
            event["params"]["request"][field] = value;
        } else if field == "resourceType" {
            event["params"]["type"] = value;
        } else {
            event["params"][field] = value;
        }
        assert_eq!(
            poll.observe(&event),
            Err(MailboxEventNetworkError::MalformedEvent),
            "speculative core-event GET {field} is not a direct app poll"
        );
    }
}
