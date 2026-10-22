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
use mail_web_adapter::ConversationListReconciliationError;
use mail_web_adapter::ConversationListResponseError;
use mail_web_adapter::ObservedConversationListResponse;
use mail_web_adapter::ReconciledVisibleConversationMetadata;
use serde_json::{Value, json};
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Mutex;
use std::time::Duration;

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

#[test]
fn network_capture_rejects_redirects_and_repeated_lifecycle_events() {
    let mut redirected = ConversationListNetworkCapture::new("session-a");
    redirected
        .observe(&request_event("session-a", "list", "GET", URL))
        .expect("capture initial exact request");
    assert_eq!(
        redirected.observe(&request_event(
            "session-a",
            "list",
            "GET",
            "https://mail.proton.me/api/mail/v4/conversations/count",
        )),
        Err(ConversationListNetworkError::RedirectedAway)
    );
    let mut repeated = ConversationListNetworkCapture::new("session-a");
    repeated
        .observe(&request_event("session-a", "list", "GET", URL))
        .expect("capture request");
    assert_eq!(
        repeated.observe(&finished_event("session-a", "list")),
        Err(ConversationListNetworkError::InvalidSequence)
    );
    repeated
        .observe(&response_event(
            "session-a",
            "list",
            URL,
            200,
            "application/json",
        ))
        .expect("capture response");
    assert_eq!(
        repeated.observe(&response_event(
            "session-a",
            "list",
            URL,
            200,
            "application/json"
        )),
        Err(ConversationListNetworkError::InvalidSequence)
    );
}

#[test]
fn network_capture_never_promotes_other_sessions_or_write_requests() {
    let mut capture = ConversationListNetworkCapture::new("session-a");
    capture
        .observe(&request_event("other-session", "foreign", "GET", URL))
        .expect("ignore foreign target");
    capture
        .observe(&response_event(
            "other-session",
            "foreign",
            URL,
            200,
            "application/json",
        ))
        .expect("ignore foreign response");
    capture
        .observe(&request_event("session-a", "write", "POST", URL))
        .expect("ignore provider write request");
    capture
        .observe(&response_event(
            "session-a",
            "write",
            URL,
            200,
            "application/json",
        ))
        .expect("ignore untracked write response");
    capture
        .observe(&finished_event("session-a", "write"))
        .expect("ignore untracked write completion");
    assert_eq!(capture.tracked_request_count(), 0);
    assert_eq!(capture.take_finished_request_ids().len(), 0);
}

#[test]
fn rendered_conversation_ids_match_observed_metadata_in_visible_order() {
    let response = ObservedConversationListResponse::parse("GET", URL, body())
        .expect("valid synthetic list response");
    // jig-ignore-next-line: canonical rustfmt line.
    let matched = ReconciledVisibleConversationMetadata::reconcile(&["c-1", "c-2"], &response)
        // jig-ignore-next-line: canonical rustfmt line.
        .expect("match reversed visible order without interpreting provider sort");
    assert_eq!(matched.conversations()[0].id(), "c-1");
    assert_eq!(matched.conversations()[0].time(), 100);
    assert_eq!(matched.conversations()[1].id(), "c-2");
    assert_eq!(matched.conversations()[1].message_count(), 4);
    let diagnostic = format!("{matched:?}");
    assert!(!diagnostic.contains("c-1"));
    assert!(!diagnostic.contains("c-2"));
    assert!(!diagnostic.contains("SECRET"));
}

#[test]
fn rendered_subset_may_ignore_prefetched_provider_rows() {
    let response = ObservedConversationListResponse::parse("GET", URL, body())
        .expect("valid synthetic list response");
    // jig-ignore-next-line: canonical rustfmt line.
    let matched = ReconciledVisibleConversationMetadata::reconcile(&["c-2"], &response)
        .expect("ignore provider row not currently visible");
    assert_eq!(matched.conversations().len(), 1);
    assert_eq!(matched.conversations()[0].id(), "c-2");
}

#[test]
fn rendered_ids_fail_closed_on_invalid_or_missing_coverage() {
    let response = ObservedConversationListResponse::parse("GET", URL, body())
        .expect("valid synthetic list response");
    for ids in [vec![""], vec!["c-1", "c-1"]] {
        assert_eq!(
            ReconciledVisibleConversationMetadata::reconcile(&ids, &response),
            Err(ConversationListReconciliationError::InvalidVisibleId)
        );
    }
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ReconciledVisibleConversationMetadata::reconcile(&["unobserved"], &response),
        Err(ConversationListReconciliationError::MissingVisibleConversation)
    );
    let oversized = "x".repeat(513);
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ReconciledVisibleConversationMetadata::reconcile(&[&oversized], &response),
        Err(ConversationListReconciliationError::InvalidVisibleId)
    );
    let too_many = vec!["c-2"; 201];
    assert_eq!(
        ReconciledVisibleConversationMetadata::reconcile(&too_many, &response),
        Err(ConversationListReconciliationError::TooManyVisibleConversations)
    );
}

#[test]
fn empty_rendered_rows_require_an_empty_observed_response() {
    let response = ObservedConversationListResponse::parse("GET", URL, body())
        .expect("valid synthetic list response");
    assert_eq!(
        ReconciledVisibleConversationMetadata::reconcile(&[], &response),
        Err(ConversationListReconciliationError::UnexpectedObservedConversation)
    );
    let empty = ObservedConversationListResponse::parse(
        "GET",
        URL,
        r#"{"Code":1000,"Stale":0,"Total":0,"Conversations":[]}"#,
    )
    .expect("fresh empty provider list");
    let matched = ReconciledVisibleConversationMetadata::reconcile(&[], &empty)
        .expect("explicit empty and provider empty agree");
    assert_eq!(matched.conversations().len(), 0);
    let contradictory_total = ObservedConversationListResponse::parse(
        "GET",
        URL,
        r#"{"Code":1000,"Stale":0,"Total":5,"Conversations":[]}"#,
    )
    // jig-ignore-next-line: canonical rustfmt line.
    .expect("empty page with nonzero provider total can be syntactically valid");
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ReconciledVisibleConversationMetadata::reconcile(&[], &contradictory_total),
        Err(ConversationListReconciliationError::UnexpectedObservedConversation)
    );
}

static CONVERSATION_LIST_BROWSER_TEST_LOCK: Mutex<()> = Mutex::new(());

fn conversation_list_browser_root(label: &str) -> PathBuf {
    env::temp_dir().join(format!(
        "protonmail-ai-conversation-list-{label}-{}",
        process::id()
    ))
}

fn fake_conversation_list_browser(
    root: &Path,
    emit_detail: bool,
    complete_body: bool,
    late_during_disable: bool,
) -> PathBuf {
    fake_conversation_list_browser_view(
        root,
        emit_detail,
        complete_body,
        late_during_disable,
        "conversation-2",
        false,
        false,
    )
}

#[expect(
    clippy::too_many_lines,
    clippy::fn_params_excessive_bools,
    // jig-ignore-next-line: canonical rustfmt line.
    reason = "synthetic browser fixture handles independent view and request states"
)]
fn fake_conversation_list_browser_view(
    root: &Path,
    emit_detail: bool,
    complete_body: bool,
    late_during_disable: bool,
    visible_id: &str,
    view_drift: bool,
    message_mode: bool,
) -> PathBuf {
    let script = root.join("fake-browser");
    let log = root.join("conversation-list-log.txt");
    let template = r#"#!/usr/bin/env bash
set -eu
while IFS= read -r -d '' message <&3; do
  id=$(printf '%s' "$message" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$message" in
    *'Browser.getVersion'*)
      printf '{"id":%s,"result":{"product":"FakeChrome/1"}}\0' "$id" >&4;;
    *'Target.getTargets'*)
      target='[{"targetId":"page-1","type":"page",'
      target+='"url":"https://mail.proton.me/u/0/inbox"}]'
      printf '{"id":%s,"result":{"targetInfos":%s}}\0' "$id" "$target" >&4;;
    *'Target.attachToTarget'*)
      printf '{"id":%s,"result":{"sessionId":"session-1"}}\0' "$id" >&4;;
    *'Runtime.evaluate'*)
      case "$message" in
        *'forcedMessageRoute'*)
          value='{"forcedMessageRoute":__MESSAGE_MODE__,"activeSearch":false}';;
        *'message-list-loaded'*)
          view='__VISIBLE_ID__'
          if [ '__DRIFT__' = 'true' ] && [ -f '__LOG__' ]; then
            view='changed-conversation'
          fi
          if [ "$view" = '__EMPTY__' ]; then
            # jig-ignore-next-line: indivisible synthetic shell fixture.
            value='{"loading":false,"loaded":true,"rowIds":[],"skeletonCount":0,"emptyMarker":true,"nextPresent":false,"nextDisabled":null,"currentTestId":null}'
          elif [ "$view" = '__LOADING__' ]; then
            # jig-ignore-next-line: indivisible synthetic shell fixture.
            value='{"loading":true,"loaded":false,"rowIds":[],"skeletonCount":1,"emptyMarker":false,"nextPresent":false,"nextDisabled":null,"currentTestId":null}'
          else
            # jig-ignore-next-line: indivisible synthetic shell fixture.
            value='{"loading":false,"loaded":true,"rowIds":["'"$view"'"],"skeletonCount":0,"emptyMarker":false,"nextPresent":false,"nextDisabled":null,"currentTestId":null}'
          fi;;
        *) value='{"protocol":"https:","hostname":"mail.proton.me","port":""}';;
      esac
      printf '{"id":%s,"result":{"result":{"value":%s}}}\0' "$id" "$value" >&4;;
    *'DOM.getDocument'*)
      printf '{"id":%s,"result":{"root":{"nodeId":1}}}\0' "$id" >&4;;
    *'Accessibility.queryAXTree'*)
      # jig-ignore-next-line: indivisible synthetic shell fixture.
      case "$message" in *'"role":"navigation"'*|*'"role":"search"'*) nodes='[{"ignored":false}]';; *'"role":"dialog"'*|*'"role":"alertdialog"'*) nodes='[]';; *) exit 91;; esac
      printf '{"id":%s,"result":{"nodes":%s}}\0' "$id" "$nodes" >&4;;
    *'Network.enable'*)
      printf 'enable\n' >> '__LOG__'
      if [ '__EMIT_DETAIL__' = 'true' ]; then
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        url='https://mail.proton.me/api/mail/v4/conversations?Page=0&PageSize=50&Limit=50'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        request='{"sessionId":"session-1","method":"Network.requestWillBeSent","params":{"requestId":"list-1","request":{"method":"GET","url":"'"$url"'","headers":{"Authorization":"Bearer secret","Cookie":"secret-cookie"}}}}'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        response='{"sessionId":"session-1","method":"Network.responseReceived","params":{"requestId":"list-1","response":{"url":"'"$url"'","status":200,"mimeType":"application/json","headers":{"Set-Cookie":"secret-cookie"}}}}'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        finished='{"sessionId":"session-1","method":"Network.loadingFinished","params":{"requestId":"list-1"}}'
        printf '%s\0%s\0%s\0' "$request" "$response" "$finished" >&4
      fi
      printf '{"id":%s,"result":{}}\0' "$id" >&4;;
    *'Network.getResponseBody'*'"requestId":"list-1"'*)
      printf 'body\n' >> '__LOG__'
      if [ '__COMPLETE_BODY__' = 'true' ]; then
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        body='{"Code":1000,"Stale":0,"TasksRunning":[],"Total":2,"Conversations":[{"ID":"conversation-2","Time":1700000002,"Order":2,"NumMessages":2,"Subject":"SECRET SUBJECT"},{"ID":"conversation-1","Time":1700000001,"Order":1,"NumMessages":1,"Header":"SECRET HEADER"}]}'
      else
        body='{"Code":1000,"Stale":1,"Total":0,"Conversations":[]}'
      fi
      printf '{"id":%s,"result":{"body":"%s","base64Encoded":false}}\0' \
        "$id" "${body//\"/\\\"}" >&4;;
    *'Network.disable'*)
      printf 'disable\n' >> '__LOG__'
      if [ '__LATE_DETAIL__' = 'true' ]; then
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        url='https://mail.proton.me/api/mail/v4/conversations?Page=1&PageSize=50'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        request='{"sessionId":"session-1","method":"Network.requestWillBeSent","params":{"requestId":"list-late","request":{"method":"GET","url":"'"$url"'"}}}'
        printf '%s\0' "$request" >&4
      fi
      printf '{"id":%s,"result":{}}\0' "$id" >&4;;
    *'Target.detachFromTarget'*)
      printf '{"id":%s,"result":{}}\0' "$id" >&4;;
    *'Page.reload'*) exit 94;;
    *) exit 92;;
  esac
done
"#;
    let body = template
        .replace("__LOG__", &log.display().to_string())
        .replace(
            "__EMIT_DETAIL__",
            if emit_detail { "true" } else { "false" },
        )
        .replace(
            "__COMPLETE_BODY__",
            if complete_body { "true" } else { "false" },
        )
        .replace(
            "__LATE_DETAIL__",
            if late_during_disable { "true" } else { "false" },
        )
        .replace("__VISIBLE_ID__", visible_id)
        .replace("__DRIFT__", if view_drift { "true" } else { "false" })
        .replace(
            "__MESSAGE_MODE__",
            if message_mode { "true" } else { "false" },
        );
    fs::write(&script, body).expect("write fake conversation browser");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
        .expect("chmod fake conversation browser");
    script
}

#[test]
fn managed_browser_passively_observes_conversation_list_without_navigation() {
    use mail_web_adapter::{ManagedBrowser, ManagedBrowserPlan};

    let _guard = CONVERSATION_LIST_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic conversation browser tests");
    let root = conversation_list_browser_root("passive");
    fs::create_dir_all(&root).expect("create passive conversation root");
    let browser = fake_conversation_list_browser(&root, true, true, false);
    let plan = ManagedBrowserPlan::under_data_home(
        browser.to_str().expect("conversation browser path UTF-8"),
        &root.join("data"),
    )
    .expect("build passive conversation plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch conversation browser");
    let page = managed.provider_page().expect("discover passive Mail page");
    let observed = managed
        .observe_passive_conversation_list(&page, Duration::from_secs(1))
        .expect("observe browser-owned conversation request")
        .expect("conversation request should arrive");
    assert_eq!(observed.total(), 2);
    assert_eq!(observed.conversations().len(), 2);
    assert_eq!(observed.conversations()[0].id(), "conversation-2");
    drop(managed);
    let log = fs::read_to_string(root.join("conversation-list-log.txt"))
        .expect("read passive conversation log");
    assert_eq!(log, "enable\nbody\ndisable\n");
    fs::remove_dir_all(&root).expect("remove passive conversation root");
}

#[test]
fn managed_browser_conversation_list_timeout_performs_no_provider_action() {
    // jig-ignore-next-line: canonical rustfmt line.
    use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};

    let _guard = CONVERSATION_LIST_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic conversation browser tests");
    let root = conversation_list_browser_root("timeout");
    fs::create_dir_all(&root).expect("create timeout conversation root");
    let browser = fake_conversation_list_browser(&root, false, true, false);
    let plan = ManagedBrowserPlan::under_data_home(
        browser.to_str().expect("timeout browser path UTF-8"),
        &root.join("data"),
    )
    .expect("build timeout conversation plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch timeout browser");
    let page = managed.provider_page().expect("discover timeout Mail page");
    assert_eq!(
        managed
            .observe_passive_conversation_list(&page, Duration::from_millis(25))
            .expect("clean conversation timeout"),
        None
    );
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        managed.observe_passive_conversation_list(&page, Duration::from_secs(31)),
        Err(BrowserDriverError::ConversationListWaitTooLong)
    );
    drop(managed);
    let log = fs::read_to_string(root.join("conversation-list-log.txt"))
        .expect("read timeout conversation log");
    assert_eq!(log, "enable\ndisable\n");
    fs::remove_dir_all(&root).expect("remove timeout conversation root");
}

#[test]
fn stale_conversation_list_disables_network_before_error() {
    // jig-ignore-next-line: canonical rustfmt line.
    use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};

    let _guard = CONVERSATION_LIST_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic conversation browser tests");
    let root = conversation_list_browser_root("incomplete");
    fs::create_dir_all(&root).expect("create incomplete conversation root");
    let browser = fake_conversation_list_browser(&root, true, false, false);
    let plan = ManagedBrowserPlan::under_data_home(
        browser.to_str().expect("incomplete browser path UTF-8"),
        &root.join("data"),
    )
    .expect("build incomplete conversation plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch incomplete browser");
    let page = managed
        .provider_page()
        .expect("discover incomplete Mail page");
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        managed.observe_passive_conversation_list(&page, Duration::from_secs(1)),
        Err(BrowserDriverError::ConversationListResponse(
            ConversationListResponseError::StaleResponse,
        ))
    );
    drop(managed);
    let log = fs::read_to_string(root.join("conversation-list-log.txt"))
        .expect("read incomplete conversation log");
    assert_eq!(log, "enable\nbody\ndisable\n");
    fs::remove_dir_all(&root).expect("remove incomplete conversation root");
}

#[test]
fn conversation_list_started_during_network_disable_fails_closed() {
    // jig-ignore-next-line: canonical rustfmt line.
    use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};

    let _guard = CONVERSATION_LIST_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic conversation browser tests");
    let root = conversation_list_browser_root("late-disable");
    fs::create_dir_all(&root).expect("create late conversation root");
    let browser = fake_conversation_list_browser(&root, true, true, true);
    let plan = ManagedBrowserPlan::under_data_home(
        browser.to_str().expect("late browser path UTF-8"),
        &root.join("data"),
    )
    .expect("build late conversation plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch late browser");
    let page = managed.provider_page().expect("discover late Mail page");
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        managed.observe_passive_conversation_list(&page, Duration::from_secs(1)),
        Err(BrowserDriverError::ConversationListAmbiguous)
    );
    drop(managed);
    let log =
        // jig-ignore-next-line: canonical rustfmt line.
        fs::read_to_string(root.join("conversation-list-log.txt")).expect("read late conversation log");
    assert_eq!(log, "enable\nbody\ndisable\n");
    fs::remove_dir_all(&root).expect("remove late conversation root");
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ViewDrift {
    None,
    Rows,
    Mode,
    Origin,
}

#[derive(Clone, Copy)]
struct VisibleBrowserCase<'view> {
    row_id: &'view str,
    drift: ViewDrift,
    message_mode: bool,
    emits_response: bool,
    request_query: &'view str,
    page_marker: Option<&'view str>,
}

fn observe_visible_case(
    label: &str,
    case: VisibleBrowserCase<'_>,
) -> (
    // jig-ignore-next-line: canonical rustfmt line.
    Result<Option<ReconciledVisibleConversationMetadata>, mail_web_adapter::BrowserDriverError>,
    String,
) {
    use mail_web_adapter::{ManagedBrowser, ManagedBrowserPlan};
    let _guard = CONVERSATION_LIST_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic conversation browser tests");
    let root = conversation_list_browser_root(label);
    fs::create_dir_all(&root).expect("create visible conversation root");
    let browser = fake_conversation_list_browser_view(
        &root,
        case.emits_response,
        true,
        false,
        case.row_id,
        case.drift == ViewDrift::Rows,
        case.message_mode,
    );
    // jig-ignore-next-line: canonical rustfmt line.
    let script = fs::read_to_string(&browser).expect("read synthetic browser fixture");
    // jig-ignore-next-line: canonical rustfmt line.
    let script = script.replace("?Page=0&PageSize=50&Limit=50", case.request_query);
    let script = if let Some(page_marker) = case.page_marker {
        script.replace(
            "\"currentTestId\":null",
            &format!("\"currentTestId\":\"{page_marker}\""),
        )
    } else {
        script
    };
    let script = if case.drift == ViewDrift::Mode {
        script.replace(
            r#"value='{"forcedMessageRoute":false,"activeSearch":false}';;"#,
            &format!(
                // jig-ignore-next-line: indivisible synthetic shell fixture.
                "value='{{\"forcedMessageRoute\":false,\"activeSearch\":false}}'; if [ -f '{}' ]; then value='{{\"forcedMessageRoute\":true,\"activeSearch\":false}}'; fi;;",
                root.join("conversation-list-log.txt").display()
            ),
        )
    } else {
        script
    };
    let script = if case.drift == ViewDrift::Origin {
        script.replace(
            // jig-ignore-next-line: indivisible synthetic shell fixture.
            r#"*) value='{"protocol":"https:","hostname":"mail.proton.me","port":""}';;"#,
            &format!(
                // jig-ignore-next-line: indivisible synthetic shell fixture.
                "*) value='{{\"protocol\":\"https:\",\"hostname\":\"mail.proton.me\",\"port\":\"\"}}'; if [ -f '{}' ]; then value='{{\"protocol\":\"https:\",\"hostname\":\"other.example\",\"port\":\"\"}}'; fi;;",
                root.join("conversation-list-log.txt").display()
            ),
        )
    } else {
        script
    };
    fs::write(&browser, script).expect("update synthetic browser view");
    let plan = ManagedBrowserPlan::under_data_home(
        browser.to_str().expect("synthetic browser path UTF-8"),
        &root.join("data"),
    )
    .expect("build visible conversation plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch synthetic browser");
    let page = managed
        .provider_page()
        .expect("discover synthetic Mail page");
    // jig-ignore-next-line: canonical rustfmt line.
    let observed = managed.observe_visible_conversation_metadata(&page, Duration::from_millis(50));
    drop(managed);
    // jig-ignore-next-line: canonical rustfmt line.
    let log = fs::read_to_string(root.join("conversation-list-log.txt")).unwrap_or_default();
    fs::remove_dir_all(&root).expect("remove synthetic visible browser root");
    (observed, log)
}

#[test]
fn managed_browser_matches_stable_visible_conversation_without_action() {
    let (observed, log) = observe_visible_case(
        "visible-success",
        VisibleBrowserCase {
            row_id: "conversation-2",
            drift: ViewDrift::None,
            message_mode: false,
            emits_response: true,
            request_query: "?Page=0&PageSize=50&Limit=50",
            page_marker: None,
        },
    );
    let matched = observed
        .expect("stable visible read")
        .expect("app-owned response");
    assert_eq!(matched.conversations().len(), 1);
    assert_eq!(matched.conversations()[0].id(), "conversation-2");
    assert_eq!(matched.conversations()[0].time(), 1_700_000_002);
    assert_eq!(log, "enable\nbody\ndisable\n");
}

#[test]
fn managed_browser_rejects_uncovered_or_changing_visible_rows() {
    use mail_web_adapter::BrowserDriverError;
    let (missing, log) = observe_visible_case(
        "visible-missing",
        VisibleBrowserCase {
            row_id: "other-conversation",
            drift: ViewDrift::None,
            message_mode: false,
            emits_response: true,
            request_query: "?Page=0&PageSize=50&Limit=50",
            page_marker: None,
        },
    );
    assert_eq!(
        missing,
        Err(BrowserDriverError::ConversationListReconciliation(
            ConversationListReconciliationError::MissingVisibleConversation,
        ))
    );
    assert_eq!(log, "enable\nbody\ndisable\n");
    let (changed, log) = observe_visible_case(
        "visible-changed",
        VisibleBrowserCase {
            row_id: "conversation-2",
            drift: ViewDrift::Rows,
            message_mode: false,
            emits_response: true,
            request_query: "?Page=0&PageSize=50&Limit=50",
            page_marker: None,
        },
    );
    assert_eq!(changed, Err(BrowserDriverError::MailboxPageChanged));
    assert_eq!(log, "enable\nbody\ndisable\n");
}

#[test]
fn managed_browser_refuses_message_mode_and_unsettled_rows_before_network() {
    use mail_web_adapter::BrowserDriverError;
    for (label, row_id, message_mode, expected) in [
        (
            "visible-message",
            "conversation-2",
            true,
            BrowserDriverError::ConversationListMessageMode,
        ),
        (
            "visible-loading",
            "__LOADING__",
            false,
            BrowserDriverError::MailboxPageNotSettled,
        ),
    ] {
        let (observed, log) = observe_visible_case(
            label,
            VisibleBrowserCase {
                row_id,
                drift: ViewDrift::None,
                message_mode,
                emits_response: true,
                request_query: "?Page=0&PageSize=50&Limit=50",
                page_marker: None,
            },
        );
        assert_eq!(observed, Err(expected));
        assert_eq!(log, "");
    }
}

#[test]
fn managed_browser_rejects_explicit_empty_contradiction() {
    use mail_web_adapter::BrowserDriverError;
    let (observed, log) = observe_visible_case(
        "visible-empty",
        VisibleBrowserCase {
            row_id: "__EMPTY__",
            drift: ViewDrift::None,
            message_mode: false,
            emits_response: true,
            request_query: "?Page=0&PageSize=50&Limit=50",
            page_marker: None,
        },
    );
    assert_eq!(
        observed,
        Err(BrowserDriverError::ConversationListReconciliation(
            ConversationListReconciliationError::UnexpectedObservedConversation,
        ))
    );
    assert_eq!(log, "enable\nbody\ndisable\n");
}

#[test]
fn managed_browser_visible_metadata_timeout_keeps_rows_unchanged() {
    let (observed, log) = observe_visible_case(
        "visible-timeout",
        VisibleBrowserCase {
            row_id: "conversation-2",
            drift: ViewDrift::None,
            message_mode: false,
            emits_response: false,
            request_query: "?Page=0&PageSize=50&Limit=50",
            page_marker: None,
        },
    );
    assert_eq!(observed, Ok(None));
    assert_eq!(log, "enable\ndisable\n");
}

#[test]
fn managed_browser_rejects_request_page_mismatch_and_anchor() {
    use mail_web_adapter::BrowserDriverError;
    for (label, request_query, marker) in [
        ("request-page-one", "?Page=1&PageSize=50", None),
        ("request-missing-page", "?PageSize=50", None),
        ("request-anchor", "?Page=0&Anchor=123&AnchorID=secret", None),
        (
            "visible-page-two",
            "?Page=0&PageSize=50",
            Some("pagination-row:go-to-page-2"),
        ),
    ] {
        let (observed, log) = observe_visible_case(
            label,
            VisibleBrowserCase {
                row_id: "conversation-2",
                drift: ViewDrift::None,
                message_mode: false,
                emits_response: true,
                request_query,
                page_marker: marker,
            },
        );
        let expected = if label == "request-anchor" {
            BrowserDriverError::ConversationListNetwork(
                ConversationListNetworkError::InvalidPagination,
            )
        } else {
            BrowserDriverError::ConversationListPageUnproven
        };
        assert_eq!(observed, Err(expected));
        assert_eq!(log, "enable\ndisable\n");
    }
}

#[test]
fn managed_browser_accepts_matching_page_number_without_claiming_snapshot() {
    let (observed, log) = observe_visible_case(
        "visible-page-two-matched",
        VisibleBrowserCase {
            row_id: "conversation-2",
            drift: ViewDrift::None,
            message_mode: false,
            emits_response: true,
            request_query: "?Page=1&PageSize=50",
            page_marker: Some("pagination-row:go-to-page-2"),
        },
    );
    // jig-ignore-next-line: canonical rustfmt line.
    let match_result = observed.expect("matched page").expect("observed response");
    assert_eq!(match_result.conversations()[0].id(), "conversation-2");
    assert_eq!(log, "enable\nbody\ndisable\n");
}

#[test]
fn matching_network_request_ids_and_urls_are_bounded() {
    let exact = "https://mail.proton.me/api/mail/v4/conversations?Page=0";
    for (index, request_id, url) in [
        ("empty", String::new(), String::from(exact)),
        ("oversized-id", "x".repeat(513), String::from(exact)),
        (
            "oversized-query",
            String::from("valid-id"),
            format!("{exact}&Keyword={}", "x".repeat(16_384)),
        ),
    ] {
        let mut capture = ConversationListNetworkCapture::new("session-a");
        assert_eq!(
            // jig-ignore-next-line: canonical rustfmt line.
            capture.observe(&request_event("session-a", &request_id, "GET", &url)),
            Err(ConversationListNetworkError::MalformedEvent),
            "{index} must be rejected without retaining content"
        );
        assert_eq!(capture.tracked_request_count(), 0);
        assert_eq!(capture.take_finished_request_ids().len(), 0);
    }
    // Large unrelated request identifiers never become list-tracking state.
    let mut ignored = ConversationListNetworkCapture::new("session-a");
    ignored
        .observe(&request_event(
            "session-a",
            &"x".repeat(1024),
            "GET",
            "https://mail.proton.me/api/mail/v4/conversations/count",
        ))
        .expect("unrelated neighbor traffic remains ignored");
    assert_eq!(ignored.tracked_request_count(), 0);
}

#[test]
fn network_capture_rejects_malformed_conversation_page_selectors() {
    for (index, query) in [
        "?Page=invalid",
        "?Page=-1",
        "?Page=4294967296",
        "?Page=0&Page=1",
        "?Page=0&Anchor=",
        "?Page=0&AnchorID=",
        "?Page=0&AnchorID=present",
        "?Page=0&Anchor=123",
        "?Page=0&Anchor=123&Anchor=456&AnchorID=present",
        "?Page=0&Anchor=123&AnchorID=present&AnchorID=other",
        "?Page=0&PageSize=0",
        "?Page=0&PageSize=101",
        "?Page=0&PageSize=not-a-number",
        "?Page=0&PageSize=50&PageSize=50",
        "?Page=0&Limit=0",
        "?Page=0&Limit=101",
        "?Page=0&Limit=-1",
        "?Page=0&Limit=50&Limit=50",
        "?Page=0&PageSize=50&Limit=25",
        "?Page=0&PageSize=10&Limit=100",
        "?Page=0&Anchor=123&AnchorID=c-2",
    ]
    .iter()
    .enumerate()
    {
        let mut capture = ConversationListNetworkCapture::new("session-a");
        let request_id = format!("invalid-{index}");
        // jig-ignore-next-line: canonical rustfmt line.
        let url = format!("https://mail.proton.me/api/mail/v4/conversations{query}");
        assert_eq!(
            // jig-ignore-next-line: canonical rustfmt line.
            capture.observe(&request_event("session-a", &request_id, "GET", &url)),
            Err(ConversationListNetworkError::InvalidPagination)
        );
        assert_eq!(capture.tracked_request_count(), 0);
    }
}

#[test]
fn malformed_request_during_enable_drains_reply_and_disables_network() {
    use mail_web_adapter::BrowserDriverError;
    let (observed, log) = observe_visible_case(
        "bad-request-during-enable",
        VisibleBrowserCase {
            row_id: "conversation-2",
            drift: ViewDrift::None,
            message_mode: false,
            emits_response: true,
            request_query: "?Page=invalid",
            page_marker: None,
        },
    );
    assert_eq!(
        observed,
        Err(BrowserDriverError::ConversationListNetwork(
            ConversationListNetworkError::InvalidPagination,
        ))
    );
    assert_eq!(log, "enable\ndisable\n");
}

#[test]
fn malformed_request_during_enable_preserves_followup_inspection() {
    // jig-ignore-next-line: canonical rustfmt line.
    use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};

    let _guard = CONVERSATION_LIST_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic conversation browser tests");
    let root = conversation_list_browser_root("enable-recovery");
    fs::create_dir_all(&root).expect("create synthetic browser root");
    let browser = fake_conversation_list_browser(&root, true, true, false);
    let script = fs::read_to_string(&browser).expect("read browser fixture");
    // jig-ignore-next-line: canonical rustfmt line.
    let malformed = script.replace("?Page=0&PageSize=50&Limit=50", "?Page=not-a-number");
    fs::write(&browser, malformed).expect("change synthetic request page");
    let plan = ManagedBrowserPlan::under_data_home(
        browser.to_str().expect("synthetic browser UTF-8 path"),
        &root.join("data"),
    )
    .expect("build synthetic browser plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch synthetic browser");
    let page = managed.provider_page().expect("find synthetic Mail page");
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        managed.observe_passive_conversation_list(&page, Duration::from_secs(1)),
        Err(BrowserDriverError::ConversationListNetwork(
            ConversationListNetworkError::InvalidPagination,
        ))
    );
    let inspected = managed
        .inspect_mailbox_list(&page)
        .expect("CDP session remains synchronized after failed request");
    assert_eq!(inspected.row_ids(), &[String::from("conversation-2")]);
    drop(managed);
    let log = fs::read_to_string(root.join("conversation-list-log.txt"))
        .expect("read synthetic browser log");
    assert_eq!(log, "enable\ndisable\n");
    fs::remove_dir_all(&root).expect("clean synthetic browser root");
}

#[test]
fn managed_browser_rejects_mode_drift_without_changing_rows() {
    use mail_web_adapter::BrowserDriverError;
    let (observed, log) = observe_visible_case(
        "visible-mode-drift",
        VisibleBrowserCase {
            row_id: "conversation-2",
            drift: ViewDrift::Mode,
            message_mode: false,
            emits_response: true,
            request_query: "?Page=0&PageSize=50&Limit=50",
            page_marker: None,
        },
    );
    assert_eq!(observed, Err(BrowserDriverError::MailboxModeChanged));
    assert_eq!(log, "enable\nbody\ndisable\n");
}

#[test]
fn managed_browser_rejects_origin_drift_after_network_teardown() {
    use mail_web_adapter::BrowserDriverError;
    let (observed, log) = observe_visible_case(
        "visible-origin-drift",
        VisibleBrowserCase {
            row_id: "conversation-2",
            drift: ViewDrift::Origin,
            message_mode: false,
            emits_response: true,
            request_query: "?Page=0&PageSize=50&Limit=50",
            page_marker: None,
        },
    );
    assert!(matches!(
        observed,
        Err(BrowserDriverError::OriginDrift { .. })
    ));
    assert_eq!(log, "enable\nbody\ndisable\n");
}

fn assert_malformed_event_recovers_cdp(stage: &str, expected_log: &str) {
    // jig-ignore-next-line: canonical rustfmt line.
    use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};

    let _guard = CONVERSATION_LIST_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic conversation browser tests");
    let root = conversation_list_browser_root(stage);
    fs::create_dir_all(&root).expect("create synthetic browser root");
    let browser = fake_conversation_list_browser(&root, true, true, false);
    let script = fs::read_to_string(&browser).expect("read browser fixture");
    let marker = match stage {
        "malformed-during-body" => "      printf 'body\\n' >> ",
        "malformed-during-disable" => "      printf 'disable\\n' >> ",
        _ => panic!("unsupported synthetic stage"),
    };
    assert!(script.contains(marker));
    let invalid_event = serde_json::json!({
        "sessionId": "session-1",
        "method": "Network.requestWillBeSent",
        "params": {
            "requestId": "bad-list",
            "request": {
                "method": "GET",
                // jig-ignore-next-line: canonical rustfmt line.
                "url": "https://mail.proton.me/api/mail/v4/conversations?Page=invalid"
            }
        }
    });
    let injection =
        // jig-ignore-next-line: canonical rustfmt line.
        format!("      invalid='{invalid_event}'\n      printf '%s\\0' \"$invalid\" >&4\n");
    let updated = script.replacen(marker, &format!("{injection}{marker}"), 1);
    fs::write(&browser, updated).expect("install synthetic invalid event");
    let plan = ManagedBrowserPlan::under_data_home(
        browser.to_str().expect("synthetic browser UTF-8 path"),
        &root.join("data"),
    )
    .expect("build synthetic browser plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch synthetic browser");
    let page = managed.provider_page().expect("find synthetic Mail page");
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        managed.observe_passive_conversation_list(&page, Duration::from_secs(1)),
        Err(BrowserDriverError::ConversationListNetwork(
            ConversationListNetworkError::InvalidPagination,
        ))
    );
    let inspected = managed
        .inspect_mailbox_list(&page)
        .expect("next CDP command succeeds after Network observation failure");
    assert_eq!(inspected.row_ids(), &[String::from("conversation-2")]);
    drop(managed);
    let log = fs::read_to_string(root.join("conversation-list-log.txt"))
        .expect("read synthetic browser log");
    assert_eq!(log, expected_log);
    fs::remove_dir_all(&root).expect("clean synthetic browser root");
}

#[test]
fn malformed_event_during_body_read_keeps_cdp_commands_synchronized() {
    // jig-ignore-next-line: canonical rustfmt line.
    assert_malformed_event_recovers_cdp("malformed-during-body", "enable\nbody\ndisable\n");
}

#[test]
fn malformed_event_during_network_disable_keeps_cdp_synchronized() {
    // jig-ignore-next-line: canonical rustfmt line.
    assert_malformed_event_recovers_cdp("malformed-during-disable", "enable\nbody\ndisable\n");
}
