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
//   - Synthetic workflow evidence for message-mode visible-page reads.
// - Must-Not:
//   - Launch real Chrome, access an account, or infer unproven list mode.
// - Allows:
//   - Emulate location proof, stable rows, and mode drift in one CDP session.
// - Split-When:
//   - Public message-page DTO mapping gains independent acceptance coverage.
// - Merge-When:
//   - A broader read-only adapter suite owns message-mode proof and snapshots.
// - Summary:
//   - Proves visible rows become message rows only with stable mode evidence.
// - Description:
//   - Covers forced routes, search mode, unknown Inbox, and mode drift.
// - Usage:
//   - Run through the `mail_web_adapter` integration-test target.
// - Defaults:
//   - Synthetic local process and filesystem state only.
//

//! Message-mode visible mailbox-page workflow regression tests.

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process;

use mail_web_adapter::MessageListReconciliationError;
use mail_web_adapter::ObservedMessageListResponse;
use mail_web_adapter::ProviderPage;
use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};
use mail_web_adapter::{MailboxRenderMode, NextPageControl};

const VISIBLE_AX: &str = r#"[{"ignored":false}]"#;
const ABSENT_AX: &str = "[]";
const STABLE_LIST: &str = r#"{
  "loading":false,"loaded":true,"rowIds":["message-a"],
  "skeletonCount":0,"emptyMarker":false,"nextPresent":true,
  "nextDisabled":false,"currentTestId":"pagination-row:go-to-page-1"
}"#;
const STABLE_ROWS: &str = r#"[
  {"id":"message-a","subject":"Interview follow-up",
   "addresses":"jobs@example.com","unread":true}
]"#;

#[derive(Clone, Copy)]
struct ModeSignals {
    forced_route: bool,
    active_search: bool,
}

const FORCED_MESSAGES: ModeSignals = ModeSignals {
    forced_route: true,
    active_search: false,
};
const SEARCH_MESSAGES: ModeSignals = ModeSignals {
    forced_route: false,
    active_search: true,
};
const UNKNOWN_MODE: ModeSignals = ModeSignals {
    forced_route: false,
    active_search: false,
};

fn test_root(label: &str) -> PathBuf {
    let name = format!("protonmail-ai-message-page-{label}-{}", process::id());
    env::temp_dir().join(name)
}

fn fake(root: &Path, before: ModeSignals, after: ModeSignals) -> PathBuf {
    let script = root.join("fake-browser");
    let template = r#"#!/usr/bin/env bash
set -eu
mode_probe=0
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
    *'Runtime.evaluate'*'forcedMessageRoute'*)
      mode_probe=$((mode_probe + 1))
      forced=__FORCED_BEFORE__
      search=__SEARCH_BEFORE__
      if [ "$mode_probe" -gt 1 ]; then
        forced=__FORCED_AFTER__
        search=__SEARCH_AFTER__
      fi
      response='{"id":'"$id"',"result":{"result":{"type":"object",'
      response+='"value":{"forcedMessageRoute":'"$forced"','
      response+='"activeSearch":'"$search"'}}}}'
      printf '%s\0' "$response" >&4;;
    *'Runtime.evaluate'*'message-list-loading'*)
      response='{"id":'"$id"',"result":{"result":{"type":"object",'
      response+='"value":__STABLE_LIST__}}}'
      printf '%s\0' "$response" >&4;;
    *'Runtime.evaluate'*'aria-labelledby'*)
      response='{"id":'"$id"',"result":{"result":{"type":"object",'
      response+='"value":__STABLE_ROWS__}}}'
      printf '%s\0' "$response" >&4;;
    *'Runtime.evaluate'*)
      response='{"id":'"$id"',"result":{"result":{"type":"object",'
      response+='"value":{"protocol":"https:",'
      response+='"hostname":"mail.proton.me","port":""}}}}'
      printf '%s\0' "$response" >&4;;
    *'DOM.getDocument'*)
      printf '{"id":%s,"result":{"root":{"nodeId":1}}}\0' "$id" >&4;;
    *'Accessibility.queryAXTree'*)
      case "$message" in
        *'"role":"navigation"'*) nodes='__VISIBLE_AX__';;
        *'"role":"search"'*) nodes='__VISIBLE_AX__';;
        *'"role":"alertdialog"'*) nodes='__ABSENT_AX__';;
        *'"role":"dialog"'*) nodes='__ABSENT_AX__';;
        *) exit 91;;
      esac
      printf '{"id":%s,"result":{"nodes":%s}}\0' "$id" "$nodes" >&4;;
    *'Target.detachFromTarget'*)
      printf '{"id":%s,"result":{}}\0' "$id" >&4;;
    *) exit 92;;
  esac
done
"#;
    let bool_text = |value: bool| if value { "true" } else { "false" };
    let body = template
        .replace("__FORCED_BEFORE__", bool_text(before.forced_route))
        .replace("__SEARCH_BEFORE__", bool_text(before.active_search))
        .replace("__FORCED_AFTER__", bool_text(after.forced_route))
        .replace("__SEARCH_AFTER__", bool_text(after.active_search))
        .replace("__STABLE_LIST__", STABLE_LIST)
        .replace("__STABLE_ROWS__", STABLE_ROWS)
        .replace("__VISIBLE_AX__", VISIBLE_AX)
        .replace("__ABSENT_AX__", ABSENT_AX);
    fs::write(&script, body).expect("write fake browser");
    let permissions = fs::Permissions::from_mode(0o700);
    fs::set_permissions(&script, permissions).expect("chmod fake browser");
    script
}

fn plan(root: &Path, browser: &Path) -> ManagedBrowserPlan {
    ManagedBrowserPlan::under_data_home(
        browser.to_str().expect("browser path must be UTF-8"),
        &root.join("data"),
    )
    .expect("build managed browser plan")
}

fn with_browser<T>(
    label: &str,
    before: ModeSignals,
    after: ModeSignals,
    inspect: impl FnOnce(&mut ManagedBrowser, &ProviderPage) -> T,
) -> T {
    let root = test_root(label);
    fs::create_dir_all(&root).expect("create synthetic root");
    let fake = fake(&root, before, after);
    let browser_plan = plan(&root, &fake);
    // jig-ignore-next-line: rustfmt keeps this launch expression intact.
    let mut managed = ManagedBrowser::launch(&browser_plan).expect("launch driver");
    let page = managed.provider_page().expect("discover Mail page");
    let result = inspect(&mut managed, &page);
    drop(managed);
    fs::remove_dir_all(root).expect("remove synthetic root");
    result
}

#[test]
fn forced_sent_route_produces_message_snapshot() {
    let snapshot = with_browser(
        "sent",
        FORCED_MESSAGES,
        FORCED_MESSAGES,
        ManagedBrowser::read_visible_message_page,
    )
    .expect("forced message route must be readable");

    assert_eq!(snapshot.current_page(), Some(1));
    assert_eq!(snapshot.next_page(), NextPageControl::Enabled);
    assert_eq!(snapshot.rows().len(), 1);
    assert_eq!(snapshot.rows()[0].id(), "message-a");
    assert_eq!(snapshot.rows()[0].subject(), "Interview follow-up");
}

#[test]
fn active_search_produces_message_snapshot_in_inbox() {
    let snapshot = with_browser(
        "search",
        SEARCH_MESSAGES,
        SEARCH_MESSAGES,
        ManagedBrowser::read_visible_message_page,
    )
    .expect("active search must force message mode");
    assert_eq!(snapshot.rows()[0].id(), "message-a");
}

#[test]
fn ordinary_inbox_refuses_message_semantics() {
    let error = with_browser(
        "inbox",
        UNKNOWN_MODE,
        UNKNOWN_MODE,
        ManagedBrowser::read_visible_message_page,
    )
    .expect_err("ordinary Inbox mode is not externally proven");
    assert_eq!(error, BrowserDriverError::MailboxMessageModeRequired);
}

#[test]
fn message_mode_change_during_read_invalidates_snapshot() {
    let error = with_browser(
        "mode-change",
        FORCED_MESSAGES,
        UNKNOWN_MODE,
        ManagedBrowser::read_visible_message_page,
    )
    .expect_err("mode drift must invalidate snapshot");
    assert_eq!(error, BrowserDriverError::MailboxModeChanged);
}

#[test]
fn location_only_inspection_exposes_no_mailbox_content() {
    let evidence = with_browser(
        "mode-only",
        FORCED_MESSAGES,
        FORCED_MESSAGES,
        ManagedBrowser::inspect_mailbox_mode,
    )
    .expect("inspect mailbox mode");
    assert_eq!(evidence.mode(), MailboxRenderMode::Messages);
    assert_eq!(
        format!("{evidence:?}"),
        "MailboxModeEvidence { mode: Messages }"
    );
}

#[test]
fn stable_message_page_reconciles_only_its_visible_ids() {
    let snapshot = with_browser(
        "reconcile",
        FORCED_MESSAGES,
        FORCED_MESSAGES,
        ManagedBrowser::read_visible_message_page,
    )
    .expect("read stable message page");
    let response = ObservedMessageListResponse::parse(
        "GET",
        "https://mail.proton.me/api/mail/v4/messages?Page=0",
        concat!(
            r#"{"Total":2,"Messages":[{"ID":"prefetch","Time":2,"Order":2},"#,
            r#"{"ID":"message-a","Time":1,"Order":1}]}"#,
        ),
    )
    .expect("parse synthetic provider metadata");
    let reconciled = snapshot
        .reconcile_metadata(&[response])
        .expect("reconcile stable visible message");
    assert_eq!(reconciled.messages().len(), 1);
    assert_eq!(reconciled.messages()[0].id(), "message-a");
    assert_eq!(reconciled.messages()[0].time(), 1);
}

#[test]
fn stable_message_page_rejects_missing_machine_metadata() {
    let snapshot = with_browser(
        "reconcile-missing",
        FORCED_MESSAGES,
        FORCED_MESSAGES,
        ManagedBrowser::read_visible_message_page,
    )
    .expect("read stable message page");
    let response = ObservedMessageListResponse::parse(
        "GET",
        "https://mail.proton.me/api/mail/v4/messages?Page=0",
        r#"{"Total":1,"Messages":[{"ID":"other","Time":1,"Order":1}]}"#,
    )
    .expect("parse unrelated provider metadata");
    assert_eq!(
        snapshot.reconcile_metadata(&[response]),
        Err(MessageListReconciliationError::MissingVisibleMessage)
    );
}
