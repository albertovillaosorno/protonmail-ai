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
//   - Synthetic CDP evidence for stable visible mailbox-page snapshots.
// - Must-Not:
//   - Launch real Chrome, access an account, or read message bodies.
// - Allows:
//   - Emulate visible row metadata and list changes during one target session.
// - Split-When:
//   - Full message opening or body projection gains separate read fixtures.
// - Merge-When:
//   - A broader read-only adapter suite owns the same snapshot invariants.
// - Summary:
//   - Proves visible rows are returned only from one stable settled list page.
// - Description:
//   - Exercises content projection, explicit empty, loading, and list drift.
// - Usage:
//   - Run through the `mail_web_adapter` integration-test target.
// - Defaults:
//   - Synthetic local process and filesystem state only.
//

//! Stable visible mailbox-page workflow regression tests.

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process;

use mail_web_adapter::NextPageControl;
use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};

const VISIBLE_AX: &str = r#"[{"ignored":false}]"#;
const ABSENT_AX: &str = "[]";
const STABLE_LIST: &str = r#"{
  "loading":false,"loaded":true,"rowIds":["row-a","row-b"],
  "skeletonCount":0,"emptyMarker":false,"nextPresent":true,
  "nextDisabled":false,"currentTestId":"pagination-row:go-to-page-2"
}"#;
const CHANGED_LIST: &str = r#"{
  "loading":false,"loaded":true,"rowIds":["row-a","row-c"],
  "skeletonCount":0,"emptyMarker":false,"nextPresent":true,
  "nextDisabled":false,"currentTestId":"pagination-row:go-to-page-2"
}"#;
const EMPTY_LIST: &str = r#"{
  "loading":false,"loaded":true,"rowIds":[],"skeletonCount":0,
  "emptyMarker":true,"nextPresent":false,"nextDisabled":null,
  "currentTestId":null
}"#;
const LOADING_LIST: &str = r#"{
  "loading":true,"loaded":false,"rowIds":[],"skeletonCount":0,
  "emptyMarker":false,"nextPresent":false,"nextDisabled":null,
  "currentTestId":null
}"#;
const UNPROVEN_LIST: &str = r#"{
  "loading":false,"loaded":true,"rowIds":[],"skeletonCount":0,
  "emptyMarker":false,"nextPresent":false,"nextDisabled":null,
  "currentTestId":null
}"#;
const STABLE_ROWS: &str = r#"[
  {"id":"row-a","subject":"Interview follow-up",
   "addresses":"jobs@example.com","unread":true},
  {"id":"row-b","subject":"Next steps",
   "addresses":"recruiter@example.org","unread":false}
]"#;
const REORDERED_ROWS: &str = r#"[
  {"id":"row-b","subject":"Next steps",
   "addresses":"recruiter@example.org","unread":false},
  {"id":"row-a","subject":"Interview follow-up",
   "addresses":"jobs@example.com","unread":true}
]"#;
const MALFORMED_ROWS: &str = r#"[
  {"id":"row-a","subject":"Interview follow-up","unread":true},
  {"id":"row-b","subject":"Next steps",
   "addresses":"recruiter@example.org","unread":false}
]"#;

fn test_root(label: &str) -> PathBuf {
    let name = format!("protonmail-ai-page-{label}-{}", process::id());
    env::temp_dir().join(name)
}

fn fake_browser(root: &Path, before: &str, rows: &str, after: &str) -> PathBuf {
    fake_browser_with_rows(root, before, rows, rows, after)
}

fn fake_browser_with_rows(
    root: &Path,
    before: &str,
    first_rows: &str,
    second_rows: &str,
    after: &str,
) -> PathBuf {
    let script = root.join("fake-browser");
    let body = format!(
        r#"#!/usr/bin/env bash
set -eu
list_probe=0
row_probe=0
while IFS= read -r -d '' message <&3; do
  id=$(printf '%s' "$message" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$message" in
    *'Browser.getVersion'*)
      printf '{{"id":%s,"result":{{"product":"FakeChrome/1"}}}}\0' "$id" >&4;;
    *'Target.getTargets'*)
      target='[{{"targetId":"page-1","type":"page",'
      target+='"url":"https://mail.proton.me/u/0/inbox"}}]'
      printf '{{"id":%s,"result":{{"targetInfos":%s}}}}\0' "$id" "$target" >&4;;
    *'Target.attachToTarget'*)
      printf '{{"id":%s,"result":{{"sessionId":"session-1"}}}}\0' "$id" >&4;;
    *'Runtime.evaluate'*'aria-labelledby'*)
      row_probe=$((row_probe + 1))
      value='{first_rows}'
      if [ "$row_probe" -gt 1 ]; then value='{second_rows}'; fi
      response='{{"id":'"$id"','
      response+='"sessionId":"session-1","result":{{"result":{{"type":"object",'
      response+='"value":'"$value"'}}}}}}'
      printf '%s\0' "$response" >&4;;
    *'Runtime.evaluate'*'message-list-loading'*)
      list_probe=$((list_probe + 1))
      value='{before}'
      if [ "$list_probe" -gt 1 ]; then value='{after}'; fi
      response='{{"id":'"$id"','
      response+='"sessionId":"session-1","result":{{"result":{{"type":"object",'
      response+='"value":'"$value"'}}}}}}'
      printf '%s\0' "$response" >&4;;
    *'Runtime.evaluate'*)
      response='{{"id":'"$id"','
      response+='"sessionId":"session-1","result":{{"result":{{"type":"object",'
      response+='"value":{{"protocol":"https:",'
      response+='"hostname":"mail.proton.me","port":""}}}}}}}}'
      printf '%s\0' "$response" >&4;;
    *'DOM.getDocument'*)
      reply_format='{{"id":%s,"sessionId":"session-1",'
      reply_format+='"result":{{"root":{{"nodeId":1}}}}}}\0'
      printf "$reply_format" "$id" >&4;;
    *'Accessibility.queryAXTree'*)
      case "$message" in
        *'"role":"navigation"'*) nodes='{VISIBLE_AX}';;
        *'"role":"search"'*) nodes='{VISIBLE_AX}';;
        *'"role":"alertdialog"'*) nodes='{ABSENT_AX}';;
        *'"role":"dialog"'*) nodes='{ABSENT_AX}';;
        *) exit 91;;
      esac
      reply_format='{{"id":%s,"sessionId":"session-1",'
      reply_format+='"result":{{"nodes":%s}}}}\0'
      printf "$reply_format" "$id" "$nodes" >&4;;
    *'Target.detachFromTarget'*)
      printf '{{"id":%s,"result":{{}}}}\0' "$id" >&4;;
    *) exit 92;;
  esac
done
"#,
    );
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

fn read(
    label: &str,
    before: &str,
    rows: &str,
    after: &str,
) -> Result<mail_web_adapter::MailboxPageSnapshot, BrowserDriverError> {
    let root = test_root(label);
    fs::create_dir_all(&root).expect("create synthetic root");
    let browser = fake_browser(&root, before, rows, after);
    let browser_plan = plan(&root, &browser);
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&browser_plan).expect("launch fake driver");
    let page = managed.provider_page().expect("discover Mail page");
    let result = managed.read_visible_mailbox_page(&page);
    drop(managed);
    fs::remove_dir_all(root).expect("remove synthetic root");
    result
}

#[test]
fn stable_visible_rows_project_bounded_mail_metadata() {
    // jig-ignore-next-line: canonical rustfmt line.
    let snapshot = read("stable", STABLE_LIST, STABLE_ROWS, STABLE_LIST).expect("read stable page");
    assert_eq!(snapshot.current_page(), Some(2));
    assert_eq!(snapshot.next_page(), NextPageControl::Enabled);
    assert!(!snapshot.explicitly_empty());
    assert_eq!(snapshot.rows().len(), 2);
    let first = &snapshot.rows()[0];
    assert_eq!(first.id(), "row-a");
    assert_eq!(first.subject(), "Interview follow-up");
    assert_eq!(first.displayed_addresses(), "jobs@example.com");
    assert!(first.unread());
    let diagnostic = format!("{snapshot:?}");
    for secret in ["row-a", "Interview follow-up", "jobs@example.com"] {
        assert!(!diagnostic.contains(secret));
    }
}

#[test]
fn explicit_empty_is_the_only_empty_snapshot() {
    // jig-ignore-next-line: canonical rustfmt line.
    let snapshot = read("empty", EMPTY_LIST, "[]", EMPTY_LIST).expect("read explicit empty page");
    assert!(snapshot.explicitly_empty());
    assert_eq!(snapshot.rows().len(), 0);
}

#[test]
fn loading_and_unproven_empty_do_not_become_snapshots() {
    // jig-ignore-next-line: canonical rustfmt line.
    for (label, list) in [("loading", LOADING_LIST), ("unproven", UNPROVEN_LIST)] {
        // jig-ignore-next-line: canonical rustfmt line.
        let error = read(label, list, "[]", list).expect_err("list must not settle");
        assert_eq!(error, BrowserDriverError::MailboxPageNotSettled);
    }
}

#[test]
fn list_change_during_content_read_fails_closed() {
    let error = read("changed", STABLE_LIST, STABLE_ROWS, CHANGED_LIST)
        .expect_err("changing list must fail closed");
    assert_eq!(error, BrowserDriverError::MailboxPageChanged);
}

#[test]
fn row_order_must_match_settled_list_ids() {
    let error = read("reordered", STABLE_LIST, REORDERED_ROWS, STABLE_LIST)
        .expect_err("row reordering must fail closed");
    assert_eq!(error, BrowserDriverError::MailboxPageChanged);
}

#[test]
fn malformed_visible_row_fails_closed() {
    let error = read("malformed", STABLE_LIST, MALFORMED_ROWS, STABLE_LIST)
        .expect_err("missing address metadata must fail closed");
    assert_eq!(error, BrowserDriverError::MailboxPageIncompatible);
}
#[test]
fn empty_subject_is_valid_visible_metadata() {
    let rows = r#"[
      {"id":"row-a","subject":"","addresses":"jobs@example.com","unread":true},
      {"id":"row-b","subject":"Next steps",
   "addresses":"recruiter@example.org","unread":false}
    ]"#;
    let snapshot = read("no-subject", STABLE_LIST, rows, STABLE_LIST)
        .expect("empty subject must remain readable");
    assert_eq!(snapshot.rows()[0].subject(), "");
}

#[test]
fn oversized_visible_text_fails_closed() {
    let long_subject = "s".repeat(16_385);
    let rows = format!(
        r#"[
          {{"id":"row-a","subject":"{long_subject}",
           "addresses":"jobs@example.com","unread":true}},
          {{"id":"row-b","subject":"Next steps",
           "addresses":"recruiter@example.org","unread":false}}
        ]"#
    );
    let error = read("long-subject", STABLE_LIST, &rows, STABLE_LIST)
        .expect_err("oversized subject must fail closed");
    assert_eq!(error, BrowserDriverError::MailboxPageIncompatible);

    let long_addresses = "a".repeat(16_385);
    let rows = format!(
        r#"[
          {{"id":"row-a","subject":"Interview follow-up",
           "addresses":"{long_addresses}","unread":true}},
          {{"id":"row-b","subject":"Next steps",
           "addresses":"recruiter@example.org","unread":false}}
        ]"#
    );
    let error = read("long-address", STABLE_LIST, &rows, STABLE_LIST)
        .expect_err("oversized addresses must fail closed");
    assert_eq!(error, BrowserDriverError::MailboxPageIncompatible);
}

#[test]
fn changing_subject_with_stable_row_ids_invalidates_page_snapshot() {
    let root = test_root("content-drift");
    fs::create_dir_all(&root).expect("create isolated fake browser root");
    // jig-ignore-next-line: canonical rustfmt line.
    let changed_subject = STABLE_ROWS.replace("Interview follow-up", "Changed subject");
    let browser = fake_browser_with_rows(
        &root,
        STABLE_LIST,
        STABLE_ROWS,
        &changed_subject,
        STABLE_LIST,
    );
    let plan = plan(&root, &browser);
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch synthetic browser");
    let page = managed.provider_page().expect("find synthetic Mail page");
    assert_eq!(
        managed.read_visible_mailbox_page(&page),
        Err(BrowserDriverError::MailboxPageChanged),
        "stable IDs alone must not hide changing row metadata"
    );
    drop(managed);
    fs::remove_dir_all(root).expect("remove fake browser root");
}

#[test]
fn changing_addresses_or_unread_state_invalidates_page_snapshot() {
    for (label, changed) in [
        (
            "address-drift",
            STABLE_ROWS.replace("jobs@example.com", "changed@example.net"),
        ),
        (
            "unread-drift",
            STABLE_ROWS.replacen("\"unread\":true", "\"unread\":false", 1),
        ),
    ] {
        let root = test_root(label);
        fs::create_dir_all(&root).expect("create isolated browser fixture");
        let browser =
            // jig-ignore-next-line: canonical rustfmt line.
            fake_browser_with_rows(&root, STABLE_LIST, STABLE_ROWS, &changed, STABLE_LIST);
        let plan = plan(&root, &browser);
        // jig-ignore-next-line: canonical rustfmt line.
        let mut managed = ManagedBrowser::launch(&plan).expect("launch fake Mail");
        let page = managed.provider_page().expect("find fake Mail page");
        assert_eq!(
            managed.read_visible_mailbox_page(&page),
            Err(BrowserDriverError::MailboxPageChanged),
            "{label} must invalidate the snapshot"
        );
        drop(managed);
        fs::remove_dir_all(root).expect("remove isolated browser fixture");
    }
}

#[test]
fn expired_mail_shell_after_projection_refuses_visible_page() {
    let root = test_root("late-shell-expiry");
    fs::create_dir_all(&root).expect("create fake Mail root");
    let browser = fake_browser(&root, STABLE_LIST, STABLE_ROWS, STABLE_LIST);
    // jig-ignore-next-line: canonical rustfmt line.
    let script = fs::read_to_string(&browser).expect("read fake browser script");
    let ready = format!("nodes='{VISIBLE_AX}'");
    let late_expiry = format!(
        // jig-ignore-next-line: indivisible fake-browser shell fragment.
        "nodes='{VISIBLE_AX}'; if [ \"$list_probe\" -gt 1 ]; then nodes='[{{\"ignored\":true}}]'; fi"
    );
    assert!(script.contains(&ready));
    fs::write(&browser, script.replace(&ready, &late_expiry))
        .expect("install late login expiry in synthetic browser");
    let browser_plan = plan(&root, &browser);
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&browser_plan).expect("launch fake Chrome");
    let page = managed.provider_page().expect("discover fake Mail page");
    assert_eq!(
        managed.read_visible_mailbox_page(&page),
        Err(BrowserDriverError::MailShellNotReady),
        "a signed-out Mail shell may not release projected content"
    );
    drop(managed);
    fs::remove_dir_all(root).expect("remove fake browser root");
}

#[test]
fn list_change_during_final_shell_recheck_invalidates_snapshot() {
    let root = test_root("late-list-drift");
    fs::create_dir_all(&root).expect("create fake browser root");
    let browser = fake_browser(&root, STABLE_LIST, STABLE_ROWS, STABLE_LIST);
    let script = fs::read_to_string(&browser).expect("read fake browser");
    let marker = "      response='{";
    let late_change =
        // jig-ignore-next-line: indivisible fake-browser shell fragment.
        format!("      if [ \"$list_probe\" -gt 2 ]; then value='{CHANGED_LIST}'; fi\n{marker}");
    assert!(script.contains(marker));
    // The content branch also constructs CDP result frames. Inject only
    // after the list branch, not at the first generic response constructor.
    let branch = script
        .find("*'Runtime.evaluate'*'message-list-loading'*)")
        .expect("synthetic list branch");
    let (prefix, suffix) = script.split_at(branch);
    let changed = suffix.replacen(marker, &late_change, 1);
    let updated = format!("{prefix}{changed}");
    fs::write(&browser, updated).expect("install late list drift");
    let plan = plan(&root, &browser);
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch fake browser");
    let page = managed.provider_page().expect("find synthetic Mail page");
    assert_eq!(
        managed.read_visible_mailbox_page(&page),
        Err(BrowserDriverError::MailboxPageChanged),
        "list drift after shell recheck cannot release a stale page"
    );
    drop(managed);
    fs::remove_dir_all(root).expect("remove fake browser fixture");
}
