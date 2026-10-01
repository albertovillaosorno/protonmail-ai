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
  "loading":true,"loaded":false,"rowIds":["partial"],"skeletonCount":2,
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
    let script = root.join("fake-browser");
    let body = format!(
        r#"#!/usr/bin/env bash
set -eu
list_probe=0
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
    *'Runtime.evaluate'*'message-list-loading'*)
      list_probe=$((list_probe + 1))
      value='{before}'
      if [ "$list_probe" -gt 1 ]; then value='{after}'; fi
      response='{{"id":'"$id"',"result":{{"result":{{"type":"object",'
      response+='"value":'"$value"'}}}}}}'
      printf '%s\0' "$response" >&4;;
    *'Runtime.evaluate'*'aria-labelledby'*)
      response='{{"id":'"$id"',"result":{{"result":{{"type":"object",'
      response+='"value":{rows}}}}}}}'
      printf '%s\0' "$response" >&4;;
    *'Runtime.evaluate'*)
      response='{{"id":'"$id"',"result":{{"result":{{"type":"object",'
      response+='"value":{{"protocol":"https:",'
      response+='"hostname":"mail.proton.me","port":""}}}}}}}}'
      printf '%s\0' "$response" >&4;;
    *'DOM.getDocument'*)
      printf '{{"id":%s,"result":{{"root":{{"nodeId":1}}}}}}\0' "$id" >&4;;
    *'Accessibility.queryAXTree'*)
      case "$message" in
        *'"role":"navigation"'*) nodes='{VISIBLE_AX}';;
        *'"role":"search"'*) nodes='{VISIBLE_AX}';;
        *'"role":"alertdialog"'*) nodes='{ABSENT_AX}';;
        *'"role":"dialog"'*) nodes='{ABSENT_AX}';;
        *) exit 91;;
      esac
      printf '{{"id":%s,"result":{{"nodes":%s}}}}\0' "$id" "$nodes" >&4;;
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
    assert!(snapshot.rows().is_empty());
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
