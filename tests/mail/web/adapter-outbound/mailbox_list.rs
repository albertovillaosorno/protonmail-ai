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
//   - Synthetic CDP evidence for content-free mailbox-list inspection.
// - Must-Not:
//   - Launch real Chrome, access an account, or expose message content.
// - Allows:
//   - Emulate list loading, rows, empty markers, paging, and origin drift.
// - Split-When:
//   - Content-bearing row projection gains its own read-model fixtures.
// - Merge-When:
//   - A broader read-only adapter suite owns the same list-state invariants.
// - Summary:
//   - Proves conservative list settling; partial loading is never exposed.
// - Description:
//   - Exercises loaded rows, loading, empty, contradictions, and origin drift.
// - Usage:
//   - Run through the `mail_web_adapter` integration-test target.
// - Defaults:
//   - Synthetic local process and filesystem state only.
//

//! Proton Mail mailbox-list semantic regression tests.

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process;

use mail_web_adapter::PageOrigin;
use mail_web_adapter::{BrowserDriverError, MailboxListState, NextPageControl};
use mail_web_adapter::{ManagedBrowser, ManagedBrowserPlan};

const VISIBLE_AX: &str = r#"[{"ignored":false}]"#;
const IGNORED_AX: &str = r#"[{"ignored":true}]"#;
const ABSENT_AX: &str = "[]";

const ROWS: &str = r#"{
  "loading": false,
  "loaded": true,
  "rowIds": ["row-a", "row-b"],
  "skeletonCount": 0,
  "emptyMarker": false,
  "nextPresent": true,
  "nextDisabled": false,
  "currentTestId": "pagination-row:go-to-page-2"
}"#;
const LOADING: &str = r#"{
  "loading": true,
  "loaded": false,
  "rowIds": ["partial-row"],
  "skeletonCount": 3,
  "emptyMarker": false,
  "nextPresent": true,
  "nextDisabled": true,
  "currentTestId": "pagination-row:go-to-page-1"
}"#;
const EXPLICIT_EMPTY: &str = r#"{
  "loading": false,
  "loaded": true,
  "rowIds": [],
  "skeletonCount": 0,
  "emptyMarker": true,
  "nextPresent": false,
  "nextDisabled": null,
  "currentTestId": null
}"#;
const UNPROVEN_NO_ROWS: &str = r#"{
  "loading": false,
  "loaded": true,
  "rowIds": [],
  "skeletonCount": 0,
  "emptyMarker": false,
  "nextPresent": false,
  "nextDisabled": null,
  "currentTestId": null
}"#;
const LOADED_WITH_SKELETON: &str = r#"{
  "loading": false,
  "loaded": true,
  "rowIds": ["row-a"],
  "skeletonCount": 1,
  "emptyMarker": false,
  "nextPresent": false,
  "nextDisabled": null,
  "currentTestId": null
}"#;
const DUPLICATE_ROWS: &str = r#"{
  "loading": false,
  "loaded": true,
  "rowIds": ["row-a", "row-a"],
  "skeletonCount": 0,
  "emptyMarker": false,
  "nextPresent": false,
  "nextDisabled": null,
  "currentTestId": null
}"#;

fn test_root(label: &str) -> PathBuf {
    let name = format!("protonmail-ai-list-{label}-{}", process::id());
    env::temp_dir().join(name)
}

// jig-ignore-next-line: canonical rustfmt line.
fn fake_browser(root: &Path, list_value: &str, search_ax: &str, host_after_list: &str) -> PathBuf {
    let script = root.join("fake-browser");
    let body = format!(
        r#"#!/usr/bin/env bash
set -eu
origin_probe=0
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
    *'Runtime.evaluate'*'message-list-loaded'*)
      response='{{"id":'"$id"',"result":{{"result":{{"type":"object",'
      response+='"value":{list_value}}}}}}}'
      printf '%s\0' "$response" >&4;;
    *'Runtime.evaluate'*)
      origin_probe=$((origin_probe + 1))
      host='mail.proton.me'
      if [ "$origin_probe" -gt 2 ]; then host='{host_after_list}'; fi
      response='{{"id":'"$id"',"result":{{"result":{{"type":"object",'
      response+='"value":{{"protocol":"https:",'
      response+='"hostname":"'"$host"'","port":""}}}}}}}}'
      printf '%s\0' "$response" >&4;;
    *'DOM.getDocument'*)
      printf '{{"id":%s,"result":{{"root":{{"nodeId":1}}}}}}\0' "$id" >&4;;
    *'Accessibility.queryAXTree'*)
      case "$message" in
        *'"role":"navigation"'*) nodes='{VISIBLE_AX}';;
        *'"role":"search"'*) nodes='{search_ax}';;
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

fn inspect(
    label: &str,
    list_value: &str,
    search_ax: &str,
    host_after_list: &str,
) -> Result<mail_web_adapter::MailboxListEvidence, BrowserDriverError> {
    let root = test_root(label);
    fs::create_dir_all(&root).expect("create synthetic root");
    let browser = fake_browser(&root, list_value, search_ax, host_after_list);
    let browser_plan = plan(&root, &browser);
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&browser_plan).expect("launch fake driver");
    let page = managed.provider_page().expect("discover Mail page");
    let result = managed.inspect_mailbox_list(&page);
    drop(managed);
    fs::remove_dir_all(root).expect("remove synthetic root");
    result
}

#[test]
fn settled_rows_expose_only_opaque_ids_and_paging_state() {
    let evidence =
        // jig-ignore-next-line: canonical rustfmt line.
        inspect("rows", ROWS, VISIBLE_AX, "mail.proton.me").expect("inspect settled rows");
    assert_eq!(evidence.state(), MailboxListState::SettledRows);
    assert_eq!(
        evidence.row_ids(),
        &[String::from("row-a"), String::from("row-b")]
    );
    assert_eq!(evidence.current_page(), Some(2));
    assert_eq!(evidence.next_page(), NextPageControl::Enabled);
    assert!(!evidence.explicitly_empty());
    let diagnostic = format!("{evidence:?}");
    assert!(!diagnostic.contains("row-a"));
    assert!(!diagnostic.contains("row-b"));
}

#[test]
fn loading_discards_partial_rows_and_pagination() {
    let evidence =
        // jig-ignore-next-line: canonical rustfmt line.
        inspect("loading", LOADING, VISIBLE_AX, "mail.proton.me").expect("inspect loading list");
    assert_eq!(evidence.state(), MailboxListState::Loading);
    assert!(evidence.row_ids().is_empty());
    assert_eq!(evidence.current_page(), None);
    assert_eq!(evidence.next_page(), NextPageControl::Absent);
}

#[test]
fn explicit_empty_is_distinct_from_unproven_no_rows() {
    let empty = inspect("empty", EXPLICIT_EMPTY, VISIBLE_AX, "mail.proton.me")
        .expect("inspect explicit empty state");
    // jig-ignore-next-line: canonical rustfmt line.
    let unproven = inspect("unproven", UNPROVEN_NO_ROWS, VISIBLE_AX, "mail.proton.me")
        .expect("inspect unproven no-row state");

    assert_eq!(empty.state(), MailboxListState::SettledExplicitEmpty);
    assert!(empty.explicitly_empty());
    assert_eq!(unproven.state(), MailboxListState::SettledNoRowsUnproven);
    assert!(!unproven.explicitly_empty());
}

#[test]
fn loaded_state_with_skeleton_fails_closed() {
    let error = inspect(
        "loaded-skeleton",
        LOADED_WITH_SKELETON,
        VISIBLE_AX,
        "mail.proton.me",
    )
    .expect_err("loaded list with skeleton must fail closed");
    assert_eq!(error, BrowserDriverError::MailboxListIncompatible);
}

#[test]
fn duplicate_provider_row_ids_fail_closed() {
    // jig-ignore-next-line: canonical rustfmt line.
    let error = inspect("duplicates", DUPLICATE_ROWS, VISIBLE_AX, "mail.proton.me")
        .expect_err("duplicate row IDs must fail closed");
    assert_eq!(error, BrowserDriverError::MailboxListIncompatible);
}

#[test]
fn mail_shell_must_be_ready_before_list_observation() {
    let error = inspect("shell-not-ready", ROWS, IGNORED_AX, "mail.proton.me")
        .expect_err("unready Mail shell must block list inspection");
    assert_eq!(error, BrowserDriverError::MailShellNotReady);
}

#[test]
fn origin_drift_after_list_observation_invalidates_evidence() {
    let error = inspect("late-drift", ROWS, VISIBLE_AX, "account.proton.me")
        .expect_err("origin drift must invalidate list evidence");
    assert_eq!(
        error,
        BrowserDriverError::OriginDrift {
            expected: PageOrigin::ProtonMail,
            observed: PageOrigin::ProtonAccount,
        }
    );
}

#[test]
fn oversized_list_evidence_fails_closed() {
    let long_id = "x".repeat(513);
    let long_id_value = format!(
        r#"{{"loading":false,"loaded":true,"rowIds":["{long_id}"],
        "skeletonCount":0,"emptyMarker":false,"nextPresent":false,
        "nextDisabled":null,"currentTestId":null}}"#
    );
    let error = inspect("long-id", &long_id_value, VISIBLE_AX, "mail.proton.me")
        .expect_err("oversized provider ID must fail closed");
    assert_eq!(error, BrowserDriverError::MailboxListIncompatible);

    let ids = (0usize..201usize)
        .map(|index| format!(r#""row-{index}""#))
        .collect::<Vec<_>>()
        .join(",");
    let too_many = format!(
        r#"{{"loading":false,"loaded":true,"rowIds":[{ids}],
        "skeletonCount":0,"emptyMarker":false,"nextPresent":false,
        "nextDisabled":null,"currentTestId":null}}"#
    );
    let error = inspect("too-many", &too_many, VISIBLE_AX, "mail.proton.me")
        .expect_err("too many visible rows must fail closed");
    assert_eq!(error, BrowserDriverError::MailboxListIncompatible);
}
