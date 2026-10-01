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
//   - Synthetic evidence for visible sort proof and list_messages blockers.
// - Must-Not:
//   - Access a live account, translated labels, or change provider sort state.
// - Allows:
//   - Emulate menu open/close, aria-pressed state, mode, shell, and origin.
// - Split-When:
//   - Public cursor traversal gains an independently complete acceptance suite.
// - Merge-When:
//   - Read workflow acceptance owns sort and cursor readiness end to end.
// - Summary:
//   - Proves sort inspection is non-mutating and list_messages stays gated.
// - Description:
//   - Covers newest/other sort, menu lifecycle, malformed state, and blockers.
// - Usage:
//   - Run through the `mail_web_adapter` integration-test target.
// - Defaults:
//   - Synthetic local process and filesystem state only.
//

//! Sort evidence and provider-neutral list-readiness regression tests.

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process;

use mail_web_adapter::ProviderPage;
use mail_web_adapter::{BrowserDriverError, ListMessagesBlocker};
use mail_web_adapter::{MailboxSortOrder, ManagedBrowser, ManagedBrowserPlan};

const VISIBLE_AX: &str = r#"[{"ignored":false}]"#;
const ABSENT_AX: &str = "[]";

#[derive(Clone, Copy)]
enum SortScenario {
    Newest,
    Oldest,
    Multiple,
}

fn test_root(label: &str) -> PathBuf {
    let name = format!("protonmail-ai-sort-{label}-{}", process::id());
    env::temp_dir().join(name)
}

type PressedPair = (&'static str, &'static str);

const fn pressed_values(scenario: SortScenario) -> PressedPair {
    match scenario {
        SortScenario::Newest => ("true", "false"),
        SortScenario::Oldest => ("false", "true"),
        SortScenario::Multiple => ("true", "true"),
    }
}

fn fake(root: &Path, scenario: SortScenario, starts_open: bool) -> PathBuf {
    let script = root.join("fake-browser");
    let log = root.join("menu-log.txt");
    let (newest, oldest) = pressed_values(scenario);
    let open = i32::from(starts_open);
    let body = format!(
        r#"#!/usr/bin/env bash
set -eu
menu_open={open}
value_reply='{{"id":%s,"result":{{"result":{{"value":%s}}}}}}\0'
while IFS= read -r -d '' message <&3; do
  id=$(printf '%s' "$message" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$message" in
    *'Browser.getVersion'*)
      printf '{{"id":%s,"result":{{"product":"FakeChrome/1"}}}}\0' "$id" >&4;;
    *'Target.getTargets'*)
      target='[{{"targetId":"page-1","type":"page",'
      target+='"url":"https://mail.proton.me/u/0/sent"}}]'
      printf '{{"id":%s,"result":{{"targetInfos":%s}}}}\0' "$id" "$target" >&4;;
    *'Target.attachToTarget'*)
      printf '{{"id":%s,"result":{{"sessionId":"session-1"}}}}\0' "$id" >&4;;
    *'Runtime.evaluate'*'forcedMessageRoute'*)
      value='{{"forcedMessageRoute":true,"activeSearch":false}}'
      printf "$value_reply" "$id" "$value" >&4;;
    *'Runtime.evaluate'*'alreadyOpen'*)
      if [ "$menu_open" -eq 1 ]; then
        value='{{"alreadyOpen":true,"clicked":false}}'
      else
        menu_open=1
        printf 'open\n' >> '{log}'
        value='{{"alreadyOpen":false,"clicked":true}}'
      fi
      printf "$value_reply" "$id" "$value" >&4;;
    *'Runtime.evaluate'*'newest:values[0]'*)
      if [ "$menu_open" -eq 0 ]; then value='{{"ready":false}}';
      else
        value='{{"ready":true,"valid":true,"newest":{newest},'
        value+='"oldest":{oldest},"largest":false,"smallest":false}}'
      fi
      printf "$value_reply" "$id" "$value" >&4;;
    *'Runtime.evaluate'*'nodes[0].click();return true'*)
      menu_open=0
      printf 'close\n' >> '{log}'
      printf '{{"id":%s,"result":{{"result":{{"value":true}}}}}}\0' "$id" >&4;;
    *'Runtime.evaluate'*'===null'*)
      if [ "$menu_open" -eq 0 ]; then closed=true; else closed=false; fi
      printf "$value_reply" "$id" "$closed" >&4;;
    *'Runtime.evaluate'*)
      value='{{"protocol":"https:","hostname":"mail.proton.me","port":""}}'
      printf "$value_reply" "$id" "$value" >&4;;
    *'DOM.getDocument'*)
      printf '{{"id":%s,"result":{{"root":{{"nodeId":1}}}}}}\0' "$id" >&4;;
    *'Accessibility.queryAXTree'*)
      case "$message" in
        *'"role":"navigation"'*) nodes='{visible}';;
        *'"role":"search"'*) nodes='{visible}';;
        *'"role":"alertdialog"'*) nodes='{absent}';;
        *'"role":"dialog"'*) nodes='{absent}';;
        *) exit 91;;
      esac
      printf '{{"id":%s,"result":{{"nodes":%s}}}}\0' "$id" "$nodes" >&4;;
    *'Target.detachFromTarget'*)
      printf '{{"id":%s,"result":{{}}}}\0' "$id" >&4;;
    *) exit 92;;
  esac
done
"#,
        open = open,
        log = log.display(),
        newest = newest,
        oldest = oldest,
        visible = VISIBLE_AX,
        absent = ABSENT_AX,
    );
    fs::write(&script, body).expect("write fake browser");
    let permissions = fs::Permissions::from_mode(0o700);
    fs::set_permissions(&script, permissions).expect("chmod fake browser");
    script
}

fn fake_cleanup_drift(root: &Path) -> PathBuf {
    let script = fake(root, SortScenario::Newest, false);
    let body = fs::read_to_string(&script).expect("read fake browser");
    let original = concat!(
        "    *'Runtime.evaluate'*)\n",
        "      value='{\"protocol\":\"https:\",",
        "\"hostname\":\"mail.proton.me\",\"port\":\"\"}'\n",
        "      printf \"$value_reply\" \"$id\" \"$value\" >&4;;"
    );
    let replacement = concat!(
        "    *'Runtime.evaluate'*)\n",
        "      origin_checks=${origin_checks:-0}\n",
        "      origin_checks=$((origin_checks+1))\n",
        "      if [ \"$origin_checks\" -eq 4 ]; then ",
        "host='account.proton.me'; else host='mail.proton.me'; fi\n",
        "      value='{\"protocol\":\"https:\",\"hostname\":\"'\"$host\"'\",",
        "\"port\":\"\"}'\n",
        "      printf \"$value_reply\" \"$id\" \"$value\" >&4;;"
    );
    let changed = body.replace(original, replacement);
    assert_ne!(changed, body, "fake origin branch must be replaced");
    fs::write(&script, changed).expect("rewrite drift fake browser");
    script
}

fn with_browser<T>(
    label: &str,
    scenario: SortScenario,
    starts_open: bool,
    inspect: impl FnOnce(&mut ManagedBrowser, &ProviderPage) -> T,
) -> (T, String) {
    let root = test_root(label);
    fs::create_dir_all(&root).expect("create synthetic root");
    let fake = fake(&root, scenario, starts_open);
    let plan = ManagedBrowserPlan::under_data_home(
        fake.to_str().expect("browser path must be UTF-8"),
        &root.join("data"),
    )
    .expect("build plan");
    let mut browser = ManagedBrowser::launch(&plan).expect("launch driver");
    let page = browser.provider_page().expect("discover page");
    let result = inspect(&mut browser, &page);
    drop(browser);
    let log = fs::read_to_string(root.join("menu-log.txt")).unwrap_or_default();
    fs::remove_dir_all(root).expect("remove synthetic root");
    (result, log)
}

#[test]
fn origin_drift_before_cleanup_prevents_close_click() {
    let root = test_root("cleanup-origin-drift");
    fs::create_dir_all(&root).expect("create synthetic root");
    let fake = fake_cleanup_drift(&root);
    let plan = ManagedBrowserPlan::under_data_home(
        fake.to_str().expect("browser path must be UTF-8"),
        &root.join("data"),
    )
    .expect("build plan");
    let mut browser = ManagedBrowser::launch(&plan).expect("launch driver");
    let page = browser.provider_page().expect("discover page");
    let result = browser.inspect_mailbox_sort(&page);
    assert_eq!(
        result,
        Err(BrowserDriverError::OriginDrift {
            expected: mail_web_adapter::PageOrigin::ProtonMail,
            observed: mail_web_adapter::PageOrigin::ProtonAccount,
        })
    );
    drop(browser);
    let log = fs::read_to_string(root.join("menu-log.txt")).unwrap_or_default();
    assert_eq!(log, "open\n");
    fs::remove_dir_all(root).expect("remove synthetic root");
}

#[test]
fn newest_first_is_observed_and_adapter_opened_menu_is_restored() {
    let (result, log) = with_browser(
        "newest",
        SortScenario::Newest,
        false,
        ManagedBrowser::inspect_mailbox_sort,
    );
    assert_eq!(result, Ok(MailboxSortOrder::NewestFirst));
    assert_eq!(log, "open\nclose\n");
}

#[test]
fn preopened_menu_is_not_closed_by_adapter() {
    let (result, log) = with_browser(
        "already-open",
        SortScenario::Oldest,
        true,
        ManagedBrowser::inspect_mailbox_sort,
    );
    assert_eq!(result, Ok(MailboxSortOrder::OldestFirst));
    assert!(log.is_empty());
}

#[test]
fn multiple_active_sort_options_fail_closed() {
    let (result, log) = with_browser(
        "multiple",
        SortScenario::Multiple,
        false,
        ManagedBrowser::inspect_mailbox_sort,
    );
    assert_eq!(result, Err(BrowserDriverError::MailboxSortIncompatible));
    assert_eq!(log, "open\nclose\n");
}

#[test]
fn newest_first_still_has_two_provider_neutral_blockers() {
    let (result, _log) = with_browser(
        "readiness-newest",
        SortScenario::Newest,
        false,
        ManagedBrowser::inspect_list_messages_readiness,
    );
    let readiness = result.expect("readiness must be inspectable");
    assert_eq!(readiness.observed_sort(), MailboxSortOrder::NewestFirst);
    assert_eq!(
        readiness.blockers(),
        [
            ListMessagesBlocker::ProviderTieBreakDiffers,
            ListMessagesBlocker::MissingSnapshotBoundary,
        ]
    );
    assert!(!readiness.ready());
}

#[test]
fn non_newest_sort_adds_explicit_order_blocker() {
    let (result, _log) = with_browser(
        "readiness-oldest",
        SortScenario::Oldest,
        false,
        ManagedBrowser::inspect_list_messages_readiness,
    );
    let readiness = result.expect("readiness must be inspectable");
    assert_eq!(readiness.observed_sort(), MailboxSortOrder::OldestFirst);
    assert!(
        readiness
            .blockers()
            .contains(&ListMessagesBlocker::SortNotNewestFirst)
    );
    assert!(!readiness.ready());
}
