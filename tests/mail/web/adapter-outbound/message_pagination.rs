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
//   - Synthetic evidence for one-step read-only message pagination.
// - Must-Not:
//   - Launch real Chrome, access an account, or target mailbox mutations.
// - Allows:
//   - Emulate stable page evidence, Next activation, and transition drift.
// - Split-When:
//   - Public multi-page list workflow gains independent adapter integration.
// - Merge-When:
//   - A broader read-only suite owns page navigation and stable snapshots.
// - Summary:
//   - Proves Next advances exactly one externally proven message page.
// - Description:
//   - Covers control drift, page drift, mode drift, and origin drift.
// - Usage:
//   - Run through the `mail_web_adapter` integration-test target.
// - Defaults:
//   - Synthetic local process and filesystem state only.
//

//! Message-mode next-page navigation regression tests.

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process;

use mail_web_adapter::NextPageControl;
use mail_web_adapter::PageOrigin;
use mail_web_adapter::ProviderPage;
use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};

const VISIBLE_AX: &str = r#"[{"ignored":false}]"#;
const ABSENT_AX: &str = "[]";

#[derive(Clone, Copy)]
enum BinaryState {
    No,
    Yes,
}

impl BinaryState {
    const fn shell(self) -> &'static str {
        match self {
            Self::No => "false",
            Self::Yes => "true",
        }
    }
}

#[derive(Clone, Copy)]
struct Scenario {
    before_next_disabled: BinaryState,
    click_disabled: BinaryState,
    current_page_visible: BinaryState,
    destination_page: u32,
    mode_after_click: BinaryState,
    origin_after_click_is_mail: BinaryState,
}

const SUCCESS: Scenario = Scenario {
    before_next_disabled: BinaryState::No,
    click_disabled: BinaryState::No,
    current_page_visible: BinaryState::Yes,
    destination_page: 2,
    mode_after_click: BinaryState::Yes,
    origin_after_click_is_mail: BinaryState::Yes,
};

fn test_root(label: &str) -> PathBuf {
    let name = format!("protonmail-ai-pagination-{label}-{}", process::id());
    env::temp_dir().join(name)
}

const fn fake_template() -> &'static str {
    r#"#!/usr/bin/env bash
set -eu
page=1
clicked=0
while IFS= read -r -d '' message <&3; do
  id=$(printf '%s' "$message" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$message" in
    *'Browser.getVersion'*)
      printf '{"id":%s,"result":{"product":"FakeChrome/1"}}\0' "$id" >&4;;
    *'Target.getTargets'*)
      target='[{"targetId":"page-1","type":"page",'
      target+='"url":"https://mail.proton.me/u/0/sent"}]'
      printf '{"id":%s,"result":{"targetInfos":%s}}\0' "$id" "$target" >&4;;
    *'Target.attachToTarget'*)
      printf '{"id":%s,"result":{"sessionId":"session-1"}}\0' "$id" >&4;;
    *'Runtime.evaluate'*'forcedMessageRoute'*)
      forced=true
      if [ "$clicked" -eq 1 ] &&
         [ '__MODE_AFTER__' = false ]; then forced=false; fi
      value='{"forcedMessageRoute":'"$forced"',"activeSearch":false}'
      printf '{"id":%s,"result":{"result":{"type":"object","value":%s}}}\0' \
        "$id" "$value" >&4;;
    *'Runtime.evaluate'*'pagination-row:go-to-next-page'*'next.click'*)
      if [ '__CLICK_DISABLED__' = true ]; then
        value='{"present":true,"disabled":true,"clicked":false}'
      else
        clicked=1
        page=__DESTINATION_PAGE__
        value='{"present":true,"disabled":false,"clicked":true}'
      fi
      printf '{"id":%s,"result":{"result":{"type":"object","value":%s}}}\0' \
        "$id" "$value" >&4;;
    *'Runtime.evaluate'*'message-list-loading'*)
      disabled=false
      if [ "$page" -gt 1 ] ||
         [ '__BEFORE_DISABLED__' = true ]; then disabled=true; fi
      row="message-$page"
      value='{"loading":false,"loaded":true,"rowIds":["'"$row"'"],'
      value+='"skeletonCount":0,"emptyMarker":false,"nextPresent":true,'
      value+='"nextDisabled":'"$disabled"','
      if [ '__CURRENT_VISIBLE__' = true ]; then
        value+='"currentTestId":"pagination-row:go-to-page-'"$page"'"}'
      else
        value+='"currentTestId":null}'
      fi
      printf '{"id":%s,"result":{"result":{"type":"object","value":%s}}}\0' \
        "$id" "$value" >&4;;
    *'Runtime.evaluate'*'aria-labelledby'*)
      row="message-$page"
      value='[{"id":"'"$row"'","subject":"Page '"$page"'",'
      value+='"addresses":"jobs@example.com","unread":false}]'
      printf '{"id":%s,"result":{"result":{"type":"object","value":%s}}}\0' \
        "$id" "$value" >&4;;
    *'Runtime.evaluate'*)
      host='mail.proton.me'
      if [ "$clicked" -eq 1 ] && [ '__ORIGIN_AFTER_MAIL__' = false ]; then
        host='account.proton.me'
      fi
      value='{"protocol":"https:","hostname":"'"$host"'","port":""}'
      printf '{"id":%s,"result":{"result":{"type":"object","value":%s}}}\0' \
        "$id" "$value" >&4;;
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
"#
}

fn fake(root: &Path, scenario: Scenario) -> PathBuf {
    let script = root.join("fake-browser");
    let body = fake_template()
        .replace("__BEFORE_DISABLED__", scenario.before_next_disabled.shell())
        .replace("__CLICK_DISABLED__", scenario.click_disabled.shell())
        .replace("__CURRENT_VISIBLE__", scenario.current_page_visible.shell())
        .replace(
            "__DESTINATION_PAGE__",
            &scenario.destination_page.to_string(),
        )
        .replace("__MODE_AFTER__", scenario.mode_after_click.shell())
        .replace(
            "__ORIGIN_AFTER_MAIL__",
            scenario.origin_after_click_is_mail.shell(),
        )
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
    scenario: Scenario,
    inspect: impl FnOnce(&mut ManagedBrowser, &ProviderPage) -> T,
) -> T {
    let root = test_root(label);
    fs::create_dir_all(&root).expect("create synthetic root");
    let fake = fake(&root, scenario);
    let browser_plan = plan(&root, &fake);
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&browser_plan).expect("launch driver");
    let page = managed.provider_page().expect("discover Mail page");
    let result = inspect(&mut managed, &page);
    drop(managed);
    fs::remove_dir_all(root).expect("remove synthetic root");
    result
}

#[test]
fn enabled_next_advances_exactly_one_message_page() {
    let snapshot = with_browser(
        "success",
        SUCCESS,
        ManagedBrowser::read_next_visible_message_page,
    )
    .expect("advance to next message page");
    assert_eq!(snapshot.current_page(), Some(2));
    assert_eq!(snapshot.next_page(), NextPageControl::Disabled);
    assert_eq!(snapshot.rows()[0].id(), "message-2");
    assert_eq!(snapshot.rows()[0].subject(), "Page 2");
}

#[test]
fn disabled_next_refuses_navigation() {
    let scenario = Scenario {
        before_next_disabled: BinaryState::Yes,
        ..SUCCESS
    };
    let error = with_browser(
        "disabled",
        scenario,
        ManagedBrowser::read_next_visible_message_page,
    )
    .expect_err("disabled next must not be clicked");
    assert_eq!(error, BrowserDriverError::MailboxNextPageUnavailable);
}

#[test]
fn control_change_between_snapshot_and_click_fails_closed() {
    let scenario = Scenario {
        click_disabled: BinaryState::Yes,
        ..SUCCESS
    };
    let error = with_browser(
        "control-change",
        scenario,
        ManagedBrowser::read_next_visible_message_page,
    )
    .expect_err("changed next control must fail closed");
    assert_eq!(error, BrowserDriverError::MailboxPaginationChanged);
}

#[test]
fn unexpected_page_jump_fails_closed() {
    let scenario = Scenario {
        destination_page: 3,
        ..SUCCESS
    };
    let error = with_browser(
        "page-jump",
        scenario,
        ManagedBrowser::read_next_visible_message_page,
    )
    .expect_err("page jump must fail closed");
    assert_eq!(error, BrowserDriverError::MailboxPaginationChanged);
}

#[test]
fn message_mode_drift_after_click_fails_closed() {
    let scenario = Scenario {
        mode_after_click: BinaryState::No,
        ..SUCCESS
    };
    let error = with_browser(
        "mode-drift",
        scenario,
        ManagedBrowser::read_next_visible_message_page,
    )
    .expect_err("mode drift must fail closed");
    assert_eq!(error, BrowserDriverError::MailboxModeChanged);
}

#[test]
fn missing_current_page_refuses_navigation() {
    let scenario = Scenario {
        current_page_visible: BinaryState::No,
        ..SUCCESS
    };
    let error = with_browser(
        "missing-current",
        scenario,
        ManagedBrowser::read_next_visible_message_page,
    )
    .expect_err("current page evidence is required");
    assert_eq!(error, BrowserDriverError::MailboxPaginationIncompatible);
}

#[test]
fn origin_drift_after_click_fails_closed() {
    let scenario = Scenario {
        origin_after_click_is_mail: BinaryState::No,
        ..SUCCESS
    };
    let error = with_browser(
        "origin-drift",
        scenario,
        ManagedBrowser::read_next_visible_message_page,
    )
    .expect_err("origin drift after click must fail closed");
    assert_eq!(
        error,
        BrowserDriverError::OriginDrift {
            expected: PageOrigin::ProtonMail,
            observed: PageOrigin::ProtonAccount,
        }
    );
}
