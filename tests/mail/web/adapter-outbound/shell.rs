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
//   - Synthetic CDP evidence for translation-free Mail-shell inspection.
// - Must-Not:
//   - Launch real Chrome, access an account, or expose accessible-name content.
// - Allows:
//   - Emulate DOM root and role-filtered Accessibility query responses.
// - Split-When:
//   - Composer semantics require their own independent page-state fixtures.
// - Merge-When:
//   - A broader web-adapter semantic suite owns the same shell invariants.
// - Summary:
//   - Proves Mail readiness uses structural roles and fails closed on drift.
// - Description:
//   - Exercises landmarks, blockers, malformed AX output, and origin drift.
// - Usage:
//   - Run through the `mail_web_adapter` integration-test target.
// - Defaults:
//   - Synthetic local process and filesystem state only.
//

//! Proton Mail shell accessibility-query regression tests.

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process;

use mail_web_adapter::PageOrigin;
use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};

const VISIBLE: &str =
    // jig-ignore-next-line: indivisible synthetic AX privacy fixture.
    r#"[{"ignored":false,"name":{"value":"no-leer"},"value":{"value":"secreto"}}]"#;
const IGNORED: &str = r#"[{"ignored":true,"name":{"value":"no-leer"}}]"#;
const ABSENT: &str = "[]";

struct RoleFixture<'fixture> {
    alertdialog: &'fixture str,
    dialog: &'fixture str,
    navigation: &'fixture str,
    search: &'fixture str,
}

impl RoleFixture<'_> {
    const fn ready() -> Self {
        Self {
            alertdialog: ABSENT,
            dialog: ABSENT,
            navigation: VISIBLE,
            search: VISIBLE,
        }
    }
}

fn test_root(label: &str) -> PathBuf {
    let name = format!("protonmail-ai-shell-{label}-{}", process::id());
    env::temp_dir().join(name)
}

fn fake_browser(
    root: &Path,
    target_url: &str,
    runtime_host: &str,
    runtime_host_after: &str,
    roles: &RoleFixture<'_>,
) -> PathBuf {
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
      target='[{{"targetId":"page-1","type":"page","url":"{target_url}"}}]'
      printf '{{"id":%s,"result":{{"targetInfos":%s}}}}\0' "$id" "$target" >&4;;
    *'Target.attachToTarget'*)
      printf '{{"id":%s,"result":{{"sessionId":"session-1"}}}}\0' "$id" >&4;;
    *'Runtime.evaluate'*)
      origin_probe=$((origin_probe + 1))
      host='{runtime_host}'
      if [ "$origin_probe" -gt 1 ]; then host='{runtime_host_after}'; fi
      response='{{"id":'"$id"',"result":{{"result":{{"type":"object",'
      response+='"value":{{"protocol":"https:",'
      response+='"hostname":"'"$host"'",'
      response+='"port":""}}}}}}}}'
      printf '%s\0' "$response" >&4;;
    *'DOM.getDocument'*)
      printf '{{"id":%s,"result":{{"root":{{"nodeId":1}}}}}}\0' "$id" >&4;;
    *'Accessibility.queryAXTree'*)
      case "$message" in
        *'"role":"navigation"'*) nodes='{navigation}';;
        *'"role":"search"'*) nodes='{search}';;
        *'"role":"alertdialog"'*) nodes='{alertdialog}';;
        *'"role":"dialog"'*) nodes='{dialog}';;
        *) exit 91;;
      esac
      printf '{{"id":%s,"result":{{"nodes":%s}}}}\0' "$id" "$nodes" >&4;;
    *'Target.detachFromTarget'*)
      printf '{{"id":%s,"result":{{}}}}\0' "$id" >&4;;
    *) exit 92;;
  esac
done
"#,
        target_url = target_url,
        runtime_host = runtime_host,
        runtime_host_after = runtime_host_after,
        navigation = roles.navigation,
        search = roles.search,
        dialog = roles.dialog,
        alertdialog = roles.alertdialog,
    );
    fs::write(&script, body).expect("write fake browser");
    // jig-ignore-next-line: canonical rustfmt line.
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).expect("chmod fake browser");
    script
}

fn plan(root: &Path, browser: &Path) -> ManagedBrowserPlan {
    ManagedBrowserPlan::under_data_home(
        browser.to_str().expect("browser path must be UTF-8"),
        &root.join("data"),
    )
    .expect("build managed browser plan")
}

fn inspect_with_hosts(
    label: &str,
    target_url: &str,
    runtime_host: &str,
    runtime_host_after: &str,
    roles: &RoleFixture<'_>,
) -> Result<mail_web_adapter::MailShellEvidence, BrowserDriverError> {
    let root = test_root(label);
    fs::create_dir_all(&root).expect("create synthetic root");
    // jig-ignore-next-line: canonical rustfmt line.
    let browser = fake_browser(&root, target_url, runtime_host, runtime_host_after, roles);
    let browser_plan = plan(&root, &browser);
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&browser_plan).expect("launch fake driver");
    let page = managed.provider_page().expect("discover provider page");
    let result = managed.inspect_mail_shell(&page);
    drop(managed);
    fs::remove_dir_all(root).expect("remove synthetic root");
    result
}

fn inspect(
    label: &str,
    target_url: &str,
    runtime_host: &str,
    roles: &RoleFixture<'_>,
) -> Result<mail_web_adapter::MailShellEvidence, BrowserDriverError> {
    inspect_with_hosts(label, target_url, runtime_host, runtime_host, roles)
}

#[test]
fn structural_roles_make_mail_shell_ready_without_using_names() {
    let evidence = inspect(
        "ready",
        "https://mail.proton.me/u/0/inbox",
        "mail.proton.me",
        &RoleFixture::ready(),
    )
    .expect("inspect ready Mail shell");
    assert!(evidence.navigation_visible());
    assert!(evidence.search_visible());
    assert!(!evidence.modal_blocker_visible());
    assert!(evidence.ready());
    let diagnostic = format!("{evidence:?}");
    assert!(!diagnostic.contains("no-leer"));
    assert!(!diagnostic.contains("secreto"));
}

#[test]
fn required_mail_shell_rejects_missing_landmark() {
    let roles = RoleFixture {
        search: IGNORED,
        ..RoleFixture::ready()
    };
    let root = test_root("required-shell");
    fs::create_dir_all(&root).expect("create synthetic root");
    let browser = fake_browser(
        &root,
        "https://mail.proton.me/u/0/inbox",
        "mail.proton.me",
        "mail.proton.me",
        &roles,
    );
    let browser_plan = plan(&root, &browser);
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&browser_plan).expect("launch fake driver");
    let page = managed.provider_page().expect("discover Mail page");
    let error = managed
        .require_mail_shell(&page)
        .expect_err("missing search landmark must block mailbox workflows");
    assert_eq!(error, BrowserDriverError::MailShellNotReady);
    drop(managed);
    fs::remove_dir_all(root).expect("remove synthetic root");
}

#[test]
fn ignored_search_landmark_fails_closed() {
    let roles = RoleFixture {
        search: IGNORED,
        ..RoleFixture::ready()
    };
    let evidence = inspect(
        "ignored-search",
        "https://mail.proton.me/u/0/inbox",
        "mail.proton.me",
        &roles,
    )
    .expect("inspect shell with ignored search");
    assert!(!evidence.search_visible());
    assert!(!evidence.ready());
}

#[test]
fn visible_dialog_roles_block_readiness() {
    for (label, roles) in [
        (
            "dialog",
            RoleFixture {
                dialog: VISIBLE,
                ..RoleFixture::ready()
            },
        ),
        (
            "alertdialog",
            RoleFixture {
                alertdialog: VISIBLE,
                ..RoleFixture::ready()
            },
        ),
    ] {
        let evidence = inspect(
            label,
            "https://mail.proton.me/u/0/inbox",
            "mail.proton.me",
            &roles,
        )
        .expect("inspect blocked shell");
        assert!(evidence.modal_blocker_visible());
        assert!(!evidence.ready());
    }
}

#[test]
fn malformed_role_query_is_protocol_failure() {
    let roles = RoleFixture {
        search: "null",
        ..RoleFixture::ready()
    };
    let error = inspect(
        "malformed",
        "https://mail.proton.me/u/0/inbox",
        "mail.proton.me",
        &roles,
    )
    .expect_err("malformed AX response must fail closed");
    assert_eq!(error, BrowserDriverError::Protocol);
}

#[test]
fn account_origin_is_not_mail_shell() {
    let error = inspect(
        "account",
        "https://account.proton.me/login",
        "account.proton.me",
        &RoleFixture::ready(),
    )
    .expect_err("Account page must not be inspected as Mail");
    assert_eq!(error, BrowserDriverError::MailOriginRequired);
}

#[test]
fn origin_drift_precedes_accessibility_queries() {
    let error = inspect(
        "origin-drift",
        "https://mail.proton.me/u/0/inbox",
        "account.proton.me",
        &RoleFixture::ready(),
    )
    .expect_err("origin drift must fail before shell evidence");
    assert_eq!(
        error,
        BrowserDriverError::OriginDrift {
            expected: PageOrigin::ProtonMail,
            observed: PageOrigin::ProtonAccount,
        }
    );
}

#[test]
fn origin_drift_after_accessibility_queries_fails_closed() {
    let error = inspect_with_hosts(
        "late-origin-drift",
        "https://mail.proton.me/u/0/inbox",
        "mail.proton.me",
        "account.proton.me",
        &RoleFixture::ready(),
    )
    .expect_err("late origin drift must invalidate ready AX evidence");
    assert_eq!(
        error,
        BrowserDriverError::OriginDrift {
            expected: PageOrigin::ProtonMail,
            observed: PageOrigin::ProtonAccount,
        }
    );
}
