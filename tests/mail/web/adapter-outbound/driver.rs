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
//   - Synthetic process evidence for the private Chromium DevTools pipe.
// - Must-Not:
//   - Launch real Chrome, access a live account, or read browser session data.
// - Allows:
//   - Emulate FD 3/4 ASCIIZ CDP responses with an isolated fake executable.
// - Split-When:
//   - Live opt-in browser acceptance gains separate ownership.
// - Merge-When:
//   - Browser lifecycle and semantic page fixtures share one acceptance suite.
// - Summary:
//   - Proves the managed driver uses a private pipe and fail-closed origins.
// - Description:
//   - Exercises handshake, target discovery, ambiguity, and spoof rejection.
// - Usage:
//   - Run through the `mail_web_adapter` integration-test target.
// - Defaults:
//   - Synthetic local process and filesystem state only.
//

//! Private DevTools-pipe driver regression tests.

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process;

use mail_web_adapter::PageOrigin;
use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};

fn test_root(label: &str) -> PathBuf {
    let name = format!("protonmail-ai-driver-{label}-{}", process::id());
    env::temp_dir().join(name)
}

// jig-ignore-next-line: canonical rustfmt line.
fn fake_browser(root: &Path, target_infos: &str, runtime_host: &str) -> PathBuf {
    let script = root.join("fake-browser");
    let args = root.join("browser-args.txt");
    let body = format!(
        r#"#!/usr/bin/env bash
set -eu
printf '%s\n' "$@" > '{args}'
while IFS= read -r -d '' message <&3; do
  case "$message" in
    *'Browser.getVersion'*)
      printf '%s\0' '{{"id":1,"result":{{"product":"FakeChrome/1"}}}}' >&4;;
    *'Target.getTargets'*)
      printf '%s\0' '{{"id":2,"result":{{"targetInfos":{target_infos}}}}}' >&4;;
    *'Target.attachToTarget'*)
      printf '%s\0' '{{"id":3,"result":{{"sessionId":"session-1"}}}}' >&4;;
    *'Runtime.evaluate'*)
      response='{{"id":4,"result":{{"result":{{"type":"object",'
      response+='"value":{{"protocol":"https:",'
      response+='"hostname":"{runtime_host}","port":""}}}}}}}}'
      printf '%s\0' "$response" >&4;;
    *'Target.detachFromTarget'*)
      printf '%s\0' '{{"id":5,"result":{{}}}}' >&4;;
  esac
done
"#,
        args = args.display(),
        target_infos = target_infos,
        runtime_host = runtime_host,
    );
    fs::write(&script, body).expect("write fake browser");
    let permissions = fs::Permissions::from_mode(0o700);
    fs::set_permissions(&script, permissions).expect("chmod fake browser");
    script
}

fn plan(root: &Path, browser: &Path) -> ManagedBrowserPlan {
    let data_home = root.join("data");
    ManagedBrowserPlan::under_data_home(
        browser.to_str().expect("browser path must be UTF-8"),
        &data_home,
    )
    .expect("build managed browser plan")
}

fn cleanup(root: &Path) {
    fs::remove_dir_all(root).expect("remove synthetic driver tree");
}

#[test]
fn managed_browser_uses_private_pipe_and_dedicated_profile() {
    let root = test_root("mail");
    fs::create_dir_all(&root).expect("create synthetic root");
    let targets = concat!(
        "[{\"targetId\":\"page-1\",\"type\":\"page\",",
        "\"url\":\"https://mail.proton.me/u/0/inbox\"}]"
    );
    let browser = fake_browser(&root, targets, "mail.proton.me");
    let plan = plan(&root, &browser);
    let expected_profile = plan.profile_dir().to_path_buf();
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch fake driver");

    let page = managed.provider_page().expect("discover Proton Mail page");
    assert_eq!(page.origin(), PageOrigin::ProtonMail);
    assert_eq!(
        managed
            .verify_provider_origin(&page)
            .expect("verify live origin"),
        PageOrigin::ProtonMail
    );
    // jig-ignore-next-line: canonical rustfmt line.
    let args = fs::read_to_string(root.join("browser-args.txt")).expect("read browser args");
    let expected = format!("--user-data-dir={}", expected_profile.display());
    assert!(args.lines().any(|line| line == expected));
    assert!(args.lines().any(|line| line == "--remote-debugging-pipe"));
    assert!(!args.contains("remote-debugging-port"));
    assert!(args.lines().any(|line| line == "https://mail.proton.me/"));

    drop(managed);
    cleanup(&root);
}

#[test]
fn provider_account_origin_is_not_authenticated_mail() {
    let root = test_root("account");
    fs::create_dir_all(&root).expect("create synthetic root");
    let targets = concat!(
        "[{\"targetId\":\"page-1\",\"type\":\"page\",",
        "\"url\":\"https://account.proton.me/login\"}]"
    );
    let browser = fake_browser(&root, targets, "account.proton.me");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan(&root, &browser)).expect("launch fake driver");
    let page = managed.provider_page().expect("discover account page");
    assert_eq!(page.origin(), PageOrigin::ProtonAccount);
    assert_eq!(
        managed
            .verify_provider_origin(&page)
            .expect("verify account origin"),
        PageOrigin::ProtonAccount
    );
    drop(managed);
    cleanup(&root);
}

#[test]
fn lookalike_provider_host_is_ignored() {
    let root = test_root("spoof");
    fs::create_dir_all(&root).expect("create synthetic root");
    let targets = concat!(
        "[{\"targetId\":\"page-1\",\"type\":\"page\",",
        "\"url\":\"https://mail.proton.me.evil.example/inbox\"}]"
    );
    let browser = fake_browser(&root, targets, "mail.proton.me");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan(&root, &browser)).expect("launch fake driver");
    let error = managed
        .provider_page()
        .expect_err("lookalike host must not be a provider page");
    assert_eq!(error, BrowserDriverError::MissingProviderPage);
    drop(managed);
    cleanup(&root);
}

#[test]
fn execution_context_origin_drift_fails_closed() {
    let root = test_root("origin-drift");
    fs::create_dir_all(&root).expect("create synthetic root");
    let targets = concat!(
        "[{\"targetId\":\"page-1\",\"type\":\"page\",",
        "\"url\":\"https://mail.proton.me/u/0/inbox\"}]"
    );
    let browser = fake_browser(&root, targets, "account.proton.me");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan(&root, &browser)).expect("launch fake driver");
    let page = managed.provider_page().expect("discover target page");
    let error = managed
        .verify_provider_origin(&page)
        .expect_err("origin drift must fail closed");
    assert_eq!(
        error,
        BrowserDriverError::OriginDrift {
            expected: PageOrigin::ProtonMail,
            observed: PageOrigin::ProtonAccount,
        }
    );
    drop(managed);
    cleanup(&root);
}

#[test]
fn multiple_provider_pages_fail_closed() {
    let root = test_root("ambiguous");
    fs::create_dir_all(&root).expect("create synthetic root");
    let targets = concat!(
        "[",
        "{\"targetId\":\"mail\",\"type\":\"page\",",
        "\"url\":\"https://mail.proton.me/u/0/inbox\"},",
        "{\"targetId\":\"account\",\"type\":\"page\",",
        "\"url\":\"https://account.proton.me/login\"}",
        "]"
    );
    let browser = fake_browser(&root, targets, "mail.proton.me");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan(&root, &browser)).expect("launch fake driver");
    let error = managed
        .provider_page()
        .expect_err("multiple provider pages must fail closed");
    assert_eq!(error, BrowserDriverError::AmbiguousProviderPages);
    drop(managed);
    cleanup(&root);
}

#[test]
fn opt_in_real_chrome_private_pipe_smoke() {
    let Ok(real_chrome) = env::var("PROTONMAIL_AI_REAL_CHROME") else {
        return;
    };
    let root = test_root("real-chrome");
    fs::create_dir_all(&root).expect("create real Chrome smoke root");
    let wrapper = root.join("headless-chrome");
    let body = concat!(
        "#!/usr/bin/env bash\n",
        "set -eu\n",
        "exec \"$PROTONMAIL_AI_REAL_CHROME\" ",
        "--headless=new --disable-gpu \"$@\"\n"
    );
    fs::write(&wrapper, body).expect("write real Chrome wrapper");
    let permissions = fs::Permissions::from_mode(0o700);
    fs::set_permissions(&wrapper, permissions).expect("chmod Chrome wrapper");
    assert!(!real_chrome.is_empty());

    let plan = plan(&root, &wrapper);
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch real Chrome");
    let page = managed
        .provider_page()
        .expect("discover real provider page");
    assert!(matches!(
        page.origin(),
        PageOrigin::ProtonMail | PageOrigin::ProtonAccount
    ));
    match managed.verify_provider_origin(&page) {
        Ok(origin) => assert_eq!(origin, page.origin()),
        Err(BrowserDriverError::OriginDrift { expected, .. }) => {
            assert_eq!(expected, page.origin());
        }
        Err(error) => panic!("real origin probe failed: {error}"),
    }
    managed.shutdown().expect("cleanly shut down real Chrome");
    cleanup(&root);
}
