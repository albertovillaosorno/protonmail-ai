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

use mail_web_adapter::MessageListReconciliationError;
use mail_web_adapter::MessageListResponseError;
use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};
use mail_web_adapter::{PageOrigin, ProviderPage};

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

#[expect(
    clippy::fn_params_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "synthetic CDP transcript toggles independent failure scenarios"
)]
fn fake_network_browser(
    root: &Path,
    base64_encoded: bool,
    visible_id: &str,
    multi_batch: bool,
    mismatched_anchor: bool,
    third_batch_on_disable: bool,
    continuation_anchor_id: &str,
    initial_page: &str,
) -> PathBuf {
    let script = root.join("fake-network-browser");
    let log = root.join("network-log.txt");
    let encoded = if base64_encoded { "true" } else { "false" };
    let limit = if multi_batch { "1" } else { "50" };
    let third_batch = if third_batch_on_disable {
        "true"
    } else {
        "false"
    };
    let anchor = if mismatched_anchor {
        "1790847000"
    } else {
        "1790848000"
    };
    let row_ids = if multi_batch {
        "[\"m-1\",\"m-2\"]"
    } else {
        "[\"__VISIBLE_ID__\"]"
    };
    let rows = if multi_batch {
        concat!(
            "[{\"id\":\"m-1\",\"subject\":\"Rendered one\",",
            "\"addresses\":\"one@example.test\",\"unread\":false},",
            "{\"id\":\"m-2\",\"subject\":\"Rendered two\",",
            "\"addresses\":\"two@example.test\",\"unread\":false}]",
        )
    } else {
        concat!(
            "[{\"id\":\"__VISIBLE_ID__\",",
            "\"subject\":\"Rendered subject\",",
            "\"addresses\":\"synthetic@example.test\",",
            "\"unread\":false}]",
        )
    };
    let template = r#"#!/usr/bin/env bash
set -eu
while IFS= read -r -d '' message <&3; do
  id=$(printf '%s' "$message" |
    sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$message" in
    *'Browser.getVersion'*)
      printf '{"id":%s,"result":{"product":"FakeChrome/1"}}\0' \
        "$id" >&4;;
    *'Target.getTargets'*)
      target='[{"targetId":"page-1","type":"page",'
      target+='"url":"https://mail.proton.me/u/0/sent"}]'
      printf '{"id":%s,"result":{"targetInfos":%s}}\0' \
        "$id" "$target" >&4;;
    *'Target.attachToTarget'*)
      printf '{"id":%s,"result":{"sessionId":"session-1"}}\0' \
        "$id" >&4;;
    *'Runtime.evaluate'*'forcedMessageRoute'*)
      value='{"forcedMessageRoute":true,"activeSearch":false}'
      printf '{"id":%s,"result":{"result":{"value":%s}}}\0' \
        "$id" "$value" >&4;;
    *'Runtime.evaluate'*'message-list-loading'*)
      value='{"loading":false,"loaded":true,"rowIds":__ROW_IDS__,'
      value+='"skeletonCount":0,"emptyMarker":false,'
      value+='"nextPresent":false,"nextDisabled":null,'
      value+='"currentTestId":"pagination-row:go-to-page-1"}'
      printf '{"id":%s,"result":{"result":{"value":%s}}}\0' \
        "$id" "$value" >&4;;
    *'Runtime.evaluate'*'aria-labelledby'*)
      value='__ROWS__'
      printf '{"id":%s,"result":{"result":{"value":%s}}}\0' \
        "$id" "$value" >&4;;
    *'Runtime.evaluate'*)
      value='{"protocol":"https:",'
      value+='"hostname":"mail.proton.me","port":""}'
      printf '{"id":%s,"result":{"result":{"value":%s}}}\0' \
        "$id" "$value" >&4;;
    *'DOM.getDocument'*)
      printf '{"id":%s,"result":{"root":{"nodeId":1}}}\0' \
        "$id" >&4;;
    *'Accessibility.queryAXTree'*)
      case "$message" in
        *'"role":"navigation"'*|*'"role":"search"'*)
          nodes='[{"ignored":false}]';;
        *'"role":"dialog"'*|*'"role":"alertdialog"'*) nodes='[]';;
        *) exit 91;;
      esac
      printf '{"id":%s,"result":{"nodes":%s}}\0' \
        "$id" "$nodes" >&4;;
    *'Network.enable'*)
      case "$message" in
        *'"maxPostDataSize":0'*'"maxResourceBufferSize":262144'*) ;;
        *) exit 93;;
      esac
      printf 'enable\n' >> '__LOG__'
      printf '{"id":%s,"result":{}}\0' "$id" >&4;;
    *'Page.reload'*)
      printf 'reload\n' >> '__LOG__'
      extra='{"sessionId":"session-1",'
      extra+='"method":"Network.requestWillBeSentExtraInfo","params":{'
      extra+='"requestId":"other","headers":{"Cookie":"secret-cookie"}}}'
      printf '%s\0' "$extra" >&4
      other='{"sessionId":"session-1",'
      other+='"method":"Network.requestWillBeSent","params":{'
      other+='"requestId":"other","request":{"method":"GET",'
      other+='"url":"https://mail.proton.me/api/core/v4/users?secret=query",'
      other+='"headers":{"Authorization":"Bearer secret"}}}}'
      printf '%s\0' "$other" >&4
      request='{"sessionId":"session-1",'
      request+='"method":"Network.requestWillBeSent","params":{'
      request+='"requestId":"list-1","request":{"method":"GET",'
      request+='"url":"https://mail.proton.me/api/mail/v4/messages?'
      request+='Page=__INITIAL_PAGE__&PageSize=__LIMIT__&Limit=__LIMIT__",'
      request+='"headers":{"Authorization":"Bearer secret"}}}}'
      printf '%s\0' "$request" >&4
      response='{"sessionId":"session-1",'
      response+='"method":"Network.responseReceived","params":{'
      response+='"requestId":"list-1","response":{'
      response+='"url":"https://mail.proton.me/api/mail/v4/messages?'
      response+='Page=__INITIAL_PAGE__&PageSize=__LIMIT__&Limit=__LIMIT__",'
      response+='"status":200,"mimeType":"application/json",'
      response+='"headers":{"Set-Cookie":"secret-cookie"}}}}'
      printf '%s\0' "$response" >&4
      finished='{"sessionId":"session-1",'
      finished+='"method":"Network.loadingFinished","params":{'
      finished+='"requestId":"list-1"}}'
      printf '%s\0' "$finished" >&4
      printf '{"id":%s,"result":{}}\0' "$id" >&4;;
    *'Network.getResponseBody'*'"requestId":"list-1"'*)
      printf 'body\n' >> '__LOG__'
      if [ '__MULTI_BATCH__' = 'true' ]; then
        request='{"sessionId":"session-1",'
        request+='"method":"Network.requestWillBeSent","params":{'
        request+='"requestId":"list-2","request":{"method":"GET",'
        request+='"url":"https://mail.proton.me/api/mail/v4/messages?'
        request+='Limit=1&Anchor=__ANCHOR__&AnchorID=__ANCHOR_ID__",'
        request+='"headers":{"Authorization":"Bearer secret"}}}}'
        printf '%s\0' "$request" >&4
        response='{"sessionId":"session-1",'
        response+='"method":"Network.responseReceived","params":{'
        response+='"requestId":"list-2","response":{'
        response+='"url":"https://mail.proton.me/api/mail/v4/messages?'
        response+='Limit=1&Anchor=__ANCHOR__&AnchorID=__ANCHOR_ID__",'
        response+='"status":200,"mimeType":"application/json"}}}'
        printf '%s\0' "$response" >&4
        finished='{"sessionId":"session-1",'
        finished+='"method":"Network.loadingFinished","params":{'
        finished+='"requestId":"list-2"}}'
        printf '%s\0' "$finished" >&4
      fi
      body='{\"Code\":1000,\"Total\":__TOTAL__,\"Messages\":[{'
      body+='\"ID\":\"m-1\",\"Time\":1790848000,\"Order\":9,'
      body+='\"Subject\":\"secret subject\"}]}'
      prefix='{"id":'"$id"',"result":{"body":"'
      suffix='","base64Encoded":__ENCODED__}}'
      printf '%s%s%s\0' "$prefix" "$body" "$suffix" >&4;;
    *'Network.getResponseBody'*'"requestId":"list-2"'*)
      printf 'body\n' >> '__LOG__'
      body='{\"Code\":1000,\"Total\":2,\"Messages\":[{'
      body+='\"ID\":\"m-2\",\"Time\":1790847999,\"Order\":8}]}'
      prefix='{"id":'"$id"',"result":{"body":"'
      suffix='","base64Encoded":false}}'
      printf '%s%s%s\0' "$prefix" "$body" "$suffix" >&4;;
    *'Network.disable'*)
      printf 'disable\n' >> '__LOG__'
      if [ '__THIRD_BATCH__' = 'true' ]; then
        request='{"sessionId":"session-1",'
        request+='"method":"Network.requestWillBeSent","params":{'
        request+='"requestId":"list-3","request":{"method":"GET",'
        request+='"url":"https://mail.proton.me/api/mail/v4/messages?'
        request+='Limit=1&Anchor=1790847999&AnchorID=m-2"}}}'
        printf '%s\0' "$request" >&4
      fi
      printf '{"id":%s,"result":{}}\0' "$id" >&4;;
    *'Target.detachFromTarget'*)
      printf '{"id":%s,"result":{}}\0' "$id" >&4;;
    *) exit 92;;
  esac
done
"#;
    let total = if multi_batch { "2" } else { "1" };
    let body = template
        .replace("__LOG__", &log.display().to_string())
        .replace("__ENCODED__", encoded)
        .replace(
            "__MULTI_BATCH__",
            if multi_batch { "true" } else { "false" },
        )
        .replace("__THIRD_BATCH__", third_batch)
        .replace("__LIMIT__", limit)
        .replace("__ANCHOR__", anchor)
        .replace("__ANCHOR_ID__", continuation_anchor_id)
        .replace("__INITIAL_PAGE__", initial_page)
        .replace("__TOTAL__", total)
        .replace("__ROW_IDS__", row_ids)
        .replace("__ROWS__", rows)
        .replace("__VISIBLE_ID__", visible_id);
    fs::write(&script, body).expect("write fake network browser");
    let permissions = fs::Permissions::from_mode(0o700);
    let permission_result = fs::set_permissions(&script, permissions);
    permission_result.expect("chmod fake network browser");
    script
}

#[expect(
    clippy::fn_params_excessive_bools,
    clippy::too_many_arguments,
    reason = "test helper forwards independent synthetic CDP scenarios"
)]
fn with_network_browser<T>(
    label: &str,
    base64_encoded: bool,
    visible_id: &str,
    multi_batch: bool,
    mismatched_anchor: bool,
    third_batch_on_disable: bool,
    continuation_anchor_id: &str,
    initial_page: &str,
    inspect: impl FnOnce(&mut ManagedBrowser, &ProviderPage) -> T,
) -> (T, String) {
    let root = test_root(label);
    fs::create_dir_all(&root).expect("create synthetic network root");
    let browser = fake_network_browser(
        &root,
        base64_encoded,
        visible_id,
        multi_batch,
        mismatched_anchor,
        third_batch_on_disable,
        continuation_anchor_id,
        initial_page,
    );
    let browser_plan = plan(&root, &browser);
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&browser_plan).expect("launch network driver");
    let page = managed.provider_page().expect("discover network Mail page");
    let result = inspect(&mut managed, &page);
    drop(managed);
    // jig-ignore-next-line: canonical rustfmt line.
    let log = fs::read_to_string(root.join("network-log.txt")).unwrap_or_default();
    cleanup(&root);
    (result, log)
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
fn exact_message_list_network_body_is_projected_and_network_is_disabled() {
    let (response, log) = with_network_browser(
        "network-list",
        false,
        "m-1",
        false,
        false,
        false,
        "m-1",
        "0",
        ManagedBrowser::observe_message_list_response,
    );
    let response = response.expect("observe exact message-list response");
    assert_eq!(response.total(), 1);
    assert_eq!(response.messages().len(), 1);
    assert_eq!(response.messages()[0].id(), "m-1");
    assert_eq!(response.messages()[0].time(), 1_790_848_000);
    assert_eq!(response.messages()[0].order(), 9);
    let debug = format!("{response:?}");
    assert!(!debug.contains("secret"));
    assert_eq!(log, "enable\nreload\nbody\ndisable\n");
}

#[test]
fn network_metadata_reconciles_to_same_session_stable_rows() {
    let (metadata, log) = with_network_browser(
        "network-reconciled",
        false,
        "m-1",
        false,
        false,
        false,
        "m-1",
        "0",
        ManagedBrowser::observe_visible_message_metadata,
    );
    // jig-ignore-next-line: canonical rustfmt line.
    let metadata = metadata.expect("reconcile captured metadata to stable rows");
    assert_eq!(metadata.messages().len(), 1);
    assert_eq!(metadata.messages()[0].id(), "m-1");
    assert_eq!(metadata.messages()[0].time(), 1_790_848_000);
    assert_eq!(log, "enable\nreload\nbody\ndisable\n");
}

#[test]
fn singular_network_observation_rejects_two_batch_page_after_disable() {
    let (result, log) = with_network_browser(
        "network-multi-singular",
        false,
        "m-1",
        true,
        false,
        false,
        "m-1",
        "0",
        ManagedBrowser::observe_message_list_response,
    );
    assert_eq!(
        result,
        Err(BrowserDriverError::MessageListResponseAmbiguous)
    );
    assert_eq!(log, "enable\nreload\nbody\nbody\ndisable\n");
}

#[test]
fn mismatched_continuation_anchor_id_fails_before_second_body_fetch() {
    let (result, log) = with_network_browser(
        "network-anchor-id-mismatch",
        false,
        "m-1",
        true,
        false,
        false,
        "wrong-id",
        "0",
        ManagedBrowser::observe_visible_message_metadata,
    );
    assert_eq!(
        result,
        Err(BrowserDriverError::MessageListBatchIncompatible)
    );
    assert_eq!(log, "enable\nreload\nbody\ndisable\n");
}

#[test]
fn mismatched_continuation_anchor_fails_before_second_body_fetch() {
    let (result, log) = with_network_browser(
        "network-anchor-mismatch",
        false,
        "m-1",
        true,
        true,
        false,
        "m-1",
        "0",
        ManagedBrowser::observe_visible_message_metadata,
    );
    assert_eq!(
        result,
        Err(BrowserDriverError::MessageListBatchIncompatible)
    );
    assert_eq!(log, "enable\nreload\nbody\ndisable\n");
}

#[test]
fn third_batch_started_during_disable_fails_closed() {
    let (result, log) = with_network_browser(
        "network-third-batch",
        false,
        "m-1",
        true,
        false,
        true,
        "m-1",
        "0",
        ManagedBrowser::observe_visible_message_metadata,
    );
    assert_eq!(
        result,
        Err(BrowserDriverError::MessageListResponseAmbiguous)
    );
    assert_eq!(log, "enable\nreload\nbody\nbody\ndisable\n");
}

#[test]
fn continuation_events_during_first_body_fetch_are_reconciled() {
    let (metadata, log) = with_network_browser(
        "network-multi-batch",
        false,
        "m-1",
        true,
        false,
        false,
        "m-1",
        "0",
        ManagedBrowser::observe_visible_message_metadata,
    );
    let metadata = metadata.expect("reconcile two observed batches");
    assert_eq!(metadata.messages().len(), 2);
    assert_eq!(metadata.messages()[0].id(), "m-1");
    assert_eq!(metadata.messages()[0].time(), 1_790_848_000);
    assert_eq!(metadata.messages()[1].id(), "m-2");
    assert_eq!(metadata.messages()[1].time(), 1_790_847_999);
    assert_eq!(log, "enable\nreload\nbody\nbody\ndisable\n");
}

#[test]
fn network_metadata_rejects_request_page_mismatch() {
    let (result, log) = with_network_browser(
        "network-page-mismatch",
        false,
        "m-1",
        false,
        false,
        false,
        "m-1",
        "1",
        ManagedBrowser::observe_visible_message_metadata,
    );
    assert_eq!(result, Err(BrowserDriverError::MessageListPageMismatch));
    assert_eq!(log, "enable\nreload\nbody\ndisable\n");
}

#[test]
fn network_metadata_rejects_stable_row_without_machine_coverage() {
    let (result, log) = with_network_browser(
        "network-missing-visible",
        false,
        "visible-only",
        false,
        false,
        false,
        "m-1",
        "0",
        ManagedBrowser::observe_visible_message_metadata,
    );
    assert_eq!(
        result,
        Err(BrowserDriverError::MessageListReconciliation(
            MessageListReconciliationError::MissingVisibleMessage
        ))
    );
    assert_eq!(log, "enable\nreload\nbody\ndisable\n");
}

#[test]
fn encoded_message_list_body_fails_closed_after_network_disable() {
    let (result, log) = with_network_browser(
        "network-encoded",
        true,
        "m-1",
        false,
        false,
        false,
        "m-1",
        "0",
        ManagedBrowser::observe_message_list_response,
    );
    assert_eq!(
        result,
        Err(BrowserDriverError::MessageListResponse(
            MessageListResponseError::UnsupportedEncoding
        ))
    );
    assert_eq!(log, "enable\nreload\nbody\ndisable\n");
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
