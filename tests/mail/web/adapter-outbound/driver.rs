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
use std::io::{self, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process;

use mail_web_adapter::MessageListReconciliationError;
use mail_web_adapter::MessageListResponseError;
use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};
use mail_web_adapter::{PageOrigin, ProviderPage};

const SESSION_EMPTY_REPLY: &str = concat!(
    "      printf '{\"id\":%s,\"sessionId\":\"session-1\",",
    "\"result\":{}}\\0' \"$id\" >&4;;",
);

fn test_root(label: &str) -> PathBuf {
    let name = format!("protonmail-ai-driver-{label}-{}", process::id());
    env::temp_dir().join(name)
}

// Never overwrite an executable inode in place: parallel synthetic browser
// launches can otherwise hit Linux ETXTBSY before Chromium-like CDP starts.
fn install_script(path: &Path, body: impl AsRef<[u8]>) -> io::Result<()> {
    let staged = path.with_extension("staging");
    let mut file = fs::File::create(&staged)?;
    file.write_all(body.as_ref())?;
    file.sync_all()?;
    drop(file);
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o700))?;
    fs::rename(&staged, path)
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
    *'Target.getBrowserContexts'*)
      contexts='{{"id":3,"result":{{"browserContextIds":["other-context-7"],'
      contexts+='"defaultBrowserContextId":"default-profile-123"}}}}'
      printf '%s\0' "$contexts" >&4;;
    *'Target.attachToTarget'*)
      printf '%s\0' '{{"id":3,"result":{{"sessionId":"session-1"}}}}' >&4;;
    *'Runtime.evaluate'*)
      response='{{"id":4,'
      response+='"sessionId":"session-1","result":{{"result":{{"type":"object",'
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
    install_script(&script, body).expect("install fake browser atomically");
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
    initial_total: &str,
    second_time: &str,
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
    let row_ids = "[\"__VISIBLE_ID__\"]";
    let rows = concat!(
        "[{\"id\":\"__VISIBLE_ID__\",",
        "\"subject\":\"Rendered subject\",",
        "\"addresses\":\"synthetic@example.test\",",
        "\"unread\":false}]",
    );
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
      reply_format='{"id":%s,"sessionId":"session-1",'
      reply_format+='"result":{"result":{"value":%s}}}\0'
      printf "$reply_format" \
        "$id" "$value" >&4;;
    *'Runtime.evaluate'*'aria-labelledby'*)
      value='__ROWS__'
      reply_format='{"id":%s,"sessionId":"session-1",'
      reply_format+='"result":{"result":{"value":%s}}}\0'
      printf "$reply_format" \
        "$id" "$value" >&4;;
    *'Runtime.evaluate'*'message-list-loading'*)
      value='{"loading":false,"loaded":true,"rowIds":__ROW_IDS__,'
      value+='"skeletonCount":0,"emptyMarker":false,'
      value+='"nextPresent":false,"nextDisabled":null,'
      value+='"currentTestId":"pagination-row:go-to-page-1"}'
      reply_format='{"id":%s,"sessionId":"session-1",'
      reply_format+='"result":{"result":{"value":%s}}}\0'
      printf "$reply_format" \
        "$id" "$value" >&4;;
    *'Runtime.evaluate'*)
      value='{"protocol":"https:",'
      value+='"hostname":"mail.proton.me","port":""}'
      reply_format='{"id":%s,"sessionId":"session-1",'
      reply_format+='"result":{"result":{"value":%s}}}\0'
      printf "$reply_format" \
        "$id" "$value" >&4;;
    *'DOM.getDocument'*)
      reply_format='{"id":%s,"sessionId":"session-1",'
      # jig-ignore-next-line: indivisible synthetic CDP document root.
      reply_format+='"result":{"root":{"nodeId":1,"backendNodeId":2,"nodeType":9,"nodeName":"\u0023document","localName":"","nodeValue":""}}}\0'
      printf "$reply_format" \
        "$id" >&4;;
    *'Accessibility.queryAXTree'*)
      case "$message" in
        *'"role":"navigation"'*|*'"role":"search"'*)
          # jig-ignore-next-line: indivisible synthetic CDP AXNode fixture.
          nodes='[{"ignored":false,"nodeId":"ax-__AX_ROLE__","role":{"type":"role","value":"__AX_ROLE__"}}]';;
        *'"role":"dialog"'*|*'"role":"alertdialog"'*) nodes='[]';;
        *) exit 91;;
      esac
      # QueryAXTree commands carry one exact, reviewed role filter.
      requested_role=$(printf '%s' "$message" |
        sed -n 's/.*"role":"\([^"]*\)".*/\1/p')
      [ -n "$requested_role" ] || exit 91
      nodes=$(printf '%s' "$nodes" | sed "s/__AX_ROLE__/$requested_role/g")
      printf '{"id":%s,"sessionId":"session-1","result":{"nodes":%s}}\0' \
        "$id" "$nodes" >&4;;
    *'Network.enable'*)
      case "$message" in
        *'"maxPostDataSize":0'*'"maxResourceBufferSize":262144'*) ;;
        *) exit 93;;
      esac
      printf 'enable\n' >> '__LOG__'
      printf '{"id":%s,"sessionId":"session-1","result":{}}\0' "$id" >&4;;
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
      request+='Page=__INITIAL_PAGE__&PageSize=__LIMIT__&Limit=__LIMIT__'
      request+='&Sort=Time&Desc=1",'
      request+='"headers":{"Authorization":"Bearer secret"}}}}'
      printf '%s\0' "$request" >&4
      response='{"sessionId":"session-1",'
      response+='"method":"Network.responseReceived","params":{'
      response+='"requestId":"list-1","response":{'
      response+='"url":"https://mail.proton.me/api/mail/v4/messages?'
      response+='Page=__INITIAL_PAGE__&PageSize=__LIMIT__&Limit=__LIMIT__'
      response+='&Sort=Time&Desc=1",'
      response+='"status":200,"mimeType":"application/json",'
      response+='"headers":{"Set-Cookie":"secret-cookie"}}}}'
      printf '%s\0' "$response" >&4
      finished='{"sessionId":"session-1",'
      finished+='"method":"Network.loadingFinished","params":{'
      finished+='"requestId":"list-1"}}'
      printf '%s\0' "$finished" >&4
      printf '{"id":%s,"sessionId":"session-1","result":{}}\0' "$id" >&4;;
    *'Network.getResponseBody'*'"requestId":"list-1"'*)
      printf 'body\n' >> '__LOG__'
      if [ '__MULTI_BATCH__' = 'true' ]; then
        request='{"sessionId":"session-1",'
        request+='"method":"Network.requestWillBeSent","params":{'
        request+='"requestId":"list-2","request":{"method":"GET",'
        request+='"url":"https://mail.proton.me/api/mail/v4/messages?'
        request+='Limit=1&Anchor=__ANCHOR__&AnchorID=__ANCHOR_ID__'
        request+='&Sort=Time&Desc=1",'
        request+='"headers":{"Authorization":"Bearer secret"}}}}'
        printf '%s\0' "$request" >&4
        response='{"sessionId":"session-1",'
        response+='"method":"Network.responseReceived","params":{'
        response+='"requestId":"list-2","response":{'
        response+='"url":"https://mail.proton.me/api/mail/v4/messages?'
        response+='Limit=1&Anchor=__ANCHOR__&AnchorID=__ANCHOR_ID__'
        response+='&Sort=Time&Desc=1",'
        response+='"status":200,"mimeType":"application/json"}}}'
        printf '%s\0' "$response" >&4
        finished='{"sessionId":"session-1",'
        finished+='"method":"Network.loadingFinished","params":{'
        finished+='"requestId":"list-2"}}'
        printf '%s\0' "$finished" >&4
      fi
      body='{\"Code\":1000,\"Stale\":0,\"Total\":__TOTAL__,\"Messages\":[{'
      body+='\"ID\":\"m-1\",\"Time\":1790848000,\"Order\":9,'
      body+='\"Subject\":\"secret subject\"}]}'
      prefix='{"id":'"$id"',"sessionId":"session-1","result":{"body":"'
      suffix='","base64Encoded":__ENCODED__}}'
      printf '%s%s%s\0' "$prefix" "$body" "$suffix" >&4;;
    *'Network.getResponseBody'*'"requestId":"list-2"'*)
      printf 'body\n' >> '__LOG__'
      body='{\"Code\":1000,\"Stale\":0,\"Total\":2,\"Messages\":[{'
      body+='\"ID\":\"m-2\",\"Time\":__SECOND_TIME__,\"Order\":8}]}'
      prefix='{"id":'"$id"',"sessionId":"session-1","result":{"body":"'
      suffix='","base64Encoded":false}}'
      printf '%s%s%s\0' "$prefix" "$body" "$suffix" >&4;;
    *'Network.disable'*)
      printf 'disable\n' >> '__LOG__'
      if [ '__THIRD_BATCH__' = 'true' ]; then
        request='{"sessionId":"session-1",'
        request+='"method":"Network.requestWillBeSent","params":{'
        request+='"requestId":"list-3","request":{"method":"GET",'
        request+='"url":"https://mail.proton.me/api/mail/v4/messages?'
        request+='Limit=1&Anchor=1790847999&AnchorID=m-2&Sort=Time&Desc=1"}}}'
        printf '%s\0' "$request" >&4
      fi
      printf '{"id":%s,"sessionId":"session-1","result":{}}\0' "$id" >&4;;
    *'Target.detachFromTarget'*)
      printf '{"id":%s,"result":{}}\0' "$id" >&4;;
    *) exit 92;;
  esac
done
"#;
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
        .replace("__SECOND_TIME__", second_time)
        .replace("__TOTAL__", initial_total)
        .replace("__ROW_IDS__", row_ids)
        .replace("__ROWS__", rows)
        .replace("__VISIBLE_ID__", visible_id);
    let installed = install_script(&script, body);
    installed.expect("install fake network browser atomically");
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
    initial_total: &str,
    second_time: &str,
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
        initial_total,
        second_time,
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
    let plan_debug = format!("{plan:?}");
    assert!(!plan_debug.contains(&expected_profile.display().to_string()));
    assert!(!plan_debug.contains(&browser.display().to_string()));
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch fake driver");

    let page = managed.provider_page().expect("discover Proton Mail page");
    assert_eq!(page.origin(), PageOrigin::ProtonMail);
    assert!(!format!("{page:?}").contains("page-1"));
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
    assert!(args.lines().any(|line| line == "--disable-extensions"));
    assert!(args.lines().any(|line| line == "--disable-sync"));
    assert!(!args.contains("remote-debugging-port"));
    assert!(args.lines().any(|line| line == "https://mail.proton.me/"));

    drop(managed);
    cleanup(&root);
}

#[test]
fn event_cursor_scope_rotates_across_managed_browser_restart() {
    use mail_capability_domain::EventCursorBindingError;
    use mail_capability_domain::EventCursorResumeFailure;
    use mail_web_adapter::WebEventCursorCodecError;

    let root = test_root("event-generation");
    fs::create_dir_all(&root).expect("create synthetic generation root");
    let targets = concat!(
        "[{\"targetId\":\"page-1\",\"type\":\"page\",",
        "\"url\":\"https://mail.proton.me/u/0/inbox\"}]"
    );
    let browser = fake_browser(&root, targets, "mail.proton.me");
    let browser_plan = plan(&root, &browser);

    let (cursor, token) = {
        let managed =
            // jig-ignore-next-line: canonical rustfmt line.
            ManagedBrowser::launch(&browser_plan).expect("launch first generation browser");
        let scope = managed
            .event_cursor_scope("account-a")
            .expect("create first generation event scope");
        let cursor = scope.clone().bind(String::from("event-7"));
        assert_eq!(cursor.state_for(&scope).map(String::as_str), Ok("event-7"));
        let token = managed
            .encode_event_cursor(&cursor, &scope)
            .expect("encode first generation cursor");
        let account_drift = managed
            .event_cursor_scope("account-b")
            .expect("create alternate account scope");
        assert_eq!(
            cursor.state_for(&account_drift),
            Err(EventCursorBindingError::AccountMismatch)
        );
        assert_eq!(
            EventCursorBindingError::AccountMismatch.resume_failure(),
            EventCursorResumeFailure::InvalidCursor
        );
        let debug = format!("{managed:?}");
        assert!(debug.contains("<redacted-web-adapter-generation>"));
        assert!(debug.contains("WebEventCursorCodec([REDACTED])"));
        assert!(!debug.contains(&root.display().to_string()));
        assert!(!debug.contains("session-1"));
        (cursor, token)
    };

    // jig-ignore-next-line: canonical rustfmt line.
    let managed = ManagedBrowser::launch(&browser_plan).expect("launch second generation browser");
    let restarted_scope = managed
        .event_cursor_scope("account-a")
        .expect("create restarted event scope");
    assert_eq!(
        cursor.state_for(&restarted_scope),
        Err(EventCursorBindingError::GenerationMismatch)
    );
    assert_eq!(
        EventCursorBindingError::GenerationMismatch.resume_failure(),
        EventCursorResumeFailure::CursorExpired
    );
    assert_eq!(
        managed.decode_event_cursor(&token, &restarted_scope),
        Err(WebEventCursorCodecError::CursorExpired)
    );
    assert_eq!(
        managed.event_cursor_scope(""),
        Err(EventCursorBindingError::MalformedScope)
    );
    drop(managed);
    cleanup(&root);
}

#[test]
fn event_cursor_tokens_are_confidential_authenticated_and_scoped() {
    use mail_capability_domain::EventCursorScope;
    use mail_web_adapter::WebEventCursorCodecError;

    let root = test_root("event-cursor-codec");
    fs::create_dir_all(&root).expect("create synthetic cursor-codec root");
    let targets = concat!(
        "[{\"targetId\":\"page-1\",\"type\":\"page\",",
        "\"url\":\"https://mail.proton.me/u/0/inbox\"}]"
    );
    let browser = fake_browser(&root, targets, "mail.proton.me");
    let browser_plan = plan(&root, &browser);
    // jig-ignore-next-line: canonical rustfmt line.
    let managed = ManagedBrowser::launch(&browser_plan).expect("launch cursor-codec browser");
    let scope = managed
        .event_cursor_scope("synthetic-account-secret")
        .expect("create cursor-codec scope");
    let cursor = scope
        .clone()
        .bind(String::from("synthetic-provider-event-secret"));

    let token_one = managed
        .encode_event_cursor(&cursor, &scope)
        .expect("encode first opaque cursor");
    let token_two = managed
        .encode_event_cursor(&cursor, &scope)
        .expect("encode second opaque cursor");
    assert_ne!(token_one, token_two);
    assert!(token_one.starts_with("ev1."));
    for secret in [
        "synthetic-account-secret",
        "synthetic-provider-event-secret",
    ] {
        assert!(!token_one.contains(secret));
    }
    let decoded = managed
        .decode_event_cursor(&token_one, &scope)
        .expect("decode exact current cursor");
    assert_eq!(
        decoded.state_for(&scope).map(String::as_str),
        Ok("synthetic-provider-event-secret")
    );

    for invalid_state in [
        "event\nunsafe",
        "event\tunsafe",
        "event unsafe",
        "event\u{7f}unsafe",
    ] {
        let invalid_cursor = scope.clone().bind(String::from(invalid_state));
        assert_eq!(
            managed.encode_event_cursor(&invalid_cursor, &scope),
            Err(WebEventCursorCodecError::InvalidCursor)
        );
    }

    let account_drift = managed
        .event_cursor_scope("synthetic-account-other")
        .expect("create account-drift scope");
    assert_eq!(
        managed.decode_event_cursor(&token_one, &account_drift),
        Err(WebEventCursorCodecError::InvalidCursor)
    );
    let (account, _adapter, generation) = scope.binding_components();
    // jig-ignore-next-line: canonical rustfmt line.
    let adapter_drift = EventCursorScope::new(account, "other-adapter", generation)
        .expect("create adapter-drift scope");
    assert_eq!(
        managed.decode_event_cursor(&token_one, &adapter_drift),
        Err(WebEventCursorCodecError::InvalidCursor)
    );

    let mut tampered = token_one.into_bytes();
    let last = tampered.last_mut().expect("opaque cursor is non-empty");
    *last = if *last == b'A' { b'B' } else { b'A' };
    // jig-ignore-next-line: canonical rustfmt line.
    let tampered = String::from_utf8(tampered).expect("opaque cursor remains ASCII");
    assert_eq!(
        managed.decode_event_cursor(&tampered, &scope),
        Err(WebEventCursorCodecError::InvalidCursor)
    );

    // jig-ignore-next-line: canonical rustfmt line.
    for malformed in ["", "ev0.deadbeef.payload", "ev1.not-hex.payload", "ev1.."] {
        assert_eq!(
            managed.decode_event_cursor(malformed, &scope),
            Err(WebEventCursorCodecError::InvalidCursor)
        );
    }

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
        "1",
        "1790847999",
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
fn initial_total_rejects_silent_page_underfill() {
    let (result, log) = with_network_browser(
        "network-total-underfill",
        false,
        "m-1",
        false,
        false,
        false,
        "m-1",
        "0",
        "2",
        "1790847999",
        ManagedBrowser::observe_visible_message_metadata,
    );
    assert_eq!(
        result,
        Err(BrowserDriverError::MessageListBatchIncompatible)
    );
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
        "1",
        "1790847999",
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
        "2",
        "1790847999",
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
        "2",
        "1790847999",
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
        "2",
        "1790847999",
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
        "2",
        "1790847999",
        ManagedBrowser::observe_visible_message_metadata,
    );
    assert_eq!(
        result,
        Err(BrowserDriverError::MessageListResponseAmbiguous)
    );
    assert_eq!(log, "enable\nreload\nbody\nbody\ndisable\n");
}

#[test]
fn time_descending_response_rejects_cross_batch_order_drift() {
    let (result, log) = with_network_browser(
        "network-time-order-drift",
        false,
        "m-1",
        true,
        false,
        false,
        "m-1",
        "0",
        "2",
        "1790849000",
        ManagedBrowser::observe_visible_message_metadata,
    );
    assert_eq!(
        result,
        Err(BrowserDriverError::MessageListBatchIncompatible)
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
        "2",
        "1790847999",
        ManagedBrowser::observe_visible_message_metadata,
    );
    let metadata = metadata.expect("reconcile current page from first batch");
    assert_eq!(metadata.messages().len(), 1);
    assert_eq!(metadata.messages()[0].id(), "m-1");
    assert_eq!(metadata.messages()[0].time(), 1_790_848_000);
    assert_eq!(log, "enable\nreload\nbody\nbody\ndisable\n");
}

#[test]
fn prefetched_next_page_id_cannot_satisfy_visible_current_page() {
    let (result, log) = with_network_browser(
        "network-prefetch-not-visible",
        false,
        "m-2",
        true,
        false,
        false,
        "m-1",
        "0",
        "2",
        "1790847999",
        ManagedBrowser::observe_visible_message_metadata,
    );
    assert_eq!(
        result,
        Err(BrowserDriverError::MessageListReconciliation(
            MessageListReconciliationError::MissingVisibleMessage
        ))
    );
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
        "51",
        "1790847999",
        ManagedBrowser::observe_visible_message_metadata,
    );
    assert_eq!(result, Err(BrowserDriverError::MessageListPageMismatch));
    assert_eq!(log, "enable\nreload\nbody\ndisable\n");
}

#[test]
fn initial_total_rejects_page_beyond_result_set() {
    let (result, log) = with_network_browser(
        "network-total-page-range",
        false,
        "m-1",
        false,
        false,
        false,
        "m-1",
        "1",
        "1",
        "1790847999",
        ManagedBrowser::observe_visible_message_metadata,
    );
    assert_eq!(
        result,
        Err(BrowserDriverError::MessageListBatchIncompatible)
    );
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
        "1",
        "1790847999",
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
        "1",
        "1790847999",
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
    assert_ne!(real_chrome.len(), 0);

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

#[test]
fn rejected_message_list_network_enable_disables_before_returning() {
    let root = test_root("message-list-enable-rejected");
    fs::create_dir_all(&root).expect("create synthetic driver root");
    let browser = fake_network_browser(
        &root,
        false,
        "m-1",
        false,
        false,
        false,
        "m-1",
        "0",
        "1",
        "1790847999",
    );
    let script = fs::read_to_string(&browser).expect("read fake CDP script");
    let expected = SESSION_EMPTY_REPLY;
    assert!(script.contains(expected));
    // jig-ignore-next-line: indivisible synthetic fixture command.
    let rejected = "      printf '{\"id\":%s,\"sessionId\":\"session-1\",\"error\":{\"code\":-32601}}\\0' \"$id\" >&4;;";
    let modified = script.replacen(expected, rejected, 1);
    install_script(&browser, modified).expect("install synthetic error reply");
    let mut managed = ManagedBrowser::launch(&plan(&root, &browser))
        .expect("launch synthetic message-list driver");
    let page = managed
        .provider_page()
        .expect("discover synthetic Mail page");
    assert_eq!(
        managed.observe_message_list_response(&page),
        Err(BrowserDriverError::Protocol),
    );
    managed
        .require_mail_shell(&page)
        .expect("CDP remains usable following message-list activation failure");
    drop(managed);
    // jig-ignore-next-line: canonical rustfmt line.
    let log = fs::read_to_string(root.join("network-log.txt")).expect("read Network commands");
    assert_eq!(log, "enable\ndisable\n");
    cleanup(&root);
}

#[test]
fn redirected_in_list_capture_cleans_network_without_fetching_body() {
    use mail_web_adapter::MessageListNetworkError;

    let root = test_root("redirected-in-list");
    fs::create_dir_all(&root).expect("create synthetic driver root");
    let browser = fake_network_browser(
        &root,
        false,
        "m-1",
        false,
        false,
        false,
        "m-1",
        "0",
        "1",
        "1790847999",
    );
    let script = fs::read_to_string(&browser).expect("read browser fixture");
    let original = "      printf '%s\\0' \"$request\" >&4";
    let from = script.find("&Sort=Time&Desc=1").expect("find list request");
    let suffix = script.get(from..).expect("find UTF-8 boundary");
    let offset = from + suffix.find(original).expect("find event emission");
    let injection = concat!(
        "      request=\"${request%??}\"\n",
        "      request+=',\"redirectResponse\":{\"url\":",
        "\"https://mail.proton.me/other\"}}}'\n",
    );
    let mut patched = script.clone();
    patched.insert_str(offset, injection);
    install_script(&browser, patched).expect("install redirected-in response");
    let browser_plan = plan(&root, &browser);
    let mut managed = ManagedBrowser::launch(&browser_plan).expect("launch");
    let page = managed.provider_page().expect("discover Mail target");
    assert_eq!(
        managed.observe_message_list_response(&page),
        Err(BrowserDriverError::MessageListNetwork(
            MessageListNetworkError::RedirectedAway,
        ))
    );
    managed
        .require_mail_shell(&page)
        .expect("keep CDP synchronized");
    drop(managed);
    let log_path = root.join("network-log.txt");
    let log = fs::read_to_string(log_path).expect("read Network trace");
    assert_eq!(log, "enable\nreload\ndisable\n");
    cleanup(&root);
}

#[test]
fn consumed_message_list_id_replay_during_disable_fails_closed() {
    use mail_web_adapter::MessageListNetworkError;
    let root = test_root("message-list-replayed-during-disable");
    fs::create_dir_all(&root).expect("create synthetic network root");
    let browser = fake_network_browser(
        &root,
        false,
        "m-1",
        false,
        false,
        true,
        "m-1",
        "0",
        "1",
        "1790847999",
    );
    let script = fs::read_to_string(&browser).expect("read browser script");
    assert!(script.contains("list-3"));
    install_script(&browser, script.replace("list-3", "list-1"))
        .expect("install reused completed request ID");
    let mut managed =
        // jig-ignore-next-line: canonical rustfmt line.
        ManagedBrowser::launch(&plan(&root, &browser)).expect("launch synthetic browser");
    let page = managed.provider_page().expect("discover Mail page");
    assert_eq!(
        managed.observe_message_list_response(&page),
        Err(BrowserDriverError::MessageListNetwork(
            MessageListNetworkError::InvalidSequence,
        ))
    );
    managed
        .require_mail_shell(&page)
        .expect("the next content-free CDP read must remain synchronized");
    drop(managed);
    let log =
        // jig-ignore-next-line: canonical rustfmt line.
        fs::read_to_string(root.join("network-log.txt")).expect("read synthetic Network lifecycle");
    assert_eq!(log, "enable\nreload\nbody\ndisable\n");
    cleanup(&root);
}

#[test]
// jig-ignore-next-line: canonical rustfmt line.
fn malformed_unsolicited_cdp_envelopes_drain_enable_reply_and_disable_network() {
    for (label, unsolicited) in [
        ("bad-string-id", r#"{"id":"not-a-command","result":{}}"#),
        ("null-id", r#"{"id":null,"result":{}}"#),
        ("wrong-numeric-id", r#"{"id":999999,"result":{}}"#),
        (
            "hybrid-wrong-id",
            r#"{"id":999998,"method":"Network.loadingFinished","result":{}}"#,
        ),
        ("result-without-id", r#"{"result":{}}"#),
        ("error-without-id", r#"{"error":{"code":-32601}}"#),
        ("method-is-number", r#"{"method":7,"params":{}}"#),
        ("array-envelope", "[]"),
        ("event-empty-method", r#"{"method":""}"#),
        (
            "event-extra-private-field",
            concat!(
                r#"{"method":"Security.securityStateChanged","params":{},"#,
                r#""privateField":"sensitive"}"#,
            ),
        ),
        (
            "event-extra-null-field",
            concat!(
                r#"{"method":"Security.securityStateChanged","#,
                r#""sessionId":"session-1","extra":null}"#,
            ),
        ),
        (
            "event-null-params",
            r#"{"method":"Network.loadingFinished","params":null}"#,
        ),
        (
            "event-array-params",
            r#"{"method":"Network.loadingFinished","params":[]}"#,
        ),
        (
            "event-empty-session",
            r#"{"method":"Network.loadingFinished","sessionId":""}"#,
        ),
        (
            "event-number-session",
            r#"{"method":"Network.loadingFinished","sessionId":4}"#,
        ),
        (
            "duplicate-method-key",
            concat!(
                r#"{"method":"Security.securityStateChanged","#,
                r#""method":"Security.securityStateChanged","params":{}}"#,
            ),
        ),
        ("not-json", "not-json"),
        ("partial-json", "{\"id\":"),
        (
            "trailing-json-bytes",
            "{\"method\":\"Network.requestWillBeSent\"}bad",
        ),
    ] {
        let root = test_root(label);
        fs::create_dir_all(&root).expect("create synthetic profile");
        let browser = fake_network_browser(
            &root,
            false,
            "m-1",
            false,
            false,
            false,
            "m-1",
            "0",
            "1",
            "1790847999",
        );
        // jig-ignore-next-line: canonical rustfmt line.
        let script = fs::read_to_string(&browser).expect("read CDP browser fixture");
        let reply = SESSION_EMPTY_REPLY;
        assert!(script.contains(reply));
        // jig-ignore-next-line: canonical rustfmt line.
        let injected = format!("      printf '%s\\0' '{unsolicited}' >&4\n{reply}");
        install_script(&browser, script.replacen(reply, &injected, 1))
            .expect("inject protocol-invalid unsolicited envelope");
        let mut managed = ManagedBrowser::launch(&plan(&root, &browser))
            .expect("launch isolated synthetic browser");
        let page = managed.provider_page().expect("find Mail target");
        assert_eq!(
            managed.observe_message_list_response(&page),
            Err(BrowserDriverError::Protocol),
            "case {label} must fail closed"
        );
        managed
            .require_mail_shell(&page)
            // jig-ignore-next-line: canonical rustfmt line.
            .expect("drained CDP command reply permits same-session inspection");
        drop(managed);
        let log = fs::read_to_string(root.join("network-log.txt"))
            .expect("read synthetic Network commands");
        assert_eq!(
            log, "enable\ndisable\n",
            "case {label} must disable Network"
        );
        cleanup(&root);
    }
}

#[test]
fn hybrid_cdp_frame_with_matching_command_id_does_not_spoof_success() {
    let root = test_root("hybrid-matching-command-id");
    fs::create_dir_all(&root).expect("create test-only browser profile");
    let browser = fake_network_browser(
        &root,
        false,
        "m-1",
        false,
        false,
        false,
        "m-1",
        "0",
        "1",
        "1790847999",
    );
    // jig-ignore-next-line: canonical rustfmt line.
    let script = fs::read_to_string(&browser).expect("read synthetic CDP fixture");
    let expected = SESSION_EMPTY_REPLY;
    assert!(script.contains(expected));
    let injected = format!(
        // jig-ignore-next-line: canonical rustfmt line.
        "      printf '{{\"id\":%s,\"method\":\"Network.responseReceived\",\"result\":{{}}}}\\0' \"$id\" >&4\n{expected}"
    );
    install_script(&browser, script.replacen(expected, &injected, 1))
        .expect("inject ambiguous matching-id notification before valid reply");
    let mut managed =
        // jig-ignore-next-line: canonical rustfmt line.
        ManagedBrowser::launch(&plan(&root, &browser)).expect("launch synthetic CDP driver");
    let page = managed.provider_page().expect("discover Mail test page");
    assert_eq!(
        managed.observe_message_list_response(&page),
        Err(BrowserDriverError::Protocol)
    );
    managed
        .require_mail_shell(&page)
        // jig-ignore-next-line: canonical rustfmt line.
        .expect("drained legitimate enable reply allows later Mail-shell check");
    drop(managed);
    // jig-ignore-next-line: canonical rustfmt line.
    let log = fs::read_to_string(root.join("network-log.txt")).expect("read fake Network commands");
    assert_eq!(log, "enable\ndisable\n");
    cleanup(&root);
}

#[test]
fn malformed_cdp_result_shapes_never_enable_network_capture() {
    for (label, result_json) in [
        ("null-result", "null"),
        ("array-result", "[]"),
        ("string-result", "\"ok\""),
        ("boolean-result", "true"),
        ("numeric-result", "17"),
        ("extra-result-field", r#"{"unexpected":true}"#),
    ] {
        let root = test_root(label);
        fs::create_dir_all(&root).expect("create test-only CDP profile");
        let browser = fake_network_browser(
            &root,
            false,
            "m-1",
            false,
            false,
            false,
            "m-1",
            "0",
            "1",
            "1790847999",
        );
        // jig-ignore-next-line: canonical rustfmt line.
        let script = fs::read_to_string(&browser).expect("read synthetic browser script");
        let reply = SESSION_EMPTY_REPLY;
        assert!(script.contains(reply));
        let invalid =
            // jig-ignore-next-line: canonical rustfmt line.
            format!("      printf '{{\"id\":%s,\"sessionId\":\"session-1\",\"result\":{result_json}}}\\0' \"$id\" >&4;;");
        install_script(&browser, script.replacen(reply, &invalid, 1))
            .expect("inject invalid success payload into Network.enable");
        let mut managed =
            // jig-ignore-next-line: canonical rustfmt line.
            ManagedBrowser::launch(&plan(&root, &browser)).expect("launch isolated test browser");
        let page = managed.provider_page().expect("discover Mail page");
        assert_eq!(
            managed.observe_message_list_response(&page),
            Err(BrowserDriverError::Protocol),
            "{label} must not be treated as a successful CDP command"
        );
        managed
            .require_mail_shell(&page)
            .expect("invalid enable result leaves same session inspectable");
        drop(managed);
        let log = fs::read_to_string(root.join("network-log.txt"))
            .expect("read synthetic Network command log");
        assert_eq!(log, "enable\ndisable\n", "{label} must disable Network");
        cleanup(&root);
    }
}

#[test]
fn invalid_utf8_cdp_frame_drains_real_enable_reply_before_cleanup() {
    let root = test_root("invalid-utf8-frame");
    fs::create_dir_all(&root).expect("create synthetic browser directory");
    let browser = fake_network_browser(
        &root,
        false,
        "m-1",
        false,
        false,
        false,
        "m-1",
        "0",
        "1",
        "1790847999",
    );
    // jig-ignore-next-line: canonical rustfmt line.
    let script = fs::read_to_string(&browser).expect("read synthetic browser script");
    let reply = SESSION_EMPTY_REPLY;
    assert!(script.contains(reply));
    let injected = format!("      printf '\\377\\0' >&4\n{reply}");
    install_script(&browser, script.replacen(reply, &injected, 1))
        .expect("insert NUL-delimited invalid UTF-8 CDP frame");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan(&root, &browser)).expect("launch fake browser");
    let page = managed.provider_page().expect("find synthetic Mail page");
    assert_eq!(
        managed.observe_message_list_response(&page),
        Err(BrowserDriverError::Protocol)
    );
    managed
        .require_mail_shell(&page)
        .expect("binary frame failure must leave the command pipe aligned");
    drop(managed);
    // jig-ignore-next-line: canonical rustfmt line.
    let log = fs::read_to_string(root.join("network-log.txt")).expect("read synthetic Network log");
    assert_eq!(log, "enable\ndisable\n");
    cleanup(&root);
}

#[test]
fn provider_rejected_message_list_body_disables_network_before_returning() {
    let root = test_root("message-list-provider-code-rejected");
    fs::create_dir_all(&root).expect("create synthetic profile root");
    let browser = fake_network_browser(
        &root,
        false,
        "m-1",
        false,
        false,
        false,
        "m-1",
        "0",
        "1",
        "1790847999",
    );
    // jig-ignore-next-line: canonical rustfmt line.
    let script = fs::read_to_string(&browser).expect("read synthetic CDP script");
    let success_code = r#"\"Code\":1000"#;
    assert!(script.contains(success_code));
    install_script(&browser, script.replace(success_code, r#"\"Code\":2001"#))
        .expect("inject explicit unsuccessful provider response code");
    let browser_plan = plan(&root, &browser);
    let mut managed = ManagedBrowser::launch(&browser_plan).expect("launch");
    let page = managed.provider_page().expect("discover Mail page");
    assert_eq!(
        managed.observe_message_list_response(&page),
        Err(BrowserDriverError::MessageListResponse(
            MessageListResponseError::ProviderRejected
        ))
    );
    managed
        .require_mail_shell(&page)
        .expect("same browser remains usable after failed list projection");
    drop(managed);
    let log = fs::read_to_string(root.join("network-log.txt"))
        .expect("read synthetic browser command audit");
    assert_eq!(log, "enable\nreload\nbody\ndisable\n");
    cleanup(&root);
}

#[test]
fn browser_allows_distinct_continuation_totals_without_snapshot_claim() {
    let root = test_root("prefetch-total-changed");
    fs::create_dir_all(&root).expect("create isolated fake browser profile");
    let browser = fake_network_browser(
        &root,
        false,
        "m-1",
        true,
        false,
        false,
        "m-1",
        "0",
        "2",
        "1790847999",
    );
    let script = fs::read_to_string(&browser).expect("read browser fixture");
    // jig-ignore-next-line: canonical rustfmt line.
    let second_branch = "    *'Network.getResponseBody'*'\"requestId\":\"list-2\"'*)";
    let start = script
        .find(second_branch)
        .expect("find second list GET body branch");
    let (before, second) = script.split_at(start);
    let needle = r#"\"Total\":2,\"Messages\""#;
    assert!(second.contains(needle));
    let altered = second.replacen(needle, r#"\"Total\":3,\"Messages\""#, 1);
    install_script(&browser, format!("{before}{altered}"))
        .expect("change only the second provider-reported list total");
    let mut managed =
        // jig-ignore-next-line: canonical rustfmt line.
        ManagedBrowser::launch(&plan(&root, &browser)).expect("launch synthetic browser");
    let page = managed.provider_page().expect("discover Mail page");
    let matched = managed
        .observe_visible_message_metadata(&page)
        .expect("anchor continuation total is not the initial total");
    assert_eq!(matched.messages().len(), 1);
    managed
        .require_mail_shell(&page)
        .expect("same browser remains safe following batch-total drift");
    drop(managed);
    let log =
        // jig-ignore-next-line: canonical rustfmt line.
        fs::read_to_string(root.join("network-log.txt")).expect("read synthetic CDP command log");
    assert_eq!(log, "enable\nreload\nbody\nbody\ndisable\n");
    cleanup(&root);
}

#[test]
fn malformed_cdp_provider_target_ids_never_become_page_handles() {
    use serde_json::json;
    for (index, invalid) in [
        String::new(),
        String::from("bad id"),
        String::from("bad/path"),
        String::from("bad%2fid"),
        String::from("bad.dot"),
        String::from("bad\nnew"),
        String::from("invisible\u{200b}id"),
        "x".repeat(513),
    ]
    .into_iter()
    .enumerate()
    {
        let root = test_root(&format!("bad-target-{index}"));
        fs::create_dir_all(&root).expect("create synthetic profile");
        let targets = json!([{
            "targetId": invalid,
            "type": "page",
            "url": "https://mail.proton.me/u/0/inbox"
        }]);
        // jig-ignore-next-line: canonical rustfmt line.
        let browser = fake_browser(&root, &targets.to_string(), "mail.proton.me");
        let mut managed =
            // jig-ignore-next-line: canonical rustfmt line.
            ManagedBrowser::launch(&plan(&root, &browser)).expect("launch synthetic browser");
        assert_eq!(managed.provider_page(), Err(BrowserDriverError::Protocol));
        drop(managed);
        cleanup(&root);
    }
}

#[test]
fn unexpected_attached_session_result_fields_cannot_authorize_origin() {
    let root = test_root("attach-result-extra-field");
    fs::create_dir_all(&root).expect("create synthetic profile");
    let targets = concat!(
        r#"[{"targetId":"page-1","type":"page","#,
        r#""url":"https://mail.proton.me/"}]"#,
    );
    let browser = fake_browser(&root, targets, "mail.proton.me");
    let script = fs::read_to_string(&browser).expect("read fake browser");
    let reply = r#""result":{"sessionId":"session-1"}"#;
    assert!(script.contains(reply));
    let invalid = r#""result":{"sessionId":"session-1","extra":true}"#;
    install_script(&browser, script.replacen(reply, invalid, 1))
        .expect("inject extra attach result field");
    let browser_plan = plan(&root, &browser);
    let mut driver = ManagedBrowser::launch(&browser_plan).expect("launch");
    let page = driver.provider_page().expect("discover Mail page");
    assert_eq!(
        driver.verify_provider_origin(&page),
        Err(BrowserDriverError::Protocol),
    );
    drop(driver);
    cleanup(&root);
}

#[test]
fn unexpected_target_catalog_result_fields_cannot_select_mail_page() {
    let root = test_root("target-catalog-result-extra");
    fs::create_dir_all(&root).expect("create synthetic profile");
    let targets = concat!(
        r#"[{"targetId":"page-1","type":"page","#,
        r#""url":"https://mail.proton.me/"}]"#,
    );
    let browser = fake_browser(&root, targets, "mail.proton.me");
    let script = fs::read_to_string(&browser).expect("read fixture");
    let catalog = format!(r#""targetInfos":{targets}"#);
    assert!(script.contains(&catalog));
    let altered = format!(r#"{catalog},"unreviewed":true"#);
    install_script(&browser, script.replacen(&catalog, &altered, 1))
        .expect("inject unexpected target catalog result field");
    let browser_plan = plan(&root, &browser);
    let mut managed = ManagedBrowser::launch(&browser_plan).expect("launch");
    assert_eq!(managed.provider_page(), Err(BrowserDriverError::Protocol));
    drop(managed);
    cleanup(&root);
}

#[test]
fn unexpected_runtime_result_fields_cannot_prove_provider_origin() {
    let root = test_root("runtime-result-extra");
    fs::create_dir_all(&root).expect("create synthetic profile");
    let targets = concat!(
        r#"[{"targetId":"page-1","type":"page","#,
        r#""url":"https://mail.proton.me/"}]"#,
    );
    let browser = fake_browser(&root, targets, "mail.proton.me");
    let script = fs::read_to_string(&browser).expect("read fixture");
    let suffix = r#""hostname":"mail.proton.me","port":""}}}}"#;
    assert!(script.contains(suffix));
    let altered = concat!(
        r#""hostname":"mail.proton.me","port":""}},"#,
        r#""unreviewed":true}}"#,
    );
    install_script(&browser, script.replacen(suffix, altered, 1))
        .expect("inject unexpected runtime result field");
    let browser_plan = plan(&root, &browser);
    let mut managed = ManagedBrowser::launch(&browser_plan).expect("launch");
    let page = managed.provider_page().expect("select Mail page");
    assert_eq!(
        managed.verify_provider_origin(&page),
        Err(BrowserDriverError::Protocol),
    );
    drop(managed);
    cleanup(&root);
}

#[test]
fn runtime_result_accepts_legacy_explicit_false_throw_flag() {
    let root = test_root("runtime-result-was-thrown-false");
    fs::create_dir_all(&root).expect("create synthetic profile");
    let targets = concat!(
        r#"[{"targetId":"page-1","type":"page","#,
        r#""url":"https://mail.proton.me/"}]"#,
    );
    let browser = fake_browser(&root, targets, "mail.proton.me");
    let script = fs::read_to_string(&browser).expect("read fixture");
    let suffix = r#""hostname":"mail.proton.me","port":""}}}}"#;
    assert!(script.contains(suffix));
    let altered = concat!(
        r#""hostname":"mail.proton.me","port":""}},"#,
        r#""wasThrown":false}}"#,
    );
    install_script(&browser, script.replacen(suffix, altered, 1))
        .expect("insert legacy success indicator");
    let browser_plan = plan(&root, &browser);
    let mut managed = ManagedBrowser::launch(&browser_plan).expect("launch");
    let page = managed.provider_page().expect("select Mail page");
    assert_eq!(
        managed.verify_provider_origin(&page),
        Ok(PageOrigin::ProtonMail)
    );
    drop(managed);
    cleanup(&root);
}

#[test]
fn unexpected_runtime_location_fields_cannot_prove_trusted_origin() {
    let root = test_root("runtime-location-extra");
    fs::create_dir_all(&root).expect("create synthetic profile");
    let targets = concat!(
        r#"[{"targetId":"page-1","type":"page","#,
        r#""url":"https://mail.proton.me/"}]"#,
    );
    let browser = fake_browser(&root, targets, "mail.proton.me");
    let script = fs::read_to_string(&browser).expect("read fake browser");
    let expected = r#""hostname":"mail.proton.me","port":"""#;
    assert!(script.contains(expected));
    let with_extra = format!(r#"{expected},"unreviewed":true"#);
    install_script(&browser, script.replacen(expected, &with_extra, 1))
        .expect("inject unexpected location field");
    let browser_plan = plan(&root, &browser);
    let mut driver = ManagedBrowser::launch(&browser_plan).expect("launch");
    let page = driver.provider_page().expect("discover Mail page");
    assert_eq!(
        driver.verify_provider_origin(&page),
        Err(BrowserDriverError::Protocol),
    );
    drop(driver);
    cleanup(&root);
}

#[test]
fn malformed_attached_session_ids_fail_before_runtime_origin_evaluation() {
    use serde_json::json;
    for (index, invalid) in [
        String::new(),
        String::from("bad id"),
        String::from("bad/session"),
        String::from("bad%2fid"),
        String::from("bad\ttab"),
        String::from("invisible\u{2066}id"),
        "y".repeat(513),
    ]
    .into_iter()
    .enumerate()
    {
        let root = test_root(&format!("bad-session-{index}"));
        fs::create_dir_all(&root).expect("create synthetic profile");
        let targets = json!([{
            "targetId": "page-1",
            "type": "page",
            "url": "https://mail.proton.me/u/0/inbox"
        }]);
        // jig-ignore-next-line: canonical rustfmt line.
        let browser = fake_browser(&root, &targets.to_string(), "mail.proton.me");
        // jig-ignore-next-line: canonical rustfmt line.
        let script = fs::read_to_string(&browser).expect("read synthetic CDP fixture");
        let from = "\"sessionId\":\"session-1\"";
        assert!(script.contains(from));
        let to = format!("\"sessionId\":{}", json!(invalid));
        install_script(&browser, script.replace(from, &to))
            .expect("replace attached CDP session result");
        let mut managed =
            // jig-ignore-next-line: canonical rustfmt line.
            ManagedBrowser::launch(&plan(&root, &browser)).expect("launch synthetic browser");
        let page = managed.provider_page().expect("select eligible Mail page");
        assert_eq!(
            managed.verify_provider_origin(&page),
            Err(BrowserDriverError::Protocol),
        );
        drop(managed);
        cleanup(&root);
    }
}

#[test]
fn contradictory_runtime_subtype_cannot_prove_provider_origin() {
    let targets = concat!(
        r#"[{"targetId":"page-1","type":"page","#,
        r#""url":"https://mail.proton.me/"}]"#,
    );
    for (label, subtype) in [
        ("runtime-array-subtype", "array"),
        ("runtime-null-subtype", "null"),
        ("runtime-error-subtype", "error"),
    ] {
        let root = test_root(label);
        fs::create_dir_all(&root).expect("create synthetic profile");
        let browser = fake_browser(&root, targets, "mail.proton.me");
        let script = fs::read_to_string(&browser).expect("read fixture");
        let expected = r#""type":"object","#;
        assert!(script.contains(expected));
        let altered = format!(r#""type":"object","subtype":"{subtype}","#);
        install_script(&browser, script.replacen(expected, &altered, 1))
            .expect("inject contradictory Runtime RemoteObject subtype");
        let browser_plan = plan(&root, &browser);
        let mut driver = ManagedBrowser::launch(&browser_plan).expect("launch");
        let page = driver.provider_page().expect("discover Mail page");
        assert_eq!(
            driver.verify_provider_origin(&page),
            Err(BrowserDriverError::Protocol),
            "case {label} must fail closed"
        );
        drop(driver);
        cleanup(&root);
    }
}

#[test]
fn contradictory_runtime_remote_type_cannot_prove_provider_origin() {
    let targets = concat!(
        r#"[{"targetId":"page-1","type":"page","#,
        r#""url":"https://mail.proton.me/"}]"#,
    );
    for (label, remote_type) in [
        ("runtime-string-object", r#""type":"string""#),
        ("runtime-boolean-object", r#""type":"boolean""#),
        ("runtime-unknown-type", r#""type":"invalid""#),
        ("runtime-null-type", r#""type":null"#),
    ] {
        let root = test_root(label);
        fs::create_dir_all(&root).expect("create synthetic profile");
        let browser = fake_browser(&root, targets, "mail.proton.me");
        let script = fs::read_to_string(&browser).expect("read fixture");
        assert!(script.contains(r#""type":"object""#));
        install_script(
            &browser,
            script.replacen(r#""type":"object""#, remote_type, 1),
        )
        .expect("inject contradictory Runtime RemoteObject type");
        let browser_plan = plan(&root, &browser);
        let mut driver = ManagedBrowser::launch(&browser_plan).expect("launch");
        let page = driver.provider_page().expect("discover Mail page");
        assert_eq!(
            driver.verify_provider_origin(&page),
            Err(BrowserDriverError::Protocol),
            "case {label} must not prove a trusted origin"
        );
        drop(driver);
        cleanup(&root);
    }
}

#[test]
fn by_value_runtime_evidence_rejects_conflicting_remote_object_authority() {
    let targets = concat!(
        r#"[{"targetId":"page-1","type":"page","#,
        r#""url":"https://mail.proton.me/"}]"#,
    );
    for (label, extra) in [
        ("runtime-remote-object-id", r#""objectId":"object-1","#),
        (
            "runtime-unserializable-value",
            r#""unserializableValue":"NaN","#,
        ),
        (
            "runtime-conflicting-deep-value",
            // jig-ignore-next-line: contradictory synthetic CDP serialization.
            r#""deepSerializedValue":{"type":"object","value":{"hostname":"evil.invalid"}},"#,
        ),
        (
            "runtime-unrequested-preview",
            r#""preview":{"type":"object","properties":[]},"#,
        ),
        (
            "runtime-unrequested-custom-preview",
            r#""customPreview":{"header":"private"},"#,
        ),
    ] {
        let root = test_root(label);
        fs::create_dir_all(&root).expect("create synthetic profile");
        let browser = fake_browser(&root, targets, "mail.proton.me");
        let script = fs::read_to_string(&browser).expect("read fixture");
        let remote_type = r#""type":"object","#;
        assert!(script.contains(remote_type));
        let contradictory = format!("{remote_type}{extra}");
        let altered = script.replacen(remote_type, &contradictory, 1);
        install_script(&browser, altered).expect("inject drift");
        let browser_plan = plan(&root, &browser);
        let mut driver = ManagedBrowser::launch(&browser_plan).expect("launch");
        let page = driver.provider_page().expect("select Mail page");
        assert_eq!(
            driver.verify_provider_origin(&page),
            Err(BrowserDriverError::Protocol),
            "case {label} cannot prove an exact by-value origin"
        );
        drop(driver);
        cleanup(&root);
    }
}

#[test]
fn maximal_safe_cdp_target_and_session_handles_work_without_log_exposure() {
    use serde_json::json;
    let root = test_root("maximal-browser-handles");
    // jig-ignore-next-line: canonical rustfmt line.
    fs::create_dir_all(&root).expect("create isolated synthetic browser profile");
    let target_id = "t".repeat(512);
    let session_id = "s".repeat(512);
    let targets = json!([{
        "targetId": target_id,
        "type": "page",
        "url": "https://mail.proton.me/u/0/inbox"
    }]);
    let browser = fake_browser(&root, &targets.to_string(), "mail.proton.me");
    // jig-ignore-next-line: canonical rustfmt line.
    let script = fs::read_to_string(&browser).expect("read synthetic browser script");
    let from = r#""sessionId":"session-1""#;
    let to = format!(r#""sessionId":{}"#, json!(session_id));
    assert!(script.contains(from));
    install_script(&browser, script.replace(from, &to))
        .expect("install maximum-length synthetic session handle");
    let mut managed =
        // jig-ignore-next-line: canonical rustfmt line.
        ManagedBrowser::launch(&plan(&root, &browser)).expect("launch dedicated fake browser");
    let page = managed
        .provider_page()
        .expect("accept bounded synthetic target");
    assert_eq!(page.origin(), PageOrigin::ProtonMail);
    let debug = format!("{page:?}");
    assert!(!debug.contains(&target_id));
    assert!(debug.contains("<redacted>"));
    assert_eq!(
        managed.verify_provider_origin(&page),
        Ok(PageOrigin::ProtonMail),
    );
    drop(managed);
    cleanup(&root);
}

#[test]
fn wrong_session_reply_with_current_command_id_cannot_spoof_enable() {
    for (label, session_json) in [
        ("wrong-session", r#""sessionId":"other-session""#),
        ("null-session", r#""sessionId":null"#),
        ("numeric-session", r#""sessionId":7"#),
        ("empty-session", r#""sessionId":"""#),
    ] {
        let root = test_root(label);
        fs::create_dir_all(&root).expect("create isolated synthetic profile");
        let browser = fake_network_browser(
            &root,
            false,
            "m-1",
            false,
            false,
            false,
            "m-1",
            "0",
            "1",
            "1790847999",
        );
        // jig-ignore-next-line: canonical rustfmt line.
        let script = fs::read_to_string(&browser).expect("read browser fixture");
        let reply = SESSION_EMPTY_REPLY;
        assert!(script.contains(reply));
        let unsolicited = format!(
            // jig-ignore-next-line: canonical rustfmt line.
            "      printf '{{\"id\":%s,{session_json},\"result\":{{}}}}\\0' \"$id\" >&4\n{reply}"
        );
        install_script(&browser, script.replacen(reply, &unsolicited, 1))
            .expect("install cross-session reply ahead of actual reply");
        let browser_plan = plan(&root, &browser);
        let launched = ManagedBrowser::launch(&browser_plan);
        let mut managed = launched.expect("launch");
        let page = managed.provider_page().expect("select synthetic Mail page");
        assert_eq!(
            managed.observe_message_list_response(&page),
            Err(BrowserDriverError::Protocol),
        );
        managed
            .require_mail_shell(&page)
            .expect("authentic command reply was drained before cleanup");
        drop(managed);
        let log =
            // jig-ignore-next-line: canonical rustfmt line.
            fs::read_to_string(root.join("network-log.txt")).expect("read Network audit");
        assert_eq!(log, "enable\ndisable\n");
        cleanup(&root);
    }
}

#[test]
fn browser_scoped_handshake_rejects_attached_session_reply() {
    let root = test_root("browser-handshake-session");
    fs::create_dir_all(&root).expect("create isolated synthetic profile");
    let targets = concat!(
        r#"[{"targetId":"page-1","type":"page","#,
        r#""url":"https://mail.proton.me/"}]"#
    );
    let browser = fake_browser(&root, targets, "mail.proton.me");
    let script = fs::read_to_string(&browser).expect("read browser fixture");
    let reply = r#""id":1,"result":{"product":"FakeChrome/1"}"#;
    let wrong = concat!(
        r#""id":1,"sessionId":"session-1","#,
        r#""result":{"product":"FakeChrome/1"}"#
    );
    assert!(script.contains(reply));
    let injected = format!(
        "      printf '%s\\0' '{{{wrong}}}' >&4\n\
             printf '%s\\0' '{{{reply}}}' >&4"
    );
    let original = format!("      printf '%s\\0' '{{{reply}}}' >&4");
    assert!(script.contains(&original));
    install_script(&browser, script.replacen(&original, &injected, 1))
        .expect("install wrong-scope reply ahead of genuine acknowledgement");
    assert!(matches!(
        ManagedBrowser::launch(&plan(&root, &browser)),
        Err(BrowserDriverError::Protocol)
    ));
    cleanup(&root);
}

#[test]
fn unexpected_cdp_reply_envelope_field_cannot_spoof_enable() {
    let root = test_root("extra-reply-field");
    fs::create_dir_all(&root).expect("create isolated synthetic profile");
    let browser = fake_network_browser(
        &root,
        false,
        "m-1",
        false,
        false,
        false,
        "m-1",
        "0",
        "1",
        "1790847999",
    );
    let script = fs::read_to_string(&browser).expect("read fixture");
    let reply = SESSION_EMPTY_REPLY;
    assert!(script.contains(reply));
    let extra_reply = concat!(
        "      printf '{\"id\":%s,\"sessionId\":\"session-1\",",
        "\"result\":{},\"unexpected\":\"private\"}\\0' \"$id\" >&4"
    );
    let injected = format!("{extra_reply}\n{reply}");
    install_script(&browser, script.replacen(reply, &injected, 1))
        .expect("inject unexpected reply field ahead of valid response");
    let browser_plan = plan(&root, &browser);
    let mut managed = ManagedBrowser::launch(&browser_plan).expect("launch");
    let page = managed.provider_page().expect("select Mail page");
    assert_eq!(
        managed.observe_message_list_response(&page),
        Err(BrowserDriverError::Protocol),
    );
    managed.require_mail_shell(&page).expect("drained reply");
    drop(managed);
    let log = fs::read_to_string(root.join("network-log.txt")).expect("audit");
    assert_eq!(log, "enable\ndisable\n");
    cleanup(&root);
}

#[test]
fn absent_session_reply_cannot_spoof_an_attached_command() {
    let root = test_root("missing-session-reply");
    fs::create_dir_all(&root).expect("create isolated synthetic profile");
    let browser = fake_network_browser(
        &root,
        false,
        "m-1",
        false,
        false,
        false,
        "m-1",
        "0",
        "1",
        "1790847999",
    );
    let script = fs::read_to_string(&browser).expect("read browser fixture");
    let reply = SESSION_EMPTY_REPLY;
    assert!(script.contains(reply));
    let missing = "      printf '{\"id\":%s,\"result\":{}}\\0' \"$id\" >&4;;";
    let injected = format!("{}\n{reply}", missing.trim_end_matches(";;"));
    install_script(&browser, script.replacen(reply, &injected, 1))
        .expect("inject sessionless reply before attached acknowledgement");
    let browser_plan = plan(&root, &browser);
    let mut managed = ManagedBrowser::launch(&browser_plan).expect("launch");
    let page = managed.provider_page().expect("select synthetic Mail page");
    assert_eq!(
        managed.observe_message_list_response(&page),
        Err(BrowserDriverError::Protocol),
    );
    managed
        .require_mail_shell(&page)
        .expect("matched reply was drained before Network cleanup");
    drop(managed);
    let log = fs::read_to_string(root.join("network-log.txt")).expect("audit");
    assert_eq!(log, "enable\ndisable\n");
    cleanup(&root);
}

#[test]
fn matching_explicit_cdp_session_reply_is_accepted() {
    let root = test_root("matched-cdp-session-reply");
    fs::create_dir_all(&root).expect("create isolated test profile");
    let browser = fake_network_browser(
        &root,
        false,
        "m-1",
        false,
        false,
        false,
        "m-1",
        "0",
        "1",
        "1790847999",
    );
    // The fake Chromium sends matching flattened-session replies by default.
    let script = fs::read_to_string(&browser).expect("read browser script");
    assert!(script.contains("\"sessionId\":\"session-1\",\"result\""));
    let mut managed =
        // jig-ignore-next-line: canonical rustfmt line.
        ManagedBrowser::launch(&plan(&root, &browser)).expect("launch synthetic browser");
    let page = managed
        .provider_page()
        .expect("discover synthetic Mail page");
    let response = managed
        .observe_message_list_response(&page)
        .expect("matching explicit session permits a safe app-owned list read");
    assert_eq!(response.messages().len(), 1);
    drop(managed);
    let log =
        // jig-ignore-next-line: canonical rustfmt line.
        fs::read_to_string(root.join("network-log.txt")).expect("read Network audit");
    assert_eq!(log, "enable\nreload\nbody\ndisable\n");
    cleanup(&root);
}

#[test]
fn dedicated_browser_target_discovery_is_bounded_before_selection() {
    use serde_json::json;
    for (label, extra_targets, expected) in [
        ("at-bound", 127usize, Ok(PageOrigin::ProtonMail)),
        ("over-bound", 128usize, Err(BrowserDriverError::Protocol)),
    ] {
        let root = test_root(label);
        fs::create_dir_all(&root).expect("create test profile");
        let mut targets = vec![json!({
            "targetId":"mail-1", "type":"page",
            "url":"https://mail.proton.me/u/0/inbox"
        })];
        targets.extend(
            (0..extra_targets)
                // jig-ignore-next-line: canonical rustfmt line.
                .map(|index| json!({"targetId":format!("other-{index}"),"type":"service_worker"})),
        );
        // jig-ignore-next-line: canonical rustfmt line.
        let browser = fake_browser(&root, &json!(targets).to_string(), "mail.proton.me");
        let mut managed =
            // jig-ignore-next-line: canonical rustfmt line.
            ManagedBrowser::launch(&plan(&root, &browser)).expect("launch synthetic browser");
        assert_eq!(managed.provider_page().map(|page| page.origin()), expected);
        drop(managed);
        cleanup(&root);
    }
}

#[test]
fn provider_target_url_metadata_has_a_bounded_ceiling() {
    use serde_json::json;
    let prefix = "https://mail.proton.me/";
    for (label, size, accepted) in [
        ("url-at-bound", 16_384usize, true),
        ("url-over-bound", 16_385usize, false),
    ] {
        let root = test_root(label);
        fs::create_dir_all(&root).expect("create synthetic browser profile");
        let url = format!("{prefix}{}", "x".repeat(size - prefix.len()));
        let targets = json!([{
            "targetId":"page-1","type":"page","url":url
        }]);
        // jig-ignore-next-line: canonical rustfmt line.
        let browser = fake_browser(&root, &targets.to_string(), "mail.proton.me");
        let mut managed =
            // jig-ignore-next-line: canonical rustfmt line.
            ManagedBrowser::launch(&plan(&root, &browser)).expect("launch synthetic Chromium");
        if accepted {
            assert_eq!(
                managed.provider_page().map(|page| page.origin()),
                Ok(PageOrigin::ProtonMail)
            );
        } else {
            // jig-ignore-next-line: canonical rustfmt line.
            assert_eq!(managed.provider_page(), Err(BrowserDriverError::Protocol));
        }
        drop(managed);
        cleanup(&root);
    }
}

#[test]
fn malformed_non_page_target_entries_cannot_hide_in_valid_target_catalog() {
    use serde_json::json;
    let valid_mail = json!({
        "targetId":"page-1", "type":"page",
        "url":"https://mail.proton.me/u/0/inbox"
    });
    for (case, malformed) in [
        ("null", json!(null)),
        ("array", json!([])),
        ("string", json!("service_worker")),
        ("missing-type", json!({"targetId":"other"})),
        ("numeric-type", json!({"type":7u8})),
        ("empty-type", json!({"type":""})),
        ("oversized-type", json!({"type":"x".repeat(65)})),
        ("missing-id", json!({"type":"service_worker"})),
        ("null-id", json!({"type":"service_worker","targetId":null})),
        (
            "numeric-id",
            json!({"type":"service_worker","targetId":7u8}),
        ),
        ("empty-id", json!({"type":"service_worker","targetId":""})),
    ] {
        for (position, targets) in [
            ("before", json!([malformed.clone(), valid_mail.clone()])),
            ("after", json!([valid_mail.clone(), malformed])),
        ] {
            let root = test_root(&format!("invalid-target-{case}-{position}"));
            fs::create_dir_all(&root).expect("create isolated fake profile");
            // jig-ignore-next-line: canonical rustfmt line.
            let browser = fake_browser(&root, &targets.to_string(), "mail.proton.me");
            let browser_plan = plan(&root, &browser);
            let launched = ManagedBrowser::launch(&browser_plan);
            let mut managed = launched.expect("launch");
            // jig-ignore-next-line: canonical rustfmt line.
            assert_eq!(managed.provider_page(), Err(BrowserDriverError::Protocol));
            drop(managed);
            cleanup(&root);
        }
    }
}

#[test]
fn invalid_provider_target_attachment_metadata_is_not_authority() {
    use serde_json::json;
    for (label, extra) in [
        ("attached-provider-target", json!({"attached":true})),
        ("malformed-attached-target", json!({"attached":"false"})),
        ("null-attached-target", json!({"attached":null})),
        ("malformed-context-type", json!({"browserContextId":null})),
        ("malformed-context-empty", json!({"browserContextId":""})),
        (
            "malformed-context-separator",
            json!({"browserContextId":"bad/id"}),
        ),
    ] {
        let root = test_root(label);
        fs::create_dir_all(&root).expect("create synthetic root");
        let mut info = json!({
            "targetId":"mail-1", "type":"page",
            "url":"https://mail.proton.me/u/0/inbox"
        });
        info.as_object_mut()
            .expect("fixture object")
            .extend(extra.as_object().expect("metadata object").clone());
        let target_catalog = json!([info]).to_string();
        let browser = fake_browser(&root, &target_catalog, "mail.proton.me");
        let browser_plan = plan(&root, &browser);
        let mut managed = ManagedBrowser::launch(&browser_plan).expect("CDP");
        assert_eq!(
            managed.provider_page(),
            Err(BrowserDriverError::Protocol),
            "{label} must not authorize an unowned target"
        );
        drop(managed);
        cleanup(&root);
    }
}

const PROVIDER_TEST_HOSTS: [(&str, &str); 2] =
    [("mail", "mail.proton.me"), ("account", "account.proton.me")];

#[test]
fn provider_prerender_or_malformed_subtype_is_not_visible_page_authority() {
    use serde_json::json;
    for (label, subtype) in [
        ("prerender", json!("prerender")),
        ("portal", json!("portal")),
        ("null", json!(null)),
        ("number", json!(1u8)),
        ("object", json!({"kind":"prerender"})),
    ] {
        for (kind, host) in PROVIDER_TEST_HOSTS {
            let root = test_root(&format!("{kind}-subtype-{label}"));
            fs::create_dir_all(&root).expect("create synthetic root");
            let targets = json!([{
                "targetId":"provider-1", "type":"page",
                "url":format!("https://{host}/u/0/inbox"), "subtype":subtype
            }]);
            let browser = fake_browser(&root, &targets.to_string(), host);
            let browser_plan = plan(&root, &browser);
            let launched = ManagedBrowser::launch(&browser_plan);
            let mut managed = launched.expect("CDP");
            assert_eq!(
                managed.provider_page(),
                Err(BrowserDriverError::Protocol),
                "{kind} target with {label} subtype is not a visible page"
            );
            drop(managed);
            cleanup(&root);
        }
    }
}

#[test]
fn popup_or_child_provider_target_cannot_be_selected_as_root_page() {
    use serde_json::json;
    for (label, metadata) in [
        ("opened-popup", json!({"openerId":"external-1"})),
        ("empty-opener", json!({"openerId":""})),
        ("child-target", json!({"parentId":"parent-1"})),
        ("opener-frame", json!({"openerFrameId":"frame-1"})),
        ("opener-can-access", json!({"canAccessOpener":true})),
        ("invalid-access", json!({"canAccessOpener":null})),
    ] {
        for (kind, host) in PROVIDER_TEST_HOSTS {
            let root = test_root(&format!("{kind}-{label}"));
            fs::create_dir_all(&root).expect("create synthetic root");
            let mut target = json!({
                "targetId":"provider-1", "type":"page",
                "url":format!("https://{host}/u/0/inbox")
            });
            target
                .as_object_mut()
                .expect("fixture object")
                .extend(metadata.as_object().expect("metadata object").clone());
            let catalog = json!([target]).to_string();
            let browser = fake_browser(&root, &catalog, host);
            let browser_plan = plan(&root, &browser);
            let launched = ManagedBrowser::launch(&browser_plan);
            let mut managed = launched.expect("CDP");
            assert_eq!(
                managed.provider_page(),
                Err(BrowserDriverError::Protocol),
                "{kind} {label} target is not an exclusive root page"
            );
            drop(managed);
            cleanup(&root);
        }
    }
}

#[test]
fn unexpected_provider_target_metadata_cannot_establish_selected_page() {
    use serde_json::json;
    for (label, extra) in [
        ("unknown-field", json!({"futureOwnerContext":"unreviewed"})),
        ("null-title", json!({"title":null})),
        ("numeric-title", json!({"title":7u8})),
        ("oversized-title", json!({"title":"x".repeat(16_385)})),
    ] {
        for (kind, host) in PROVIDER_TEST_HOSTS {
            let root = test_root(&format!("{kind}-{label}-target-metadata"));
            fs::create_dir_all(&root).expect("create synthetic root");
            let mut target = json!({
                "targetId":"provider-1", "type":"page",
                "url":format!("https://{host}/u/0/inbox"),
                "attached":false, "title":"Synthetic provider"
            });
            target
                .as_object_mut()
                .expect("fixture object")
                .extend(extra.as_object().expect("metadata object").clone());
            let catalog = json!([target]).to_string();
            let browser = fake_browser(&root, &catalog, host);
            let browser_plan = plan(&root, &browser);
            let launched = ManagedBrowser::launch(&browser_plan);
            let mut managed = launched.expect("CDP");
            assert_eq!(
                managed.provider_page(),
                Err(BrowserDriverError::Protocol),
                "{kind} target with {label} metadata must not be selected"
            );
            drop(managed);
            cleanup(&root);
        }
    }
}

#[test]
fn ordinary_provider_page_allows_empty_optional_subtype() {
    use serde_json::json;
    let root = test_root("normal-page-empty-subtype");
    fs::create_dir_all(&root).expect("create synthetic root");
    let targets = json!([{
        "targetId":"mail-1", "type":"page",
        "url":"https://mail.proton.me/u/0/inbox", "subtype":"",
        "canAccessOpener":false, "attached":false, "title":"Synthetic provider"
    }]);
    let browser = fake_browser(&root, &targets.to_string(), "mail.proton.me");
    let browser_plan = plan(&root, &browser);
    let mut managed = ManagedBrowser::launch(&browser_plan).expect("CDP");
    assert_eq!(
        managed.provider_page().map(|page| page.origin()),
        Ok(PageOrigin::ProtonMail)
    );
    drop(managed);
    cleanup(&root);
}

#[test]
fn unattached_provider_target_accepts_optional_default_context_metadata() {
    use serde_json::json;
    for (label, context) in [
        ("no-context", None),
        ("default-context", Some("default-profile-123")),
    ] {
        let root = test_root(label);
        fs::create_dir_all(&root).expect("create synthetic root");
        let mut target = json!({
            "targetId":"mail-1", "type":"page",
            "url":"https://mail.proton.me/u/0/inbox", "attached":false
        });
        if let Some(context) = context {
            target["browserContextId"] = json!(context);
        }
        let targets = json!([target]);
        let catalog = targets.to_string();
        let browser = fake_browser(&root, &catalog, "mail.proton.me");
        let browser_plan = plan(&root, &browser);
        let mut managed = ManagedBrowser::launch(&browser_plan).expect("CDP");
        assert_eq!(
            managed.provider_page().map(|page| page.origin()),
            Ok(PageOrigin::ProtonMail)
        );
        drop(managed);
        cleanup(&root);
    }
}

#[test]
fn provider_context_id_requires_proven_default_browser_context() {
    use serde_json::json;
    for (label, context, expected) in [
        (
            "proven-default-context",
            "default-profile-123",
            Ok(PageOrigin::ProtonMail),
        ),
        (
            "foreign-context",
            "other-context-7",
            Err(BrowserDriverError::Protocol),
        ),
    ] {
        let root = test_root(label);
        fs::create_dir_all(&root).expect("create synthetic root");
        let targets = json!([{
            "targetId":"mail-1", "type":"page",
            "url":"https://mail.proton.me/u/0/inbox",
            "attached":false, "browserContextId":context
        }]);
        let catalog = targets.to_string();
        let browser = fake_browser(&root, &catalog, "mail.proton.me");
        let browser_plan = plan(&root, &browser);
        let mut managed = ManagedBrowser::launch(&browser_plan).expect("CDP");
        assert_eq!(managed.provider_page().map(|page| page.origin()), expected);
        drop(managed);
        cleanup(&root);
    }
}

#[test]
fn duplicated_target_ids_across_target_types_cannot_select_mail_page() {
    use serde_json::json;
    for (label, first_type) in [
        ("worker-then-mail-duplicate", "service_worker"),
        ("other-page-then-mail-duplicate", "page"),
    ] {
        let root = test_root(label);
        fs::create_dir_all(&root).expect("create synthetic root");
        let extra = if first_type == "page" {
            json!({
                "type":"page", "targetId":"mail-1",
                "url":"https://example.test/"
            })
        } else {
            json!({"type":"service_worker", "targetId":"mail-1"})
        };
        let targets = json!([
            extra,
            {
                "type":"page", "targetId":"mail-1",
                "url":"https://mail.proton.me/u/0/inbox"
            }
        ]);
        let catalog = targets.to_string();
        let browser = fake_browser(&root, &catalog, "mail.proton.me");
        let browser_plan = plan(&root, &browser);
        let mut managed = ManagedBrowser::launch(&browser_plan).expect("CDP");
        assert_eq!(
            managed.provider_page(),
            Err(BrowserDriverError::Protocol),
            "{label} cannot select a reused target ID"
        );
        drop(managed);
        cleanup(&root);
    }
}

#[test]
fn unrelated_duplicate_target_id_cannot_hide_foreign_provider_context() {
    use serde_json::json;
    let root = test_root("duplicate-unrelated-target-id");
    fs::create_dir_all(&root).expect("create synthetic root");
    let targets = json!([
        {"targetId":"mail-1", "type":"service_worker"},
        {
            "targetId":"mail-1", "type":"page",
            "url":"https://mail.proton.me/u/0/inbox",
            "browserContextId":"other-context-7"
        }
    ]);
    let catalog = targets.to_string();
    let browser = fake_browser(&root, &catalog, "mail.proton.me");
    let browser_plan = plan(&root, &browser);
    let mut managed = ManagedBrowser::launch(&browser_plan).expect("CDP");
    assert_eq!(managed.provider_page(), Err(BrowserDriverError::Protocol));
    drop(managed);
    cleanup(&root);
}

#[test]
fn malformed_browser_context_catalog_cannot_authorize_provider_page() {
    use serde_json::json;
    let default = r#""defaultBrowserContextId":"default-profile-123""#;
    let contexts = r#""browserContextIds":["other-context-7"]"#;
    for (label, from, to) in [
        (
            "context-default-missing",
            default,
            r#""unknownDefault":"default-profile-123""#,
        ),
        (
            "context-default-null",
            default,
            r#""defaultBrowserContextId":null"#,
        ),
        (
            "context-default-extra-result",
            default,
            r#""defaultBrowserContextId":"default-profile-123","unknown":true"#,
        ),
        (
            "context-default-noncanonical",
            default,
            r#""defaultBrowserContextId":"bad/id""#,
        ),
        (
            "context-list-duplicate",
            contexts,
            r#""browserContextIds":["other-context-7","other-context-7"]"#,
        ),
        (
            "context-list-default-overlap",
            contexts,
            r#""browserContextIds":["default-profile-123"]"#,
        ),
        (
            "context-list-invalid",
            contexts,
            r#""browserContextIds":[null]"#,
        ),
        (
            "context-list-noncanonical",
            contexts,
            r#""browserContextIds":["bad/id"]"#,
        ),
    ] {
        let root = test_root(label);
        fs::create_dir_all(&root).expect("create synthetic root");
        let targets = json!([{
            "targetId":"mail-1", "type":"page",
            "url":"https://mail.proton.me/u/0/inbox",
            "browserContextId":"default-profile-123"
        }]);
        let catalog = targets.to_string();
        let browser = fake_browser(&root, &catalog, "mail.proton.me");
        let script = fs::read_to_string(&browser).expect("read fixture");
        assert!(script.contains(from), "missing fixture {label}");
        install_script(&browser, script.replacen(from, to, 1))
            .expect("inject malformed browser-context catalog");
        let browser_plan = plan(&root, &browser);
        let mut managed = ManagedBrowser::launch(&browser_plan).expect("CDP");
        assert_eq!(
            managed.provider_page(),
            Err(BrowserDriverError::Protocol),
            "{label} must not establish default context"
        );
        drop(managed);
        cleanup(&root);
    }
}

#[test]
fn unrelated_well_typed_browser_targets_remain_ignorable() {
    use serde_json::json;
    let root = test_root("well-typed-other-targets");
    fs::create_dir_all(&root).expect("create fake browser profile");
    let targets = json!([
        {
            "type":"service_worker",
            "targetId":"worker-0",
            "futureMetadata":"ignored"
        },
        {"type":"shared_worker","targetId":"worker-1"},
        // jig-ignore-next-line: canonical rustfmt line.
        {"targetId":"mail-1","type":"page","url":"https://mail.proton.me/u/0/inbox"}
    ]);
    let browser = fake_browser(&root, &targets.to_string(), "mail.proton.me");
    let browser_plan = plan(&root, &browser);
    let mut managed = ManagedBrowser::launch(&browser_plan).expect("launch");
    assert_eq!(
        managed.provider_page().map(|page| page.origin()),
        Ok(PageOrigin::ProtonMail)
    );
    drop(managed);
    cleanup(&root);
}

#[test]
fn oversized_or_disguised_cdp_notification_identity_drains_real_reply() {
    use serde_json::json;
    let malformed = [
        ("long-method", json!({"method":"x".repeat(129)})),
        ("spaced-method", json!({"method":"Network loadingFinished"})),
        ("slash-method", json!({"method":"Network/loadingFinished"})),
        ("missing-domain", json!({"method":"loadingFinished"})),
        ("leading-dot", json!({"method":".loadingFinished"})),
        ("trailing-dot", json!({"method":"Network."})),
        ("extra-dot", json!({"method":"Network..loadingFinished"})),
        (
            "bad-session",
            json!({"method":"Network.loadingFinished","sessionId":"bad/id"}),
        ),
        (
            "long-session",
            // jig-ignore-next-line: canonical rustfmt line.
            json!({"method":"Network.loadingFinished","sessionId":"s".repeat(513)}),
        ),
    ];
    for (label, frame) in malformed {
        let root = test_root(label);
        // jig-ignore-next-line: canonical rustfmt line.
        fs::create_dir_all(&root).expect("create isolated fake browser profile");
        let browser = fake_network_browser(
            &root,
            false,
            "m-1",
            false,
            false,
            false,
            "m-1",
            "0",
            "1",
            "1790847999",
        );
        // jig-ignore-next-line: canonical rustfmt line.
        let script = fs::read_to_string(&browser).expect("read synthetic CDP fixture");
        let reply = SESSION_EMPTY_REPLY;
        assert!(script.contains(reply));
        let inserted = format!("      printf '%s\\0' '{frame}' >&4\n{reply}");
        install_script(&browser, script.replacen(reply, &inserted, 1))
            .expect("inject malformed CDP event before authentic enable reply");
        let mut managed = ManagedBrowser::launch(&plan(&root, &browser))
            .expect("launch isolated synthetic browser");
        let page = managed.provider_page().expect("find Mail target");
        assert_eq!(
            managed.observe_message_list_response(&page),
            Err(BrowserDriverError::Protocol),
            "case {label} must fail closed"
        );
        managed
            .require_mail_shell(&page)
            .expect("genuine reply drained before safe subsequent inspection");
        drop(managed);
        let log = fs::read_to_string(root.join("network-log.txt"))
            .expect("read synthetic Network command audit");
        assert_eq!(log, "enable\ndisable\n");
        cleanup(&root);
    }
}

#[test]
fn browser_version_rejects_unreviewed_or_malformed_handshake_fields() {
    use serde_json::json;
    let cases = [
        ("unknown", String::from(r#""futureOwnerContext":true"#)),
        ("numeric-protocol", String::from(r#""protocolVersion":3"#)),
        ("null-revision", String::from(r#""revision":null"#)),
        ("invalid-js", String::from(r#""jsVersion":false"#)),
        (
            "long-agent",
            format!("\"userAgent\":{}", json!("X".repeat(2049))),
        ),
    ];
    for (label, metadata) in cases {
        let root = test_root(&format!("handshake-{label}"));
        fs::create_dir_all(&root).expect("create synthetic profile");
        let browser = fake_browser(&root, "[]", "mail.proton.me");
        let plan = plan(&root, &browser);
        let script = fs::read_to_string(&browser).expect("read script");
        let product = r#""product":"FakeChrome/1""#;
        assert!(script.contains(product));
        let expanded = format!("{product},{metadata}");
        install_script(&browser, script.replace(product, &expanded))
            .expect("inject browser handshake field");
        assert!(matches!(
            ManagedBrowser::launch(&plan),
            Err(BrowserDriverError::Protocol)
        ));
        cleanup(&root);
    }
}

#[test]
fn browser_version_allows_standard_optional_string_fields() {
    let root = test_root("handshake-standard-fields");
    fs::create_dir_all(&root).expect("create synthetic profile");
    let browser = fake_browser(&root, "[]", "mail.proton.me");
    let script = fs::read_to_string(&browser).expect("read script");
    let product = r#""product":"FakeChrome/1""#;
    let version = concat!(
        r#""product":"FakeChrome/1","protocolVersion":"1.3","#,
        r#""revision":"r1","userAgent":"Chrome","jsVersion":"V8""#,
    );
    assert!(script.contains(product));
    install_script(&browser, script.replace(product, version))
        .expect("install standard handshake fields");
    let managed = ManagedBrowser::launch(&plan(&root, &browser))
        .expect("standard version fields are compatible");
    drop(managed);
    cleanup(&root);
}

#[test]
fn contradictory_dom_root_metadata_cannot_prove_mail_shell() {
    let cases = [
        ("element-node", r#""nodeType":9"#, r#""nodeType":1"#),
        ("null-node", r#""nodeType":9"#, r#""nodeType":null"#),
        (
            "wrong-name",
            r#""nodeName":"\u0023document""#,
            r#""nodeName":"DIV""#,
        ),
        (
            "wrong-local-name",
            r#""localName":"""#,
            r#""localName":"div""#,
        ),
        (
            "unexpected-value",
            r#""nodeValue":"""#,
            r#""nodeValue":"not-document""#,
        ),
        (
            "document-with-parent",
            r#""nodeValue":"""#,
            r#""nodeValue":"","parentId":3"#,
        ),
        (
            "document-as-pseudo",
            r#""nodeValue":"""#,
            r#""nodeValue":"","pseudoType":"before""#,
        ),
        (
            "document-as-shadow-root",
            r#""nodeValue":"""#,
            r#""nodeValue":"","shadowRootType":"open""#,
        ),
        (
            "unrequested-document-children",
            r#""nodeValue":"""#,
            r#""nodeValue":"","children":[{"nodeValue":"private"}]"#,
        ),
        (
            "unrequested-pseudo-elements",
            r#""nodeValue":"""#,
            r#""nodeValue":"","pseudoElements":[{"nodeValue":"private"}]"#,
        ),
        (
            "unrequested-shadow-roots",
            r#""nodeValue":"""#,
            r#""nodeValue":"","shadowRoots":[{"nodeValue":"private"}]"#,
        ),
        (
            "foreign-document-url",
            r#""nodeValue":"""#,
            r#""nodeValue":"","documentURL":"https://evil.invalid/""#,
        ),
        (
            "misleading-document-userinfo",
            r#""nodeValue":"""#,
            // jig-ignore-next-line: exact cross-origin CDP URL fixture.
            r#""nodeValue":"","documentURL":"https://mail.proton.me@evil.invalid/""#,
        ),
    ];
    assert_rejects_document_root(&cases);
}

#[test]
fn element_only_metadata_cannot_prove_mail_document_root() {
    let cases = [
        (
            "document-as-frame-owner",
            r#""nodeValue":"""#,
            r#""nodeValue":"","contentDocument":{"nodeValue":"private"}"#,
        ),
        (
            "document-as-template",
            r#""nodeValue":"""#,
            r#""nodeValue":"","templateContent":{"nodeValue":"private"}"#,
        ),
        (
            "document-as-import-link",
            r#""nodeValue":"""#,
            r#""nodeValue":"","importedDocument":{"nodeValue":"private"}"#,
        ),
        (
            "document-with-distribution",
            r#""nodeValue":"""#,
            r#""nodeValue":"","distributedNodes":[{"nodeName":"private"}]"#,
        ),
        (
            "document-with-attributes",
            r#""nodeValue":"""#,
            r#""nodeValue":"","attributes":["name","private"]"#,
        ),
        (
            "document-with-assigned-slot",
            r#""nodeValue":"""#,
            r#""nodeValue":"","assignedSlot":{"nodeName":"private"}"#,
        ),
    ];
    assert_rejects_document_root(&cases);
}

fn assert_rejects_document_root(cases: &[(&str, &str, &str)]) {
    for &(label, original_field, contradiction) in cases {
        let root = test_root(&format!("dom-root-{label}"));
        fs::create_dir_all(&root).expect("create synthetic root");
        let browser = fake_network_browser(
            &root,
            false,
            "m-1",
            false,
            false,
            false,
            "m-1",
            "0",
            "1",
            "1790847999",
        );
        let script = fs::read_to_string(&browser).expect("read script");
        // jig-ignore-next-line: indivisible synthetic CDP document root.
        let original = r#""root":{"nodeId":1,"backendNodeId":2,"nodeType":9,"nodeName":"\u0023document","localName":"","nodeValue":""}"#;
        let changed = original.replace(original_field, contradiction);
        assert!(script.contains(original));
        assert_ne!(changed, original, "fixture must replace a real field");
        install_script(&browser, script.replace(original, &changed))
            .expect("inject contradictory document root");
        let browser_plan = plan(&root, &browser);
        let launched = ManagedBrowser::launch(&browser_plan);
        let mut managed = launched.expect("launch fake browser");
        let page = managed.provider_page().expect("discover Mail");
        assert_eq!(
            managed.require_mail_shell(&page),
            Err(BrowserDriverError::Protocol),
            "{label} cannot prove a document root"
        );
        drop(managed);
        cleanup(&root);
    }
}

#[test]
fn ordinary_document_root_metadata_still_proves_mail_shell() {
    let root = test_root("dom-root-document");
    fs::create_dir_all(&root).expect("create synthetic root");
    let browser = fake_network_browser(
        &root,
        false,
        "m-1",
        false,
        false,
        false,
        "m-1",
        "0",
        "1",
        "1790847999",
    );
    let script = fs::read_to_string(&browser).expect("read script");
    // jig-ignore-next-line: indivisible synthetic CDP document root.
    let original = r#""root":{"nodeId":1,"backendNodeId":2,"nodeType":9,"nodeName":"\u0023document","localName":"","nodeValue":""}"#;
    // Retain a harmless optional field in the full document-root fixture.
    let normal = original.replace(
        r#""nodeValue":""}"#,
        concat!(
            "\"nodeValue\":\"\",\"childNodeCount\":0,",
            "\"documentURL\":\"https://mail.proton.me/u/0/inbox\"}"
        ),
    );
    assert!(script.contains(original));
    let changed = script.replace(original, &normal);
    install_script(&browser, changed).expect("install document root");
    let browser_plan = plan(&root, &browser);
    let launched = ManagedBrowser::launch(&browser_plan);
    let mut managed = launched.expect("launch fake browser");
    let page = managed.provider_page().expect("discover Mail");
    managed
        .require_mail_shell(&page)
        .expect("ordinary document root");
    drop(managed);
    cleanup(&root);
}

#[test]
fn contradictory_document_child_counts_cannot_authorize_ax_inspection() {
    for (label, count) in [
        ("negative-child-count", "-1"),
        ("huge-child-count", "2147483648"),
        ("text-child-count", r#""2""#),
        ("null-child-count", "null"),
        ("fractional-child-count", "1.5"),
    ] {
        let root = test_root(label);
        fs::create_dir_all(&root).expect("create isolated synthetic root");
        let browser = fake_network_browser(
            &root,
            false,
            "m-1",
            false,
            false,
            false,
            "m-1",
            "0",
            "1",
            "1790847999",
        );
        let script = fs::read_to_string(&browser).expect("read fake browser");
        // jig-ignore-next-line: indivisible synthetic CDP document root.
        let original = r#""root":{"nodeId":1,"backendNodeId":2,"nodeType":9,"nodeName":"\u0023document","localName":"","nodeValue":""}"#;
        assert!(script.contains(original));
        let updated = original.replace(
            r#""nodeValue":""}"#,
            &format!(r#""nodeValue":"","childNodeCount":{count}}}"#),
        );
        install_script(&browser, script.replace(original, &updated))
            .expect("inject malformed document child count");
        let mut managed =
            // jig-ignore-next-line: canonical rustfmt line.
            ManagedBrowser::launch(&plan(&root, &browser)).expect("launch synthetic browser");
        let page = managed.provider_page().expect("discover Mail tab");
        assert_eq!(
            managed.require_mail_shell(&page),
            Err(BrowserDriverError::Protocol),
            "invalid document child count {label} cannot prove Mail"
        );
        drop(managed);
        cleanup(&root);
    }
}

#[test]
fn malformed_chromium_handshake_releases_owned_profile_for_retry() {
    use serde_json::json;
    for (case, invalid) in [
        ("missing-product", String::from("null")),
        ("empty-product", String::from("\"\"")),
        ("numeric-product", String::from("19")),
        ("oversized-product", json!("P".repeat(257)).to_string()),
    ] {
        let root = test_root(case);
        fs::create_dir_all(&root).expect("create synthetic browser profile");
        // jig-ignore-next-line: canonical rustfmt line.
        let targets = r#"[{"targetId":"page-1","type":"page","url":"https://mail.proton.me/"}]"#;
        let browser = fake_browser(&root, targets, "mail.proton.me");
        let plan = plan(&root, &browser);
        // jig-ignore-next-line: canonical rustfmt line.
        let script = fs::read_to_string(&browser).expect("read synthetic launch script");
        let product = r#""product":"FakeChrome/1""#;
        assert!(script.contains(product));
        let invalid_product = format!("\"product\":{invalid}");
        install_script(&browser, script.replace(product, &invalid_product))
            .expect("inject malformed browser version result");
        assert!(matches!(
            ManagedBrowser::launch(&plan),
            Err(BrowserDriverError::Protocol)
        ));
        let restored = install_script(&browser, &script);
        restored.expect("restore valid isolated browser");
        let mut resumed = ManagedBrowser::launch(&plan)
            // jig-ignore-next-line: canonical rustfmt line.
            .expect("malformed handshake must release the dedicated-profile lease");
        assert_eq!(
            resumed.provider_page().map(|page| page.origin()),
            Ok(PageOrigin::ProtonMail)
        );
        drop(resumed);
        cleanup(&root);
    }
}

#[test]
fn bounded_chromium_product_marker_is_accepted_at_the_boundary() {
    use serde_json::json;
    let root = test_root("product-marker-max");
    fs::create_dir_all(&root).expect("create isolated profile");
    let targets = concat!(
        r#"[{"targetId":"page-1","type":"page","#,
        r#""url":"https://mail.proton.me/"}]"#
    );
    let browser = fake_browser(&root, targets, "mail.proton.me");
    let script = fs::read_to_string(&browser).expect("read browser fixture");
    let product = r#""product":"FakeChrome/1""#;
    assert!(script.contains(product));
    let bounded = format!("\"product\":{}", json!("P".repeat(256)));
    install_script(&browser, script.replace(product, &bounded))
        .expect("install exact maximum-length product marker");
    let mut managed = ManagedBrowser::launch(&plan(&root, &browser))
        .expect("bounded browser product marker is valid");
    assert_eq!(
        managed.provider_page().map(|page| page.origin()),
        Ok(PageOrigin::ProtonMail)
    );
    drop(managed);
    cleanup(&root);
}

#[test]
fn invisible_network_request_id_never_triggers_response_body_fetch() {
    let root = test_root("hidden-request-id");
    // jig-ignore-next-line: canonical rustfmt line.
    fs::create_dir_all(&root).expect("create isolated synthetic browser profile");
    let browser = fake_network_browser(
        &root,
        false,
        "m-1",
        false,
        false,
        false,
        "m-1",
        "0",
        "1",
        "1790847999",
    );
    // jig-ignore-next-line: canonical rustfmt line.
    let script = fs::read_to_string(&browser).expect("read synthetic Network fixture");
    assert!(script.contains("list-1"));
    let disguised = "list-\u{200b}1";
    install_script(&browser, script.replace("list-1", disguised))
        .expect("inject hidden-Unicode ID in a matching list lifecycle");
    let mut managed =
        // jig-ignore-next-line: canonical rustfmt line.
        ManagedBrowser::launch(&plan(&root, &browser)).expect("launch fake dedicated browser");
    let page = managed
        .provider_page()
        .expect("discover Mail provider page");
    assert_eq!(
        managed.observe_message_list_response(&page),
        Err(BrowserDriverError::MessageListNetwork(
            mail_web_adapter::MessageListNetworkError::MalformedEvent,
        )),
    );
    managed
        .require_mail_shell(&page)
        .expect("Network cleanup keeps the same target inspectable");
    drop(managed);
    let log =
        // jig-ignore-next-line: canonical rustfmt line.
        fs::read_to_string(root.join("network-log.txt")).expect("read synthetic command audit");
    assert_eq!(log, "enable\nreload\ndisable\n");
    assert!(!log.contains("body"));
    cleanup(&root);
}

#[test]
fn managed_browser_uses_exact_non_utf8_profile_argument() {
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};

    let root = test_root("raw-data-home");
    fs::create_dir_all(&root).expect("create synthetic root");
    let browser = fake_browser(&root, "[]", "mail.proton.me");
    let data_home = root.join(OsString::from_vec(b"data-\xff".to_vec()));
    let plan = ManagedBrowserPlan::under_data_home(
        browser.to_str().expect("ASCII fake browser path"),
        &data_home,
    )
    .expect("fixed synthetic project profile");
    // jig-ignore-next-line: canonical rustfmt line.
    let managed = ManagedBrowser::launch(&plan).expect("launch synthetic browser");
    let mut expected = b"--user-data-dir=".to_vec();
    let profile = data_home.join("protonmail-ai/browser-profile");
    expected.extend_from_slice(profile.as_os_str().as_bytes());
    // jig-ignore-next-line: canonical rustfmt line.
    let args = fs::read(root.join("browser-args.txt")).expect("browser arguments");
    assert!(
        args.split(|byte| *byte == b'\n')
            .any(|line| line == expected.as_slice())
    );
    drop(managed);
    fs::remove_dir_all(root).expect("remove synthetic browser tree");
}

#[test]
fn synthetic_browser_rewrite_does_not_execute_an_open_writer_inode() {
    use std::fs::OpenOptions;

    let root = test_root("script-writer-atomicity");
    fs::create_dir_all(&root).expect("create isolated synthetic browser root");
    let browser = fake_browser(
        &root,
        r#"[{"targetId":"p","type":"page","url":"https://mail.proton.me/"}]"#,
        "mail.proton.me",
    );
    let old_writer = OpenOptions::new()
        .write(true)
        .open(&browser)
        .expect("keep previous executable inode open for writing");
    let script = fs::read(&browser).expect("read synthetic source bytes");
    install_script(&browser, script).expect("rewrite executable test fixture");
    let mut managed = ManagedBrowser::launch(&plan(&root, &browser))
        .expect("synthetic executable must not be text-busy");
    assert_eq!(
        managed.provider_page().map(|page| page.origin()),
        Ok(PageOrigin::ProtonMail)
    );
    drop(managed);
    drop(old_writer);
    cleanup(&root);
}

#[test]
fn transient_executable_text_busy_recovers_after_writer_closes() {
    use std::fs::OpenOptions;
    use std::thread;
    use std::time::Duration;

    let root = test_root("transient-text-busy");
    fs::create_dir_all(&root).expect("create synthetic root");
    // jig-ignore-next-line: indivisible synthetic target fixture.
    let targets = r#"[{"targetId":"p","type":"page","url":"https://mail.proton.me/"}]"#;
    let browser = fake_browser(&root, targets, "mail.proton.me");
    let writer = OpenOptions::new()
        .write(true)
        .open(&browser)
        .expect("keep synthetic executable temporarily text-busy");
    let release = thread::spawn(move || {
        thread::sleep(Duration::from_millis(45));
        drop(writer);
    });
    let attempt = ManagedBrowser::launch(&plan(&root, &browser));
    release.join().expect("synthetic writer released");
    let mut managed = attempt.expect("text-busy launch must recover");
    assert_eq!(
        managed.provider_page().map(|page| page.origin()),
        Ok(PageOrigin::ProtonMail)
    );
    drop(managed);
    cleanup(&root);
}

#[test]
fn permanently_text_busy_browser_fails_closed_and_releases_lease() {
    use std::fs::OpenOptions;

    let root = test_root("permanent-text-busy");
    fs::create_dir_all(&root).expect("create synthetic busy root");
    // jig-ignore-next-line: indivisible synthetic Mail target fixture.
    let targets = r#"[{"targetId":"p","type":"page","url":"https://mail.proton.me/"}]"#;
    let browser = fake_browser(&root, targets, "mail.proton.me");
    let writer = OpenOptions::new()
        .write(true)
        .open(&browser)
        .expect("hold executable writable for entire retry budget");
    let plan = plan(&root, &browser);
    assert!(matches!(
        ManagedBrowser::launch(&plan),
        Err(BrowserDriverError::BrowserLaunch)
    ));
    drop(writer);
    let mut resumed = ManagedBrowser::launch(&plan)
        .expect("exhausted startup retries must release the profile lease");
    assert_eq!(
        resumed.provider_page().map(|page| page.origin()),
        Ok(PageOrigin::ProtonMail)
    );
    drop(resumed);
    cleanup(&root);
}

#[test]
fn exact_full_final_message_page_requires_no_empty_continuation() {
    let root = test_root("exact-full-final-page");
    fs::create_dir_all(&root).expect("create isolated synthetic browser root");
    let browser = fake_network_browser(
        &root,
        false,
        "m-1",
        false,
        false,
        false,
        "m-1",
        "0",
        "1",
        "1790847999",
    );
    let script = fs::read_to_string(&browser);
    let script = script.expect("read synthetic request script");
    let initial_shape = "PageSize=50&Limit=50";
    assert!(script.contains(initial_shape));
    let exact_page = script.replace(initial_shape, "PageSize=1&Limit=1");
    let installed = install_script(&browser, exact_page);
    installed.expect("install exact-full-page browser");
    let browser_plan = plan(&root, &browser);
    let launched = ManagedBrowser::launch(&browser_plan);
    let mut managed = launched.expect("launch synthetic browser");
    let page = managed.provider_page().expect("find fake Mail page");
    let metadata = managed
        .observe_visible_message_metadata(&page)
        .expect("exactly full final page needs no empty continuation");
    assert_eq!(metadata.messages().len(), 1);
    drop(managed);
    let log = fs::read_to_string(root.join("network-log.txt"));
    let log = log.expect("read network method audit");
    assert_eq!(log, "enable\nreload\nbody\ndisable\n");
    cleanup(&root);
}

#[test]
fn unexpected_continuation_on_exact_final_page_fails_closed() {
    let (result, log) = with_network_browser(
        "unexpected-empty-continuation",
        false,
        "m-1",
        true,
        false,
        false,
        "m-1",
        "0",
        "1",
        "1790847999",
        ManagedBrowser::observe_visible_message_metadata,
    );
    assert_eq!(
        result,
        Err(BrowserDriverError::MessageListResponseAmbiguous)
    );
    assert_eq!(log, "enable\nreload\nbody\ndisable\n");
}

#[test]
fn repeated_provider_ids_across_initial_and_prefetched_batches_fail_closed() {
    let root = test_root("duplicate-prefetch-id");
    fs::create_dir_all(&root).expect("create isolated synthetic browser root");
    let browser = fake_network_browser(
        &root,
        false,
        "m-1",
        true,
        false,
        false,
        "m-1",
        "0",
        "2",
        "1790847999",
    );
    let script = fs::read_to_string(&browser).expect("read synthetic browser");
    let branch = r#"    *'Network.getResponseBody'*'"requestId":"list-2"'*)"#;
    let index = script.find(branch).expect("find second list response");
    let (prefix, suffix) = script.split_at(index);
    let original = r#"\"ID\":\"m-2\""#;
    assert!(suffix.contains(original));
    let altered = suffix.replacen(original, r#"\"ID\":\"m-1\""#, 1);
    install_script(&browser, format!("{prefix}{altered}"))
        .expect("install duplicate provider ID fixture");
    let browser_plan = plan(&root, &browser);
    let launched = ManagedBrowser::launch(&browser_plan);
    let mut managed = launched.expect("launch fake browser");
    let page = managed.provider_page().expect("find synthetic page");
    assert_eq!(
        managed.observe_visible_message_metadata(&page),
        Err(BrowserDriverError::MessageListBatchIncompatible)
    );
    drop(managed);
    let audit = fs::read_to_string(root.join("network-log.txt"));
    let log = audit.expect("read synthetic network log");
    assert_eq!(log, "enable\nreload\nbody\nbody\ndisable\n");
    cleanup(&root);
}

#[test]
fn enabled_next_page_cannot_conflict_with_proven_final_provider_total() {
    let root = test_root("impossible-final-next-page");
    fs::create_dir_all(&root).expect("create isolated synthetic browser root");
    let browser = fake_network_browser(
        &root,
        false,
        "m-1",
        false,
        false,
        false,
        "m-1",
        "0",
        "1",
        "1790847999",
    );
    let script = fs::read_to_string(&browser);
    let source = script.expect("read fake browser script");
    let original = r#"nextPresent":false,"nextDisabled":null"#;
    assert!(source.contains(original));
    let next_enabled = r#"nextPresent":true,"nextDisabled":false"#;
    let modified = source.replace(original, next_enabled);
    let installed = install_script(&browser, modified);
    installed.expect("install impossible Next fixture");
    let browser_plan = plan(&root, &browser);
    let launched = ManagedBrowser::launch(&browser_plan);
    let mut browser_driver = launched.expect("launch synthetic browser");
    let page = browser_driver.provider_page().expect("find synthetic page");
    let result = browser_driver.observe_visible_message_metadata(&page);
    assert_eq!(result, Err(BrowserDriverError::MessageListPageMismatch));
    drop(browser_driver);
    cleanup(&root);
}

#[test]
fn enabled_next_page_is_consistent_with_remaining_provider_total() {
    let root = test_root("remaining-next-page");
    fs::create_dir_all(&root).expect("create isolated synthetic browser root");
    let browser = fake_network_browser(
        &root,
        false,
        "m-1",
        true,
        false,
        false,
        "m-1",
        "0",
        "2",
        "1790847999",
    );
    let script = fs::read_to_string(&browser);
    let source = script.expect("read fake browser script");
    let original = r#"nextPresent":false,"nextDisabled":null"#;
    assert!(source.contains(original));
    let next_enabled = r#"nextPresent":true,"nextDisabled":false"#;
    let modified = source.replace(original, next_enabled);
    install_script(&browser, modified).expect("install remaining-page fixture");
    let browser_plan = plan(&root, &browser);
    let launched = ManagedBrowser::launch(&browser_plan);
    let mut browser_driver = launched.expect("launch synthetic browser");
    let page = browser_driver.provider_page().expect("find synthetic page");
    let metadata = browser_driver
        .observe_visible_message_metadata(&page)
        .expect("Next can remain enabled while provider has more messages");
    assert_eq!(metadata.messages().len(), 1);
    drop(browser_driver);
    cleanup(&root);
}
