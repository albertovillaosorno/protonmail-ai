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
//   - Synthetic exact folder/label response and Network lifecycle evidence.
// - Must-Not:
//   - Use live accounts, real mailbox names, tokens, cookies, or provider data.
// - Allows:
//   - Exercise bounded catalog projection with synthetic JSON/CDP fixtures.
// - Split-When:
//   - Managed-browser catalog capture needs process-level fixture ownership.
// - Merge-When:
//   - Catalog projection and browser capture share one stable acceptance suite.
// - Summary:
//   - Proves passive mailbox/label catalog evidence fails closed safely.
// - Description:
//   - Covers exact endpoint types, Unicode, parents, retries, and redaction.
// - Usage:
//   - Run through the `mail_web_adapter` mailbox-catalog integration test.
// - Defaults:
//   - Synthetic local values only.
//

//! Synthetic mailbox/label catalog projection and Network capture tests.

use mail_web_adapter::WebCatalogCursorCodecError;
use mail_web_adapter::{MailboxCatalogKind, MailboxCatalogNetworkCapture};
use mail_web_adapter::{MailboxCatalogNetworkError, MailboxCatalogResponseError};
use mail_web_adapter::{MailboxCatalogPageError, MailboxCatalogPageKind};
use mail_web_adapter::{ObservedMailboxCatalog, ObservedMailboxCatalogResponse};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const LABEL_URL: &str = "https://mail.proton.me/api/core/v4/labels?Type=1";
const FOLDER_URL: &str = "https://mail.proton.me/api/core/v4/labels?Type=3";
const SYSTEM_URL: &str = "https://mail.proton.me/api/core/v4/labels?Type=4";
static CATALOG_BROWSER_TEST_LOCK: Mutex<()> = Mutex::new(());

fn request(session: &str, id: &str, method: &str, url: &str) -> Value {
    json!({
        "sessionId": session,
        "method": "Network.requestWillBeSent",
        "params": {
            "requestId": id,
            "request": {
                "method": method,
                "url": url,
                "headers": {
                    "Authorization": "Bearer synthetic-secret",
                    "Cookie": "synthetic-cookie"
                }
            }
        }
    })
}

fn response(session: &str, id: &str, url: &str) -> Value {
    json!({
        "sessionId": session,
        "method": "Network.responseReceived",
        "params": {
            "requestId": id,
            "response": {
                "url": url,
                "status": 200,
                "mimeType": "application/json",
                "headers": {"Set-Cookie": "synthetic-cookie"}
            }
        }
    })
}

fn finished(session: &str, id: &str) -> Value {
    json!({
        "sessionId": session,
        "method": "Network.loadingFinished",
        "params": {"requestId": id}
    })
}

fn failed(session: &str, id: &str) -> Value {
    json!({
        "sessionId": session,
        "method": "Network.loadingFailed",
        "params": {"requestId": id, "errorText": "synthetic failure"}
    })
}

#[test]
#[expect(
    clippy::default_numeric_fallback,
    reason = "synthetic JSON numbers mirror provider fields"
)]
fn folder_projection_preserves_unicode_parent_and_provider_order() {
    let body = json!({
        "Code": 1000,
        "Labels": [
            {
                "ID": "folder-child",
                "Name": "\u{65c5}\u{884c} \u{2709}\u{fe0f}",
                "Type": 3,
                "Order": 9,
                "ParentID": "folder-parent",
                "Color": "#ff0000",
                "Notify": 1
            },
            {
                "ID": "folder-parent",
                "Name": "Travel",
                "Type": 3,
                "Order": 2,
                "ParentID": null
            }
        ]
    })
    .to_string();
    let projected =
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedMailboxCatalogResponse::parse(MailboxCatalogKind::Folder, "GET", FOLDER_URL, &body)
            .expect("project synthetic folders");
    assert_eq!(projected.items().len(), 2);
    assert_eq!(projected.items()[0].id(), "folder-parent");
    assert_eq!(projected.items()[0].name(), "Travel");
    assert_eq!(projected.items()[0].parent_id(), None);
    assert_eq!(
        projected.items()[1].name(),
        "\u{65c5}\u{884c} \u{2709}\u{fe0f}"
    );
    assert_eq!(projected.items()[1].parent_id(), Some("folder-parent"));
    assert_eq!(projected.items()[1].order(), 9);
    let debug = format!("{projected:?} {:?}", projected.items()[1]);
    for secret in [
        "folder-child",
        "folder-parent",
        "\u{65c5}\u{884c}",
        "Travel",
        "#ff0000",
    ] {
        assert!(!debug.contains(secret));
    }
}

#[test]
#[expect(
    clippy::default_numeric_fallback,
    reason = "synthetic JSON numbers mirror provider fields"
)]
fn typed_projection_rejects_wrong_type_duplicate_and_encoded_body() {
    let wrong_type = json!({
        "Code": 1000,
        "Labels": [{"ID":"label-1","Name":"Label","Type":3,"Order":1}]
    })
    .to_string();
    assert_eq!(
        ObservedMailboxCatalogResponse::parse(
            MailboxCatalogKind::Label,
            "GET",
            LABEL_URL,
            &wrong_type,
        ),
        Err(MailboxCatalogResponseError::Malformed)
    );

    let duplicate = json!({
        "Code": 1000,
        "Labels": [
            {"ID":"folder-1","Name":"A","Type":3,"Order":1},
            {"ID":"folder-1","Name":"B","Type":3,"Order":2}
        ]
    })
    .to_string();
    assert_eq!(
        ObservedMailboxCatalogResponse::parse(
            MailboxCatalogKind::Folder,
            "GET",
            FOLDER_URL,
            &duplicate,
        ),
        Err(MailboxCatalogResponseError::DuplicateId)
    );

    assert_eq!(
        ObservedMailboxCatalogResponse::parse(
            MailboxCatalogKind::Label,
            "GET",
            LABEL_URL,
            r#"{"Code":2000,"Labels":[]}"#,
        ),
        Err(MailboxCatalogResponseError::ProviderRejected)
    );

    let encoded = json!({"body":"e30=","base64Encoded":true});
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedMailboxCatalogResponse::parse_cdp_body(MailboxCatalogKind::SystemFolder, &encoded,),
        Err(MailboxCatalogResponseError::UnsupportedEncoding)
    );
}

#[test]
fn combined_catalog_separates_mailboxes_from_labels() {
    let system = ObservedMailboxCatalogResponse::parse(
        MailboxCatalogKind::SystemFolder,
        "GET",
        SYSTEM_URL,
        // jig-ignore-next-line: canonical rustfmt line.
        r#"{"Code":1000,"Labels":[{"ID":"0","Name":"Inbox","Type":4,"Order":1}]}"#,
    )
    .expect("project system folder");
    let folders = ObservedMailboxCatalogResponse::parse(
        MailboxCatalogKind::Folder,
        "GET",
        FOLDER_URL,
        concat!(
            // jig-ignore-next-line: canonical rustfmt line.
            "{\"Code\":1000,\"Labels\":[{\"ID\":\"folder-1\",\"Name\":\"Projects\",",
            "\"Type\":3,\"Order\":4,\"ParentID\":null}]}"
        ),
    )
    .expect("project folder");
    let labels = ObservedMailboxCatalogResponse::parse(
        MailboxCatalogKind::Label,
        "GET",
        LABEL_URL,
        // jig-ignore-next-line: canonical rustfmt line.
        r#"{"Code":1000,"Labels":[{"ID":"label-1","Name":"Important","Type":1,"Order":3}]}"#,
    )
    .expect("project label");
    // jig-ignore-next-line: canonical rustfmt line.
    let catalog = ObservedMailboxCatalog::from_responses(vec![labels, system, folders])
        .expect("combine complete catalog");
    assert_eq!(catalog.mailboxes().len(), 2);
    assert_eq!(
        catalog.mailboxes()[0].kind(),
        MailboxCatalogKind::SystemFolder
    );
    assert_eq!(catalog.mailboxes()[1].kind(), MailboxCatalogKind::Folder);
    assert_eq!(catalog.labels().len(), 1);
    assert_eq!(catalog.labels()[0].kind(), MailboxCatalogKind::Label);
    let debug = format!("{catalog:?}");
    assert!(!debug.contains("Projects"));
    assert!(!debug.contains("Important"));
}

#[test]
fn network_capture_tracks_only_exact_mail_category_gets() {
    let mut capture = MailboxCatalogNetworkCapture::new("session-a");
    capture
        .observe(&request("session-b", "other-session", "GET", LABEL_URL))
        .expect("ignore another session");
    capture
        .observe(&request(
            "session-a",
            "contact-group",
            "GET",
            "https://mail.proton.me/api/core/v4/labels?Type=2",
        ))
        .expect("ignore contact group");
    capture
        .observe(&request("session-a", "mutation", "POST", LABEL_URL))
        .expect("ignore mutation");
    capture
        .observe(&request("session-a", "label-1", "GET", LABEL_URL))
        .expect("track exact label request");
    capture
        .observe(&response("session-a", "label-1", LABEL_URL))
        .expect("accept exact label response");
    capture
        .observe(&finished("session-a", "label-1"))
        .expect("finish exact label request");
    assert_eq!(
        capture.take_finished_request_ids(),
        vec![String::from("label-1")]
    );
    let debug = format!("{capture:?}");
    for secret in ["synthetic-secret", "synthetic-cookie", "label-1"] {
        assert!(!debug.contains(secret));
    }
}

#[test]
fn network_capture_rejects_response_type_drift_and_allows_app_retry() {
    let mut drift = MailboxCatalogNetworkCapture::new("session-a");
    drift
        .observe(&request("session-a", "folder-1", "GET", FOLDER_URL))
        .expect("track folder request");
    assert_eq!(
        drift.observe(&response("session-a", "folder-1", LABEL_URL)),
        Err(MailboxCatalogNetworkError::ResponseRejected)
    );

    let mut retry = MailboxCatalogNetworkCapture::new("session-a");
    retry
        .observe(&request("session-a", "first", "GET", SYSTEM_URL))
        .expect("track first attempt");
    retry
        .observe(&failed("session-a", "first"))
        .expect("discard failed app attempt");
    retry
        .observe(&request("session-a", "second", "GET", SYSTEM_URL))
        .expect("track app-owned retry");
    retry
        .observe(&response("session-a", "second", SYSTEM_URL))
        .expect("accept retry response");
    retry
        .observe(&finished("session-a", "second"))
        .expect("finish retry");
    assert_eq!(
        retry.take_finished_request_ids(),
        vec![String::from("second")]
    );
}

#[test]
fn malformed_exact_query_and_endpoint_drift_fail_closed() {
    let mut capture = MailboxCatalogNetworkCapture::new("session-a");
    assert_eq!(
        capture.observe(&request(
            "session-a",
            "bad-type",
            "GET",
            "https://mail.proton.me/api/core/v4/labels?Type=abc",
        )),
        Err(MailboxCatalogNetworkError::MalformedEvent)
    );

    capture
        .observe(&request("session-a", "folder-1", "GET", FOLDER_URL))
        .expect("track exact folder request");
    assert_eq!(
        capture.observe(&request(
            "session-a",
            "folder-1",
            "GET",
            "https://mail.proton.me/api/core/v4/users",
        )),
        Err(MailboxCatalogNetworkError::RedirectedAway)
    );
}

fn catalog_browser_root(label: &str) -> PathBuf {
    use std::env;
    use std::process;

    env::temp_dir().join(format!(
        "protonmail-ai-mailbox-catalog-{label}-{}",
        process::id()
    ))
}

// jig-ignore-next-line: canonical rustfmt line.
#[expect(clippy::too_many_lines, reason = "one synthetic CDP browser lifecycle")]
// jig-ignore-next-line: canonical rustfmt line.
fn fake_catalog_browser(root: &Path, encoded_label: bool, duplicate_label: bool) -> PathBuf {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    let script = root.join("fake-browser");
    let log = root.join("catalog-log.txt");
    let template = r#"#!/usr/bin/env bash
set -eu
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
    *'Runtime.evaluate'*)
      value='{"protocol":"https:","hostname":"mail.proton.me","port":""}'
      printf '{"id":%s,"result":{"result":{"value":%s}}}\0' "$id" "$value" >&4;;
    *'DOM.getDocument'*)
      printf '{"id":%s,"result":{"root":{"nodeId":1}}}\0' "$id" >&4;;
    *'Accessibility.queryAXTree'*)
      case "$message" in
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        *'"role":"navigation"'*|*'"role":"search"'*) nodes='[{"ignored":false}]';;
        *'"role":"dialog"'*|*'"role":"alertdialog"'*) nodes='[]';;
        *) exit 91;;
      esac
      printf '{"id":%s,"result":{"nodes":%s}}\0' "$id" "$nodes" >&4;;
    *'Network.enable'*)
      printf 'enable\n' >> '__LOG__'
      printf '{"id":%s,"result":{}}\0' "$id" >&4;;
    *'Page.reload'*)
      printf 'reload\n' >> '__LOG__'
      for spec in 'label-1:1' 'folder-1:3' 'system-1:4' 'contacts-1:2'; do
        request_id=${spec%%:*}
        type=${spec##*:}
        url="https://mail.proton.me/api/core/v4/labels?Type=$type"
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        request='{"sessionId":"session-1","method":"Network.requestWillBeSent","params":{'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        request+='"requestId":"'"$request_id"'","request":{"method":"GET","url":"'"$url"'",'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        request+='"headers":{"Authorization":"Bearer synthetic-secret","Cookie":"synthetic-cookie"}}}}'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        response='{"sessionId":"session-1","method":"Network.responseReceived","params":{'
        response+='"requestId":"'"$request_id"'","response":{"url":"'"$url"'",'
        response+='"status":200,"mimeType":"application/json",'
        response+='"headers":{"Set-Cookie":"synthetic-cookie"}}}}'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        finished='{"sessionId":"session-1","method":"Network.loadingFinished","params":{'
        finished+='"requestId":"'"$request_id"'"}}'
        printf '%s\0%s\0%s\0' "$request" "$response" "$finished" >&4
      done
      if [ '__DUPLICATE_LABEL__' = 'true' ]; then
        url='https://mail.proton.me/api/core/v4/labels?Type=1'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        request='{"sessionId":"session-1","method":"Network.requestWillBeSent","params":{"requestId":"label-2","request":{"method":"GET","url":"'"$url"'"}}}'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        response='{"sessionId":"session-1","method":"Network.responseReceived","params":{"requestId":"label-2","response":{"url":"'"$url"'","status":200,"mimeType":"application/json"}}}'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        finished='{"sessionId":"session-1","method":"Network.loadingFinished","params":{"requestId":"label-2"}}'
        printf '%s\0%s\0%s\0' "$request" "$response" "$finished" >&4
      fi
      # jig-ignore-next-line: indivisible synthetic shell fixture.
      other='{"sessionId":"session-1","method":"Network.requestWillBeSent","params":{'
      other+='"requestId":"other","request":{"method":"GET",'
      other+='"url":"https://mail.proton.me/api/core/v4/users",'
      other+='"headers":{"Authorization":"Bearer unrelated-secret"}}}}'
      printf '%s\0' "$other" >&4
      printf '{"id":%s,"result":{}}\0' "$id" >&4;;
    *'Network.getResponseBody'*'"requestId":"folder-1"'*)
      printf 'body-folder\n' >> '__LOG__'
      body='{"Code":1000,"Labels":['
      # jig-ignore-next-line: indivisible synthetic shell fixture.
      body+='{"ID":"folder-parent","Name":"Projects","Type":3,"Order":2,"ParentID":null},'
      # jig-ignore-next-line: indivisible synthetic shell fixture.
      body+='{"ID":"folder-child","Name":"Nested","Type":3,"Order":3,"ParentID":"folder-parent"}]}'
      # jig-ignore-next-line: indivisible synthetic shell fixture.
      printf '{"id":%s,"result":{"body":"%s","base64Encoded":false}}\0' "$id" "${body//\"/\\\"}" >&4;;
    *'Network.getResponseBody'*'"requestId":"label-1"'*)
      printf 'body-label\n' >> '__LOG__'
      # jig-ignore-next-line: indivisible synthetic shell fixture.
      body='{"Code":1000,"Labels":[{"ID":"label-safe","Name":"Tag","Type":1,"Order":8}]}'
      # jig-ignore-next-line: indivisible synthetic shell fixture.
      printf '{"id":%s,"result":{"body":"%s","base64Encoded":__ENCODED_LABEL__}}\0' "$id" "${body//\"/\\\"}" >&4;;
    *'Network.getResponseBody'*'"requestId":"system-1"'*)
      printf 'body-system\n' >> '__LOG__'
      # jig-ignore-next-line: indivisible synthetic shell fixture.
      body='{"Code":1000,"Labels":[{"ID":"0","Name":"Inbox","Type":4,"Order":1}]}'
      # jig-ignore-next-line: indivisible synthetic shell fixture.
      printf '{"id":%s,"result":{"body":"%s","base64Encoded":false}}\0' "$id" "${body//\"/\\\"}" >&4;;
    *'Network.disable'*)
      printf 'disable\n' >> '__LOG__'
      printf '{"id":%s,"result":{}}\0' "$id" >&4;;
    *'Target.detachFromTarget'*)
      printf '{"id":%s,"result":{}}\0' "$id" >&4;;
    *) exit 92;;
  esac
done
"#;
    let body = template
        .replace("__LOG__", &log.display().to_string())
        .replace(
            "__ENCODED_LABEL__",
            if encoded_label { "true" } else { "false" },
        )
        .replace(
            "__DUPLICATE_LABEL__",
            if duplicate_label { "true" } else { "false" },
        );
    fs::write(&script, body).expect("write fake catalog browser");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
        .expect("chmod fake catalog browser");
    script
}

#[test]
fn managed_browser_passively_captures_complete_mail_catalog() {
    use std::fs;

    use mail_web_adapter::{ManagedBrowser, ManagedBrowserPlan};

    let _guard = CATALOG_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic catalog browser tests");
    let root = catalog_browser_root("complete");
    fs::create_dir_all(&root).expect("create catalog browser root");
    let browser = fake_catalog_browser(&root, false, false);
    let plan = ManagedBrowserPlan::under_data_home(
        browser.to_str().expect("catalog browser path UTF-8"),
        &root.join("data"),
    )
    .expect("build catalog browser plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch catalog browser");
    let page = managed.provider_page().expect("discover catalog Mail page");
    let catalog = managed
        .observe_mailbox_catalog(&page)
        .expect("passively capture complete catalog");
    assert_eq!(catalog.mailboxes().len(), 3);
    assert_eq!(catalog.mailboxes()[0].id(), "0");
    assert_eq!(catalog.mailboxes()[1].id(), "folder-parent");
    assert_eq!(catalog.mailboxes()[2].parent_id(), Some("folder-parent"));
    assert_eq!(catalog.labels().len(), 1);
    assert_eq!(catalog.labels()[0].id(), "label-safe");
    let debug = format!("{catalog:?}");
    for secret in [
        "Projects",
        "Nested",
        "Tag",
        "synthetic-secret",
        "synthetic-cookie",
        "unrelated-secret",
    ] {
        assert!(!debug.contains(secret));
    }
    drop(managed);
    // jig-ignore-next-line: canonical rustfmt line.
    let log = fs::read_to_string(root.join("catalog-log.txt")).expect("read catalog browser log");
    assert_eq!(
        log,
        "enable\nreload\nbody-folder\nbody-label\nbody-system\ndisable\n"
    );
    fs::remove_dir_all(&root).expect("remove catalog browser root");
}

#[test]
fn managed_browser_disables_network_after_encoded_catalog_body() {
    use std::fs;

    use mail_web_adapter::BrowserDriverError;
    use mail_web_adapter::{ManagedBrowser, ManagedBrowserPlan};

    let _guard = CATALOG_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic catalog browser tests");
    let root = catalog_browser_root("encoded");
    fs::create_dir_all(&root).expect("create encoded catalog browser root");
    let browser = fake_catalog_browser(&root, true, false);
    let plan = ManagedBrowserPlan::under_data_home(
        browser
            .to_str()
            .expect("encoded catalog browser path UTF-8"),
        &root.join("data"),
    )
    .expect("build encoded catalog browser plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch encoded catalog browser");
    let page = managed
        .provider_page()
        .expect("discover encoded catalog Mail page");
    let error = managed
        .observe_mailbox_catalog(&page)
        .expect_err("encoded catalog body must fail closed");
    assert_eq!(
        error,
        BrowserDriverError::MailboxCatalogResponse(
            MailboxCatalogResponseError::UnsupportedEncoding
        )
    );
    drop(managed);
    // jig-ignore-next-line: canonical rustfmt line.
    let log = fs::read_to_string(root.join("catalog-log.txt")).expect("read encoded catalog log");
    assert_eq!(log, "enable\nreload\nbody-folder\nbody-label\ndisable\n");
    fs::remove_dir_all(&root).expect("remove encoded catalog browser root");
}

#[test]
fn managed_browser_rejects_duplicate_catalog_kind_before_body_fetch() {
    use std::fs;

    use mail_web_adapter::BrowserDriverError;
    use mail_web_adapter::{ManagedBrowser, ManagedBrowserPlan};

    let _guard = CATALOG_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic catalog browser tests");
    let root = catalog_browser_root("duplicate-kind");
    fs::create_dir_all(&root).expect("create duplicate catalog browser root");
    let browser = fake_catalog_browser(&root, false, true);
    let plan = ManagedBrowserPlan::under_data_home(
        browser
            .to_str()
            .expect("duplicate catalog browser path UTF-8"),
        &root.join("data"),
    )
    .expect("build duplicate catalog browser plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch duplicate catalog browser");
    let page = managed
        .provider_page()
        .expect("discover duplicate catalog Mail page");
    assert_eq!(
        managed.observe_mailbox_catalog(&page),
        Err(BrowserDriverError::MailboxCatalogAmbiguous)
    );
    drop(managed);
    // jig-ignore-next-line: canonical rustfmt line.
    let log = fs::read_to_string(root.join("catalog-log.txt")).expect("read duplicate catalog log");
    assert_eq!(log, "enable\nreload\ndisable\n");
    fs::remove_dir_all(&root).expect("remove duplicate catalog browser root");
}

#[test]
fn catalog_projection_enforces_body_field_and_item_bounds() {
    let oversized_body = "x".repeat(262_145);
    assert_eq!(
        ObservedMailboxCatalogResponse::parse(
            MailboxCatalogKind::Label,
            "GET",
            LABEL_URL,
            &oversized_body,
        ),
        Err(MailboxCatalogResponseError::BodyTooLarge)
    );

    let oversized_id = "i".repeat(513);
    let body = json!({
        "Code": 1000u16,
        // jig-ignore-next-line: canonical rustfmt line.
        "Labels": [{"ID": oversized_id, "Name": "Safe", "Type": 1u8, "Order": 1i8}]
    })
    .to_string();
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedMailboxCatalogResponse::parse(MailboxCatalogKind::Label, "GET", LABEL_URL, &body,),
        Err(MailboxCatalogResponseError::Malformed)
    );

    let oversized_name = "n".repeat(1_025);
    let body = json!({
        "Code": 1000u16,
        // jig-ignore-next-line: canonical rustfmt line.
        "Labels": [{"ID": "label-1", "Name": oversized_name, "Type": 1u8, "Order": 1i8}]
    })
    .to_string();
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedMailboxCatalogResponse::parse(MailboxCatalogKind::Label, "GET", LABEL_URL, &body,),
        Err(MailboxCatalogResponseError::Malformed)
    );

    let labels = (0..2_049u16)
        .map(|index| {
            json!({
                "ID": format!("label-{index}"),
                "Name": "Safe",
                "Type": 1u8,
                "Order": i64::from(index),
            })
        })
        .collect::<Vec<_>>();
    let body = json!({"Code": 1000u16, "Labels": labels}).to_string();
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedMailboxCatalogResponse::parse(MailboxCatalogKind::Label, "GET", LABEL_URL, &body,),
        Err(MailboxCatalogResponseError::TooManyItems)
    );
}

#[test]
fn numeric_folder_parent_is_normalized_without_losing_identity() {
    let response = ObservedMailboxCatalogResponse::parse(
        MailboxCatalogKind::Folder,
        "GET",
        FOLDER_URL,
        // jig-ignore-next-line: canonical rustfmt line.
        r#"{"Code":1000,"Labels":[{"ID":"folder-7","Name":"Nested","Type":3,"Order":1,"ParentID":42}]}"#,
    )
    .expect("project numeric folder parent");
    assert_eq!(response.items()[0].parent_id(), Some("42"));
}

#[test]
fn combined_catalog_rejects_missing_duplicate_kind_and_cross_kind_id() {
    let system = ObservedMailboxCatalogResponse::parse(
        MailboxCatalogKind::SystemFolder,
        "GET",
        SYSTEM_URL,
        // jig-ignore-next-line: canonical rustfmt line.
        r#"{"Code":1000,"Labels":[{"ID":"shared","Name":"Inbox","Type":4,"Order":1}]}"#,
    )
    .expect("project system fixture");
    let folders = ObservedMailboxCatalogResponse::parse(
        MailboxCatalogKind::Folder,
        "GET",
        FOLDER_URL,
        r#"{"Code":1000,"Labels":[]}"#,
    )
    .expect("project empty folders fixture");
    let labels = ObservedMailboxCatalogResponse::parse(
        MailboxCatalogKind::Label,
        "GET",
        LABEL_URL,
        // jig-ignore-next-line: canonical rustfmt line.
        r#"{"Code":1000,"Labels":[{"ID":"shared","Name":"Tag","Type":1,"Order":2}]}"#,
    )
    .expect("project label fixture");

    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedMailboxCatalog::from_responses(vec![system.clone(), folders.clone()]),
        Err(MailboxCatalogResponseError::MissingKind)
    );
    assert_eq!(
        ObservedMailboxCatalog::from_responses(vec![
            system.clone(),
            folders.clone(),
            labels.clone(),
            labels.clone(),
        ]),
        Err(MailboxCatalogResponseError::DuplicateKind)
    );
    assert_eq!(
        ObservedMailboxCatalog::from_responses(vec![system, folders, labels]),
        Err(MailboxCatalogResponseError::DuplicateId)
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one authenticated catalog cursor transcript"
)]
fn managed_browser_pages_catalog_snapshot_without_provider_reread() {
    use std::fs;

    // jig-ignore-next-line: canonical rustfmt line.
    use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};

    let _guard = CATALOG_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic catalog browser tests");
    let root = catalog_browser_root("paged");
    fs::create_dir_all(&root).expect("create paged catalog root");
    let browser = fake_catalog_browser(&root, false, false);
    let plan = ManagedBrowserPlan::under_data_home(
        browser.to_str().expect("paged catalog browser path UTF-8"),
        &root.join("data"),
    )
    .expect("build paged catalog plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch paged catalog browser");
    // jig-ignore-next-line: canonical rustfmt line.
    let provider_page = managed.provider_page().expect("discover paged Mail page");
    let first = managed
        .observe_mailbox_catalog_page(
            &provider_page,
            "synthetic-account-secret",
            MailboxCatalogPageKind::Mailboxes,
            Some(2),
        )
        .expect("capture first immutable mailbox page");
    assert_eq!(first.items().len(), 2);
    assert_eq!(first.items()[0].id(), "0");
    assert_eq!(first.items()[1].id(), "folder-parent");
    let cursor = first
        .next_cursor()
        .expect("three mailboxes require continuation")
        .to_owned();
    assert!(cursor.starts_with("cat1."));
    for secret in [
        "synthetic-account-secret",
        "folder-parent",
        "Projects",
        "mailboxes",
    ] {
        assert!(!cursor.contains(secret));
    }
    let page_debug = format!("{first:?}");
    assert!(!page_debug.contains("folder-parent"));
    assert!(!page_debug.contains(&cursor));

    let second = managed
        .resume_mailbox_catalog_page(
            "synthetic-account-secret",
            MailboxCatalogPageKind::Mailboxes,
            Some(2),
            &cursor,
        )
        .expect("resume immutable mailbox snapshot locally");
    assert_eq!(second.items().len(), 1);
    assert_eq!(second.items()[0].id(), "folder-child");
    assert_eq!(second.next_cursor(), None);

    let replay = managed
        .resume_mailbox_catalog_page(
            "synthetic-account-secret",
            MailboxCatalogPageKind::Mailboxes,
            Some(2),
            &cursor,
        )
        .expect("replaying exact cursor returns exact page");
    assert_eq!(replay.items(), second.items());
    assert_eq!(replay.next_cursor(), second.next_cursor());

    assert_eq!(
        managed.resume_mailbox_catalog_page(
            "other-account",
            MailboxCatalogPageKind::Mailboxes,
            Some(2),
            &cursor,
        ),
        Err(BrowserDriverError::MailboxCatalogCursor(
            WebCatalogCursorCodecError::InvalidCursor
        ))
    );
    assert_eq!(
        managed.resume_mailbox_catalog_page(
            "synthetic-account-secret",
            MailboxCatalogPageKind::Labels,
            Some(2),
            &cursor,
        ),
        Err(BrowserDriverError::MailboxCatalogCursor(
            WebCatalogCursorCodecError::InvalidCursor
        ))
    );
    assert_eq!(
        managed.resume_mailbox_catalog_page(
            "synthetic-account-secret",
            MailboxCatalogPageKind::Mailboxes,
            Some(3),
            &cursor,
        ),
        Err(BrowserDriverError::MailboxCatalogCursor(
            WebCatalogCursorCodecError::InvalidCursor
        ))
    );

    let mut tampered = cursor.into_bytes();
    let body_start = tampered
        .iter()
        .rposition(|byte| *byte == b'.')
        .expect("opaque cursor has body separator")
        + 1;
    tampered[body_start] = if tampered[body_start] == b'A' {
        b'B'
    } else {
        b'A'
    };
    // jig-ignore-next-line: canonical rustfmt line.
    let tampered = String::from_utf8(tampered).expect("tampered cursor stays ASCII");
    assert_eq!(
        managed.resume_mailbox_catalog_page(
            "synthetic-account-secret",
            MailboxCatalogPageKind::Mailboxes,
            Some(2),
            &tampered,
        ),
        Err(BrowserDriverError::MailboxCatalogCursor(
            WebCatalogCursorCodecError::InvalidCursor
        ))
    );

    drop(managed);
    // jig-ignore-next-line: canonical rustfmt line.
    let log = fs::read_to_string(root.join("catalog-log.txt")).expect("read paged catalog log");
    assert_eq!(
        log,
        "enable\nreload\nbody-folder\nbody-label\nbody-system\ndisable\n"
    );
    fs::remove_dir_all(&root).expect("remove paged catalog root");
}

#[test]
fn catalog_page_size_and_account_fail_before_network_capture() {
    use std::fs;

    // jig-ignore-next-line: canonical rustfmt line.
    use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};

    let _guard = CATALOG_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic catalog browser tests");
    let root = catalog_browser_root("page-input");
    fs::create_dir_all(&root).expect("create page-input catalog root");
    let browser = fake_catalog_browser(&root, false, false);
    let plan = ManagedBrowserPlan::under_data_home(
        browser.to_str().expect("page-input browser path UTF-8"),
        &root.join("data"),
    )
    .expect("build page-input catalog plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch page-input browser");
    let provider_page = managed
        .provider_page()
        .expect("discover page-input Mail page");
    for page_size in [Some(0), Some(101)] {
        assert_eq!(
            managed.observe_mailbox_catalog_page(
                &provider_page,
                "account-a",
                MailboxCatalogPageKind::Labels,
                page_size,
            ),
            Err(BrowserDriverError::MailboxCatalogPage(
                MailboxCatalogPageError::InvalidPageSize
            ))
        );
    }
    assert_eq!(
        managed.observe_mailbox_catalog_page(
            &provider_page,
            "",
            MailboxCatalogPageKind::Labels,
            None,
        ),
        Err(BrowserDriverError::MailboxCatalogCursor(
            WebCatalogCursorCodecError::InvalidCursor
        ))
    );
    let overlong_account = "a".repeat(513);
    assert_eq!(
        managed.observe_mailbox_catalog_page(
            &provider_page,
            &overlong_account,
            MailboxCatalogPageKind::Labels,
            None,
        ),
        Err(BrowserDriverError::MailboxCatalogCursor(
            WebCatalogCursorCodecError::InvalidCursor
        ))
    );
    drop(managed);
    // jig-ignore-next-line: canonical rustfmt line.
    let log = fs::read_to_string(root.join("catalog-log.txt")).unwrap_or_default();
    assert!(log.is_empty());
    fs::remove_dir_all(&root).expect("remove page-input catalog root");
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one same-kind replacement and cross-kind retention transcript"
)]
fn replacing_same_kind_expires_old_cursor_but_other_kind_stays_resumable() {
    use std::fs;

    // jig-ignore-next-line: canonical rustfmt line.
    use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};

    let _guard = CATALOG_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic catalog browser tests");
    let root = catalog_browser_root("snapshot-replace");
    fs::create_dir_all(&root).expect("create snapshot-replace root");
    let browser = fake_catalog_browser(&root, false, false);
    let plan = ManagedBrowserPlan::under_data_home(
        browser
            .to_str()
            .expect("snapshot-replace browser path UTF-8"),
        &root.join("data"),
    )
    .expect("build snapshot-replace plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch snapshot-replace browser");
    let provider_page = managed
        .provider_page()
        .expect("discover snapshot-replace Mail page");
    let first = managed
        .observe_mailbox_catalog_page(
            &provider_page,
            "account-a",
            MailboxCatalogPageKind::Mailboxes,
            Some(2),
        )
        .expect("capture first mailbox snapshot");
    // jig-ignore-next-line: canonical rustfmt line.
    let old_cursor = first.next_cursor().expect("old mailbox cursor").to_owned();
    assert_eq!(
        managed.observe_mailbox_catalog_page(
            &provider_page,
            "account-a",
            MailboxCatalogPageKind::Mailboxes,
            Some(0),
        ),
        Err(BrowserDriverError::MailboxCatalogPage(
            MailboxCatalogPageError::InvalidPageSize
        ))
    );
    let after_invalid_start = managed
        .resume_mailbox_catalog_page(
            "account-a",
            MailboxCatalogPageKind::Mailboxes,
            Some(2),
            &old_cursor,
        )
        .expect("invalid replacement must retain old mailbox snapshot");
    assert_eq!(after_invalid_start.items()[0].id(), "folder-child");

    let labels = managed
        .observe_mailbox_catalog_page(
            &provider_page,
            "account-a",
            MailboxCatalogPageKind::Labels,
            Some(1),
        )
        .expect("capture independent label snapshot");
    assert_eq!(labels.items().len(), 1);
    assert_eq!(labels.next_cursor(), None);
    let still_valid = managed
        .resume_mailbox_catalog_page(
            "account-a",
            MailboxCatalogPageKind::Mailboxes,
            Some(2),
            &old_cursor,
        )
        .expect("label snapshot must not evict mailbox snapshot");
    assert_eq!(still_valid.items()[0].id(), "folder-child");

    let replacement = managed
        .observe_mailbox_catalog_page(
            &provider_page,
            "account-a",
            MailboxCatalogPageKind::Mailboxes,
            Some(2),
        )
        .expect("replace mailbox snapshot");
    let replacement_cursor = replacement
        .next_cursor()
        .expect("replacement mailbox cursor")
        .to_owned();
    assert_eq!(
        managed.resume_mailbox_catalog_page(
            "account-a",
            MailboxCatalogPageKind::Mailboxes,
            Some(2),
            &old_cursor,
        ),
        Err(BrowserDriverError::MailboxCatalogCursor(
            WebCatalogCursorCodecError::CursorExpired
        ))
    );
    assert_eq!(
        managed
            .resume_mailbox_catalog_page(
                "account-a",
                MailboxCatalogPageKind::Mailboxes,
                Some(2),
                &replacement_cursor,
            )
            .expect("replacement cursor resumes")
            .items()[0]
            .id(),
        "folder-child"
    );
    drop(managed);
    let log = fs::read_to_string(root.join("catalog-log.txt"))
        .expect("read snapshot-replace catalog log");
    // jig-ignore-next-line: canonical rustfmt line.
    let one_capture = "enable\nreload\nbody-folder\nbody-label\nbody-system\ndisable\n";
    assert_eq!(log, one_capture.repeat(3));
    fs::remove_dir_all(&root).expect("remove snapshot-replace root");
}

#[test]
fn catalog_cursor_expires_across_managed_browser_generation() {
    use std::fs;

    // jig-ignore-next-line: canonical rustfmt line.
    use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};

    let _guard = CATALOG_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic catalog browser tests");
    let first_root = catalog_browser_root("cursor-generation-first");
    // jig-ignore-next-line: canonical rustfmt line.
    fs::create_dir_all(&first_root).expect("create first cursor-generation root");
    let first_browser = fake_catalog_browser(&first_root, false, false);
    let first_plan = ManagedBrowserPlan::under_data_home(
        first_browser
            .to_str()
            .expect("first cursor-generation browser path UTF-8"),
        &first_root.join("data"),
    )
    .expect("build first cursor-generation plan");
    let cursor = {
        // jig-ignore-next-line: canonical rustfmt line.
        let mut managed = ManagedBrowser::launch(&first_plan).expect("launch first generation");
        let provider_page = managed
            .provider_page()
            .expect("discover first generation page");
        managed
            .observe_mailbox_catalog_page(
                &provider_page,
                "account-a",
                MailboxCatalogPageKind::Mailboxes,
                Some(2),
            )
            .expect("capture first generation catalog")
            .next_cursor()
            .expect("first generation cursor")
            .to_owned()
    };
    // jig-ignore-next-line: canonical rustfmt line.
    fs::remove_dir_all(&first_root).expect("remove first cursor-generation root");

    let second_root = catalog_browser_root("cursor-generation-second");
    // jig-ignore-next-line: canonical rustfmt line.
    fs::create_dir_all(&second_root).expect("create second cursor-generation root");
    let second_browser = fake_catalog_browser(&second_root, false, false);
    let second_plan = ManagedBrowserPlan::under_data_home(
        second_browser
            .to_str()
            .expect("second cursor-generation browser path UTF-8"),
        &second_root.join("data"),
    )
    .expect("build second cursor-generation plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let managed = ManagedBrowser::launch(&second_plan).expect("launch second generation");
    assert_eq!(
        managed.resume_mailbox_catalog_page(
            "account-a",
            MailboxCatalogPageKind::Mailboxes,
            Some(2),
            &cursor,
        ),
        Err(BrowserDriverError::MailboxCatalogCursor(
            WebCatalogCursorCodecError::CursorExpired
        ))
    );
    drop(managed);
    // jig-ignore-next-line: canonical rustfmt line.
    let log = fs::read_to_string(second_root.join("catalog-log.txt")).unwrap_or_default();
    assert!(log.is_empty());
    // jig-ignore-next-line: canonical rustfmt line.
    fs::remove_dir_all(&second_root).expect("remove second cursor-generation root");
}

#[test]
fn catalog_size_one_chain_is_complete_and_default_page_is_terminal() {
    use std::fs;

    use mail_web_adapter::{ManagedBrowser, ManagedBrowserPlan};

    let _guard = CATALOG_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic catalog browser tests");
    let root = catalog_browser_root("three-page");
    fs::create_dir_all(&root).expect("create three-page catalog root");
    let browser = fake_catalog_browser(&root, false, false);
    let plan = ManagedBrowserPlan::under_data_home(
        browser.to_str().expect("three-page browser path UTF-8"),
        &root.join("data"),
    )
    .expect("build three-page catalog plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch three-page catalog browser");
    let provider_page = managed
        .provider_page()
        .expect("discover three-page Mail page");

    let first = managed
        .observe_mailbox_catalog_page(
            &provider_page,
            "account-a",
            MailboxCatalogPageKind::Mailboxes,
            Some(1),
        )
        .expect("capture first single-item page");
    assert_eq!(first.items()[0].id(), "0");
    let first_cursor = first.next_cursor().expect("first cursor").to_owned();

    let second = managed
        .resume_mailbox_catalog_page(
            "account-a",
            MailboxCatalogPageKind::Mailboxes,
            Some(1),
            &first_cursor,
        )
        .expect("resume second single-item page");
    assert_eq!(second.items()[0].id(), "folder-parent");
    let second_cursor = second.next_cursor().expect("second cursor").to_owned();

    let replay_second = managed
        .resume_mailbox_catalog_page(
            "account-a",
            MailboxCatalogPageKind::Mailboxes,
            Some(1),
            &first_cursor,
        )
        .expect("replay second page state");
    assert_eq!(replay_second.items(), second.items());
    let replay_cursor = replay_second
        .next_cursor()
        .expect("replayed second page cursor")
        .to_owned();
    assert_ne!(replay_cursor, second_cursor);

    for cursor in [&second_cursor, &replay_cursor] {
        let third = managed
            .resume_mailbox_catalog_page(
                "account-a",
                MailboxCatalogPageKind::Mailboxes,
                Some(1),
                cursor,
            )
            .expect("both randomized cursors resume final state");
        assert_eq!(third.items()[0].id(), "folder-child");
        assert_eq!(third.next_cursor(), None);
    }

    let default_page = managed
        .observe_mailbox_catalog_page(
            &provider_page,
            "account-a",
            MailboxCatalogPageKind::Mailboxes,
            None,
        )
        .expect("default size captures terminal page");
    assert_eq!(default_page.items().len(), 3);
    assert_eq!(default_page.next_cursor(), None);

    drop(managed);
    let log =
        // jig-ignore-next-line: canonical rustfmt line.
        fs::read_to_string(root.join("catalog-log.txt")).expect("read three-page catalog log");
    // jig-ignore-next-line: canonical rustfmt line.
    let one_capture = "enable\nreload\nbody-folder\nbody-label\nbody-system\ndisable\n";
    assert_eq!(log, one_capture.repeat(2));
    fs::remove_dir_all(&root).expect("remove three-page catalog root");
}
