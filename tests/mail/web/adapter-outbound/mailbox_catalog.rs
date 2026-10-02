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

use mail_web_adapter::{MailboxCatalogKind, MailboxCatalogNetworkCapture};
use mail_web_adapter::{MailboxCatalogNetworkError, MailboxCatalogResponseError};
use mail_web_adapter::{ObservedMailboxCatalog, ObservedMailboxCatalogResponse};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const LABEL_URL: &str = "https://mail.proton.me/api/core/v4/labels?Type=1";
const FOLDER_URL: &str = "https://mail.proton.me/api/core/v4/labels?Type=3";
const SYSTEM_URL: &str = "https://mail.proton.me/api/core/v4/labels?Type=4";

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
        r#"{"Labels":[{"ID":"0","Name":"Inbox","Type":4,"Order":1}]}"#,
    )
    .expect("project system folder");
    let folders = ObservedMailboxCatalogResponse::parse(
        MailboxCatalogKind::Folder,
        "GET",
        FOLDER_URL,
        concat!(
            "{\"Labels\":[{\"ID\":\"folder-1\",\"Name\":\"Projects\",",
            "\"Type\":3,\"Order\":4,\"ParentID\":null}]}"
        ),
    )
    .expect("project folder");
    let labels = ObservedMailboxCatalogResponse::parse(
        MailboxCatalogKind::Label,
        "GET",
        LABEL_URL,
        // jig-ignore-next-line: canonical rustfmt line.
        r#"{"Labels":[{"ID":"label-1","Name":"Important","Type":1,"Order":3}]}"#,
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

fn fake_catalog_browser(root: &Path) -> PathBuf {
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
      printf '{"id":%s,"result":{"body":"%s","base64Encoded":false}}\0' "$id" "${body//\"/\\\"}" >&4;;
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
    let body = template.replace("__LOG__", &log.display().to_string());
    fs::write(&script, body).expect("write fake catalog browser");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
        .expect("chmod fake catalog browser");
    script
}

#[test]
fn managed_browser_passively_captures_complete_mail_catalog() {
    use std::fs;

    use mail_web_adapter::{ManagedBrowser, ManagedBrowserPlan};

    let root = catalog_browser_root("complete");
    fs::create_dir_all(&root).expect("create catalog browser root");
    let browser = fake_catalog_browser(&root);
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
