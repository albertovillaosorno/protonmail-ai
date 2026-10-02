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
//   - Synthetic exact attachment-metadata response projection evidence.
// - Must-Not:
//   - Use live attachments, keys, signatures, mailbox data, or network access.
// - Allows:
//   - Prove attachment/message identity binding and metadata minimization.
// - Split-When:
//   - Browser lifecycle or plaintext attachment output needs separate fixtures.
// - Merge-When:
//   - One attachment acceptance suite owns both metadata and plaintext output.
// - Summary:
//   - Proves attachment metadata is bounded and parent-message scoped.
// - Description:
//   - Uses synthetic decoy cryptographic fields to verify they never escape.
// - Usage:
//   - Run through the `mail_web_adapter` integration-test target.
// - Defaults:
//   - Synthetic JSON only; no filesystem, browser, account, or network access.
//

//! Synthetic attachment-metadata parent-binding tests.

use mail_capability_domain::SanitizedAttachmentFilename;
// jig-ignore-next-line: canonical rustfmt line.
use mail_web_adapter::{AttachmentMetadataNetworkCapture, AttachmentMetadataNetworkError};
// jig-ignore-next-line: canonical rustfmt line.
use mail_web_adapter::{AttachmentMetadataResponseError, ObservedAttachmentMetadataResponse};
use serde_json::{Value, json};
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Mutex;
use std::time::Duration;

// jig-ignore-next-line: canonical rustfmt line.
const URL: &str = "https://mail.proton.me/api/mail/v4/attachments/attachment-1/metadata";
const MESSAGE_ID: &str = "message-1";

// jig-ignore-next-line: canonical rustfmt line.
fn request_event(session: &str, request_id: &str, method: &str, url: &str) -> Value {
    json!({
        "sessionId": session,
        "method": "Network.requestWillBeSent",
        "params": {
            "requestId": request_id,
            "request": {"method": method, "url": url,
                // jig-ignore-next-line: canonical rustfmt line.
                "headers": {"Authorization": "Bearer SECRET", "Cookie": "SECRET"}}
        }
    })
}

// jig-ignore-next-line: canonical rustfmt line.
fn response_event(session: &str, request_id: &str, url: &str, status: u64, mime: &str) -> Value {
    json!({
        "sessionId": session,
        "method": "Network.responseReceived",
        "params": {"requestId": request_id,
            "response": {"url": url, "status": status, "mimeType": mime,
                "headers": {"Set-Cookie": "SECRET"}}}
    })
}

fn finished_event(session: &str, request_id: &str) -> Value {
    json!({"sessionId": session, "method": "Network.loadingFinished",
        "params": {"requestId": request_id}})
}

fn failed_event(session: &str, request_id: &str) -> Value {
    json!({"sessionId": session, "method": "Network.loadingFailed",
        "params": {"requestId": request_id}})
}

fn metadata_body() -> Value {
    json!({
        "Code": 1000,
        "Attachment": {
            "ID": "attachment-1",
            "MessageID": MESSAGE_ID,
            "ConversationID": "SECRET-CONVERSATION",
            "Name": "../../report.pdf",
            "Size": 32_769u64,
            "MIMEType": "application/pdf",
            "Disposition": 0,
            // jig-ignore-next-line: canonical rustfmt line.
            "Sender": {"Name": "Secret Sender", "Address": "secret@example.test"},
            "KeyPackets": "SECRET-KEY-PACKET",
            "Signature": "SECRET-SIGNATURE",
            "EncSignature": "SECRET-ENC-SIGNATURE",
            "AddressID": "SECRET-ADDRESS-ID",
            "IsAutoForwardee": false
        }
    })
}

#[test]
fn metadata_projection_binds_parent_and_drops_crypto_fields() {
    let body = metadata_body().to_string();
    // jig-ignore-next-line: canonical rustfmt line.
    let observed = ObservedAttachmentMetadataResponse::parse("GET", URL, MESSAGE_ID, &body)
        .expect("project bound metadata");
    let metadata = observed.metadata();
    assert_eq!(metadata.attachment_id(), "attachment-1");
    assert_eq!(metadata.message_id(), MESSAGE_ID);
    assert_eq!(metadata.declared_size(), 32_769);
    assert_eq!(metadata.mime_type(), "application/pdf");
    assert_eq!(
        metadata
            .sanitized_name()
            .map(SanitizedAttachmentFilename::as_str),
        Some("___.._report.pdf")
    );
    let debug = format!("{observed:?}");
    for secret in [
        "attachment-1",
        MESSAGE_ID,
        "report.pdf",
        "SECRET-CONVERSATION",
        "Secret Sender",
        "secret@example.test",
        "SECRET-KEY-PACKET",
        "SECRET-SIGNATURE",
        "SECRET-ADDRESS-ID",
    ] {
        assert!(!debug.contains(secret));
    }
}

#[test]
fn metadata_projection_rejects_attachment_and_parent_identity_drift() {
    let mut wrong_attachment = metadata_body();
    wrong_attachment["Attachment"]["ID"] = json!("attachment-2");
    assert_eq!(
        ObservedAttachmentMetadataResponse::parse(
            "GET",
            URL,
            MESSAGE_ID,
            &wrong_attachment.to_string(),
        ),
        Err(AttachmentMetadataResponseError::AttachmentIdentityMismatch)
    );

    assert_eq!(
        ObservedAttachmentMetadataResponse::parse(
            "GET",
            URL,
            "message-2",
            &metadata_body().to_string()
        ),
        Err(AttachmentMetadataResponseError::ParentMessageMismatch)
    );
}

#[test]
fn metadata_projection_rejects_endpoint_provider_and_encoding_drift() {
    let body = metadata_body().to_string();
    for (method, url) in [
        ("POST", URL),
        (
            "GET",
            "https://mail.proton.me/api/mail/v4/attachments/attachment-1",
        ),
        (
            "GET",
            // jig-ignore-next-line: canonical rustfmt line.
            "https://mail.proton.me/api/mail/v4/attachments/attachment-1/metadata?x=1",
        ),
        (
            "GET",
            "https://mail.proton.me/api/mail/v4/attachments/a/b/metadata",
        ),
    ] {
        assert_eq!(
            // jig-ignore-next-line: canonical rustfmt line.
            ObservedAttachmentMetadataResponse::parse(method, url, MESSAGE_ID, &body),
            Err(AttachmentMetadataResponseError::UnexpectedEndpoint)
        );
    }
    let mut rejected = metadata_body();
    rejected["Code"] = json!(2_500u64);
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedAttachmentMetadataResponse::parse("GET", URL, MESSAGE_ID, &rejected.to_string()),
        Err(AttachmentMetadataResponseError::ProviderRejected)
    );
    let envelope = json!({"body": body, "base64Encoded": true});
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedAttachmentMetadataResponse::parse_cdp_body("attachment-1", MESSAGE_ID, &envelope),
        Err(AttachmentMetadataResponseError::UnsupportedEncoding)
    );
}

#[test]
fn metadata_projection_bounds_body_and_required_fields() {
    // jig-ignore-next-line: canonical rustfmt line.
    let huge = "x".repeat(ObservedAttachmentMetadataResponse::MAX_BODY_BYTES + 1);
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedAttachmentMetadataResponse::parse("GET", URL, MESSAGE_ID, &huge),
        Err(AttachmentMetadataResponseError::BodyTooLarge)
    );
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedAttachmentMetadataResponse::parse("GET", URL, "", &metadata_body().to_string()),
        Err(AttachmentMetadataResponseError::InvalidExpectedMessageId)
    );
    let mut malformed = metadata_body();
    malformed["Attachment"]["Size"] = json!(-1i64);
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedAttachmentMetadataResponse::parse("GET", URL, MESSAGE_ID, &malformed.to_string()),
        Err(AttachmentMetadataResponseError::Malformed)
    );
}

#[test]
fn metadata_network_capture_tracks_only_exact_get_lifecycle() {
    let mut capture = AttachmentMetadataNetworkCapture::new("session-a");
    capture
        .observe(&request_event("other", "foreign", "GET", URL))
        .expect("ignore foreign target session");
    capture
        .observe(&request_event(
            "session-a",
            "binary",
            "GET",
            "https://mail.proton.me/api/mail/v4/attachments/attachment-1",
        ))
        .expect("ignore encrypted binary endpoint");
    capture
        .observe(&request_event("session-a", "metadata", "GET", URL))
        .expect("track exact metadata request");
    capture
        .observe(&response_event(
            "session-a",
            "metadata",
            URL,
            200,
            "application/json",
        ))
        .expect("accept exact metadata response");
    capture
        .observe(&finished_event("session-a", "metadata"))
        .expect("finish exact metadata response");
    assert_eq!(
        capture.take_finished_requests(),
        vec![(String::from("metadata"), String::from("attachment-1"))]
    );
    assert_eq!(capture.tracked_request_count(), 0);
    let debug = format!("{capture:?}");
    for secret in ["session-a", "attachment-1", "SECRET"] {
        assert!(!debug.contains(secret));
    }
}

#[test]
fn metadata_network_capture_rejects_redirect_and_allows_app_retry() {
    let mut capture = AttachmentMetadataNetworkCapture::new("session-a");
    capture
        .observe(&request_event("session-a", "first", "GET", URL))
        .expect("track first metadata attempt");
    capture
        .observe(&failed_event("session-a", "first"))
        .expect("discard failed app attempt");
    assert_eq!(capture.tracked_request_count(), 0);
    capture
        .observe(&request_event("session-a", "retry", "GET", URL))
        .expect("track retry");
    assert_eq!(
        capture.observe(&request_event(
            "session-a",
            "retry",
            "GET",
            "https://mail.proton.me/inbox",
        )),
        Err(AttachmentMetadataNetworkError::RedirectedAway)
    );
}

#[test]
fn metadata_network_response_requires_same_identity_and_json_status() {
    for (url, status, mime) in [
        (
            // jig-ignore-next-line: canonical rustfmt line.
            "https://mail.proton.me/api/mail/v4/attachments/attachment-2/metadata",
            200,
            "application/json",
        ),
        (URL, 204, "application/json"),
        (URL, 200, "text/html"),
    ] {
        let mut capture = AttachmentMetadataNetworkCapture::new("session-a");
        capture
            .observe(&request_event("session-a", "metadata", "GET", URL))
            .expect("track exact metadata request");
        assert_eq!(
            // jig-ignore-next-line: canonical rustfmt line.
            capture.observe(&response_event("session-a", "metadata", url, status, mime,)),
            Err(AttachmentMetadataNetworkError::ResponseRejected)
        );
    }
}

#[test]
fn metadata_network_capture_bounds_unfinished_requests() {
    let mut capture = AttachmentMetadataNetworkCapture::new("session-a");
    for index in 0..16u8 {
        let request_id = format!("metadata-{index}");
        let url =
            // jig-ignore-next-line: canonical rustfmt line.
            format!("https://mail.proton.me/api/mail/v4/attachments/attachment-{index}/metadata");
        capture
            .observe(&request_event("session-a", &request_id, "GET", &url))
            .expect("within metadata request capacity");
    }
    assert_eq!(capture.tracked_request_count(), 16);
    assert_eq!(
        capture.observe(&request_event(
            "session-a",
            "overflow",
            "GET",
            "https://mail.proton.me/api/mail/v4/attachments/overflow/metadata",
        )),
        Err(AttachmentMetadataNetworkError::CapacityExceeded)
    );
}

static ATTACHMENT_BROWSER_TEST_LOCK: Mutex<()> = Mutex::new(());

fn attachment_browser_root(label: &str) -> PathBuf {
    env::temp_dir().join(format!(
        "protonmail-ai-attachment-metadata-{label}-{}",
        process::id()
    ))
}

fn fake_attachment_browser(
    root: &Path,
    emit_metadata: bool,
    response_message_id: &str,
    late_during_disable: bool,
) -> PathBuf {
    let script = root.join("fake-browser");
    let log = root.join("attachment-log.txt");
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
      printf '{"id":%s,"result":{}}\0' "$id" >&4
      if [ '__EMIT_METADATA__' = 'true' ]; then
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        url='https://mail.proton.me/api/mail/v4/attachments/attachment-1/metadata'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        request='{"sessionId":"session-1","method":"Network.requestWillBeSent","params":{'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        request+='"requestId":"metadata-1","request":{"method":"GET","url":"'"$url"'",'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        request+='"headers":{"Authorization":"Bearer secret","Cookie":"secret-cookie"}}}}'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        response='{"sessionId":"session-1","method":"Network.responseReceived","params":{'
        response+='"requestId":"metadata-1","response":{"url":"'"$url"'",'
        response+='"status":200,"mimeType":"application/json",'
        response+='"headers":{"Set-Cookie":"secret-cookie"}}}}'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        finished='{"sessionId":"session-1","method":"Network.loadingFinished","params":{'
        finished+='"requestId":"metadata-1"}}'
        printf '%s\0%s\0%s\0' "$request" "$response" "$finished" >&4
      fi;;
    *'Network.getResponseBody'*'"requestId":"metadata-1"'*)
      printf 'body\n' >> '__LOG__'
      body='{"Code":1000,"Attachment":{"ID":"attachment-1",'
      body+='"MessageID":"__MESSAGE_ID__","Name":"../../report.pdf",'
      body+='"Size":32769,"MIMEType":"application/pdf",'
      body+='"KeyPackets":"SECRET-KEY","Signature":"SECRET-SIGNATURE",'
      body+='"AddressID":"SECRET-ADDRESS"}}'
      printf '{"id":%s,"result":{"body":"%s","base64Encoded":false}}\0' \
        "$id" "${body//\"/\\\"}" >&4;;
    *'Network.disable'*)
      printf 'disable\n' >> '__LOG__'
      if [ '__LATE_METADATA__' = 'true' ]; then
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        url='https://mail.proton.me/api/mail/v4/attachments/attachment-late/metadata'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        request='{"sessionId":"session-1","method":"Network.requestWillBeSent","params":{'
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        request+='"requestId":"metadata-late","request":{"method":"GET","url":"'"$url"'"}}}'
        printf '%s\0' "$request" >&4
      fi
      printf '{"id":%s,"result":{}}\0' "$id" >&4;;
    *'Target.detachFromTarget'*)
      printf '{"id":%s,"result":{}}\0' "$id" >&4;;
    *'Page.reload'*) exit 94;;
    *) exit 92;;
  esac
done
"#;
    let body = template
        .replace("__LOG__", &log.display().to_string())
        .replace(
            "__EMIT_METADATA__",
            if emit_metadata { "true" } else { "false" },
        )
        .replace("__MESSAGE_ID__", response_message_id)
        .replace(
            "__LATE_METADATA__",
            if late_during_disable { "true" } else { "false" },
        );
    fs::write(&script, body).expect("write fake attachment browser");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
        .expect("chmod fake attachment browser");
    script
}

#[test]
fn managed_browser_passively_observes_attachment_metadata_without_navigation() {
    use mail_web_adapter::{ManagedBrowser, ManagedBrowserPlan};

    let _guard = ATTACHMENT_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic attachment browser tests");
    let root = attachment_browser_root("passive");
    fs::create_dir_all(&root).expect("create passive attachment root");
    let browser = fake_attachment_browser(&root, true, MESSAGE_ID, false);
    let plan = ManagedBrowserPlan::under_data_home(
        browser.to_str().expect("attachment browser path UTF-8"),
        &root.join("data"),
    )
    .expect("build passive attachment plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch attachment browser");
    let page = managed.provider_page().expect("discover passive Mail page");
    let observed = managed
        // jig-ignore-next-line: canonical rustfmt line.
        .observe_passive_attachment_metadata(&page, MESSAGE_ID, Duration::from_secs(1))
        .expect("observe browser-owned attachment metadata")
        .expect("attachment metadata should arrive");
    assert_eq!(observed.metadata().attachment_id(), "attachment-1");
    assert_eq!(observed.metadata().message_id(), MESSAGE_ID);
    assert_eq!(
        observed
            .metadata()
            .sanitized_name()
            .map(SanitizedAttachmentFilename::as_str),
        Some("___.._report.pdf")
    );
    drop(managed);
    let log =
        // jig-ignore-next-line: canonical rustfmt line.
        fs::read_to_string(root.join("attachment-log.txt")).expect("read passive attachment log");
    assert_eq!(log, "enable\nbody\ndisable\n");
    fs::remove_dir_all(&root).expect("remove passive attachment root");
}

#[test]
fn managed_browser_attachment_timeout_performs_no_provider_action() {
    // jig-ignore-next-line: canonical rustfmt line.
    use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};

    let _guard = ATTACHMENT_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic attachment browser tests");
    let root = attachment_browser_root("timeout");
    fs::create_dir_all(&root).expect("create timeout attachment root");
    let browser = fake_attachment_browser(&root, false, MESSAGE_ID, false);
    let plan = ManagedBrowserPlan::under_data_home(
        browser
            .to_str()
            .expect("timeout attachment browser path UTF-8"),
        &root.join("data"),
    )
    .expect("build timeout attachment plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch timeout browser");
    let page = managed.provider_page().expect("discover timeout Mail page");
    assert_eq!(
        managed
            // jig-ignore-next-line: canonical rustfmt line.
            .observe_passive_attachment_metadata(&page, MESSAGE_ID, Duration::from_millis(25))
            .expect("clean attachment metadata timeout"),
        None
    );
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        managed.observe_passive_attachment_metadata(&page, MESSAGE_ID, Duration::from_secs(31),),
        Err(BrowserDriverError::AttachmentMetadataWaitTooLong)
    );
    drop(managed);
    let log =
        // jig-ignore-next-line: canonical rustfmt line.
        fs::read_to_string(root.join("attachment-log.txt")).expect("read timeout attachment log");
    assert_eq!(log, "enable\ndisable\n");
    fs::remove_dir_all(&root).expect("remove timeout attachment root");
}

#[test]
fn attachment_parent_mismatch_disables_network_before_error() {
    use mail_web_adapter::{AttachmentMetadataResponseError, BrowserDriverError};
    use mail_web_adapter::{ManagedBrowser, ManagedBrowserPlan};

    let _guard = ATTACHMENT_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic attachment browser tests");
    let root = attachment_browser_root("parent-mismatch");
    fs::create_dir_all(&root).expect("create mismatch attachment root");
    let browser = fake_attachment_browser(&root, true, "message-other", false);
    let plan = ManagedBrowserPlan::under_data_home(
        browser
            .to_str()
            .expect("mismatch attachment browser path UTF-8"),
        &root.join("data"),
    )
    .expect("build mismatch attachment plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch mismatch browser");
    let page = managed
        .provider_page()
        .expect("discover mismatch Mail page");
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        managed.observe_passive_attachment_metadata(&page, MESSAGE_ID, Duration::from_secs(1),),
        Err(BrowserDriverError::AttachmentMetadataResponse(
            AttachmentMetadataResponseError::ParentMessageMismatch,
        ))
    );
    drop(managed);
    let log =
        // jig-ignore-next-line: canonical rustfmt line.
        fs::read_to_string(root.join("attachment-log.txt")).expect("read mismatch attachment log");
    assert_eq!(log, "enable\nbody\ndisable\n");
    fs::remove_dir_all(&root).expect("remove mismatch attachment root");
}

#[test]
fn attachment_started_during_network_disable_fails_closed() {
    // jig-ignore-next-line: canonical rustfmt line.
    use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};

    let _guard = ATTACHMENT_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic attachment browser tests");
    let root = attachment_browser_root("late-disable");
    fs::create_dir_all(&root).expect("create late attachment root");
    let browser = fake_attachment_browser(&root, true, MESSAGE_ID, true);
    let plan = ManagedBrowserPlan::under_data_home(
        browser
            .to_str()
            .expect("late attachment browser path UTF-8"),
        &root.join("data"),
    )
    .expect("build late attachment plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch late browser");
    let page = managed.provider_page().expect("discover late Mail page");
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        managed.observe_passive_attachment_metadata(&page, MESSAGE_ID, Duration::from_secs(1),),
        Err(BrowserDriverError::AttachmentMetadataAmbiguous)
    );
    drop(managed);
    let log =
        // jig-ignore-next-line: canonical rustfmt line.
        fs::read_to_string(root.join("attachment-log.txt")).expect("read late attachment log");
    assert_eq!(log, "enable\nbody\ndisable\n");
    fs::remove_dir_all(&root).expect("remove late attachment root");
}
