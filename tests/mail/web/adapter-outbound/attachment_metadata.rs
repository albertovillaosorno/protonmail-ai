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
fn retained_attachment_metadata_values_require_drop_custody() {
    use mail_web_adapter::ObservedAttachmentMetadata;

    #[expect(drop_bounds, reason = "require metadata scrubbing")]
    fn requires_scrub_on_drop<T>()
    where
        T: Drop,
    {
    }
    requires_scrub_on_drop::<ObservedAttachmentMetadata>();
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
fn standalone_attachment_metadata_neutralizes_bidi_filename() {
    let mut body = metadata_body();
    let deceptive = "statement\u{202e}fdp.exe";
    body["Attachment"]["Name"] = json!(deceptive);
    let raw = body.to_string();
    let project = ObservedAttachmentMetadataResponse::parse;
    let projected = project("GET", URL, MESSAGE_ID, &raw).expect("project");
    let safe = projected.metadata().sanitized_name();
    assert_eq!(
        safe.map(SanitizedAttachmentFilename::as_str),
        Some("statement_fdp.exe")
    );
    assert!(!format!("{projected:?}").contains(deceptive));
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
fn memory_cache_notification_cannot_authorize_attachment_get() {
    for after_response in [false, true] {
        let mut capture = AttachmentMetadataNetworkCapture::new("session-a");
        capture
            .observe(&request_event("session-a", "metadata", "GET", URL))
            .expect("track exact GET");
        let cache = json!({
            "sessionId": "session-a",
            "method": "Network.requestServedFromCache",
            "params": {"requestId": "metadata"}
        });
        let unrelated = json!({
            "sessionId": "session-a",
            "method": "Network.requestServedFromCache",
            "params": {"requestId": "unrelated"}
        });
        capture
            .observe(&unrelated)
            .expect("ignore unrelated cache event");
        if after_response {
            capture
                .observe(&response_event(
                    "session-a",
                    "metadata",
                    URL,
                    200,
                    "application/json",
                ))
                .expect("response before cache notice");
        }
        assert_eq!(
            capture.observe(&cache),
            Err(AttachmentMetadataNetworkError::ResponseRejected),
            "reject cache notice before or after responseReceived",
        );
        assert!(capture.take_finished_requests().is_empty());
    }
}

#[test]
fn cached_attachment_responses_cannot_authorize_provider_metadata() {
    for (source, value) in [
        ("fromDiskCache", json!(true)),
        ("fromServiceWorker", json!(true)),
        ("fromPrefetchCache", json!(true)),
        ("fromEarlyHints", json!(true)),
        ("fromEarlyHints", json!(null)),
        ("serviceWorkerResponseSource", json!("cache-storage")),
        ("serviceWorkerResponseSource", json!("network")),
        ("serviceWorkerResponseSource", json!(null)),
        ("cacheStorageCacheName", json!("mail-cache")),
        ("cacheStorageCacheName", json!(null)),
        (
            "serviceWorkerRouterInfo",
            json!({"actualSourceType":"cache"}),
        ),
        (
            "serviceWorkerRouterInfo",
            json!({"actualSourceType":"network"}),
        ),
        ("serviceWorkerRouterInfo", json!(null)),
        ("fromDiskCache", json!(null)),
        ("fromServiceWorker", json!("false")),
    ] {
        let mut capture = AttachmentMetadataNetworkCapture::new("session-a");
        capture
            .observe(&request_event("session-a", "metadata", "GET", URL))
            .expect("track exact GET");
        // jig-ignore-next-line: rustfmt canonical synthetic response.
        let mut response = response_event("session-a", "metadata", URL, 200, "application/json");
        response["params"]["response"][source] = value;
        assert_eq!(
            capture.observe(&response),
            Err(AttachmentMetadataNetworkError::ResponseRejected),
            "reject unsafe response provenance: {source}",
        );
        assert!(capture.take_finished_requests().is_empty());
    }

    let mut capture = AttachmentMetadataNetworkCapture::new("session-a");
    capture
        .observe(&request_event("session-a", "metadata", "GET", URL))
        .expect("track exact GET");
    // jig-ignore-next-line: rustfmt canonical synthetic response.
    let mut response = response_event("session-a", "metadata", URL, 200, "application/json");
    for source in [
        "fromDiskCache",
        "fromServiceWorker",
        "fromPrefetchCache",
        "fromEarlyHints",
    ] {
        response["params"]["response"][source] = json!(false);
    }
    capture.observe(&response).expect("uncached response");
    capture
        .observe(&finished_event("session-a", "metadata"))
        .expect("complete uncached response");
    assert_eq!(capture.take_finished_requests().len(), 1);
}

#[test]
fn redirected_into_exact_attachment_metadata_get_is_rejected() {
    let id = "redirected";
    let mut capture = AttachmentMetadataNetworkCapture::new("session-1");
    capture
        .observe(&request_event(
            "session-1",
            id,
            "GET",
            "https://mail.proton.me/other-resource",
        ))
        .expect("ignore initial unrelated request");
    let mut redirected = request_event("session-1", id, "GET", URL);
    redirected["params"]["redirectResponse"] = json!({
        "url": "https://mail.proton.me/other-resource"
    });
    assert_eq!(
        capture.observe(&redirected),
        Err(AttachmentMetadataNetworkError::RedirectedAway)
    );
    assert!(capture.take_finished_requests().is_empty());
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

#[expect(
    clippy::too_many_lines,
    reason = "synthetic CDP transcript includes session replies"
)]
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
      reply_format='{"id":%s,"sessionId":"session-1",'
      reply_format+='"result":{"result":{"value":%s}}}\0'
      printf "$reply_format" "$id" "$value" >&4;;
    *'DOM.getDocument'*)
      reply_format='{"id":%s,"sessionId":"session-1",'
      reply_format+='"result":{"root":{"nodeId":1}}}\0'
      printf "$reply_format" "$id" >&4;;
    *'Accessibility.queryAXTree'*)
      case "$message" in
        # jig-ignore-next-line: indivisible synthetic shell fixture.
        *'"role":"navigation"'*|*'"role":"search"'*) nodes='[{"ignored":false}]';;
        *'"role":"dialog"'*|*'"role":"alertdialog"'*) nodes='[]';;
        *) exit 91;;
      esac
      reply_format='{"id":%s,"sessionId":"session-1",'
      reply_format+='"result":{"nodes":%s}}\0'
      printf "$reply_format" "$id" "$nodes" >&4;;
    *'Network.enable'*)
      printf 'enable\n' >> '__LOG__'
      printf '{"id":%s,"sessionId":"session-1","result":{}}\0' "$id" >&4
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
      reply_format='{"id":%s,"sessionId":"session-1",'
      reply_format+='"result":{"body":"%s","base64Encoded":false}}\0'
      printf "$reply_format" \
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
      printf '{"id":%s,"sessionId":"session-1","result":{}}\0' "$id" >&4;;
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

#[test]
fn malformed_attachment_event_during_enable_disables_network() {
    // jig-ignore-next-line: canonical rustfmt line.
    use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};

    let _guard = ATTACHMENT_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic attachment browser tests");
    let root = attachment_browser_root("invalid-enable");
    fs::create_dir_all(&root).expect("create attachment browser root");
    let browser = fake_attachment_browser(&root, false, MESSAGE_ID, false);
    // jig-ignore-next-line: canonical rustfmt line.
    let script = fs::read_to_string(&browser).expect("read synthetic browser script");
    let marker = concat!(
        "      printf '{\"id\":%s,\"sessionId\":\"session-1\",",
        "\"result\":{}}\\0' \"$id\" >&4",
    );
    assert!(script.contains(marker));
    let invalid_event = json!({
        "sessionId": "session-1",
        "method": "Network.requestWillBeSent",
        "params": {
            "requestId": "bad-attachment",
            "request": {"method": null, "url": URL}
        }
    });
    let injection =
        // jig-ignore-next-line: canonical rustfmt line.
        format!("      invalid='{invalid_event}'\n      printf '%s\\0' \"$invalid\" >&4\n");
    let updated = script.replacen(marker, &format!("{injection}{marker}"), 1);
    fs::write(&browser, updated).expect("install invalid attachment event");
    let plan = ManagedBrowserPlan::under_data_home(
        browser.to_str().expect("synthetic browser UTF-8 path"),
        &root.join("data"),
    )
    .expect("build attachment test plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch fake browser");
    let page = managed.provider_page().expect("discover fake Mail page");
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        managed.observe_passive_attachment_metadata(&page, MESSAGE_ID, Duration::from_secs(1),),
        Err(BrowserDriverError::AttachmentMetadataNetwork(
            AttachmentMetadataNetworkError::MalformedEvent,
        ))
    );
    managed
        .require_mail_shell(&page)
        .expect("safe Mail inspection remains possible after failed enable");
    drop(managed);
    let log = fs::read_to_string(root.join("attachment-log.txt"))
        .expect("read synthetic Network lifecycle");
    assert_eq!(log, "enable\ndisable\n");
    fs::remove_dir_all(&root).expect("remove synthetic attachment root");
}

#[test]
fn rejected_network_enable_still_disables_attachment_observation() {
    // jig-ignore-next-line: canonical rustfmt line.
    use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};

    let _guard = ATTACHMENT_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic attachment browser tests");
    let root = attachment_browser_root("rejected-enable");
    fs::create_dir_all(&root).expect("create attachment browser root");
    let browser = fake_attachment_browser(&root, false, MESSAGE_ID, false);
    // jig-ignore-next-line: canonical rustfmt line.
    let script = fs::read_to_string(&browser).expect("read synthetic browser script");
    let reply = concat!(
        "      printf '{\"id\":%s,\"sessionId\":\"session-1\",",
        "\"result\":{}}\\0' \"$id\" >&4",
    );
    // jig-ignore-next-line: indivisible synthetic fixture command.
    let replacement = "      printf '{\"id\":%s,\"sessionId\":\"session-1\",\"error\":{\"code\":-32601,\"message\":\"synthetic unavailable\"}}\\0' \"$id\" >&4";
    assert!(script.contains(reply));
    let updated = script.replacen(reply, replacement, 1);
    fs::write(&browser, updated).expect("install synthetic CDP rejection");
    let plan = ManagedBrowserPlan::under_data_home(
        browser.to_str().expect("synthetic browser UTF-8 path"),
        &root.join("data"),
    )
    .expect("build attachment test plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch fake browser");
    let page = managed.provider_page().expect("discover fake Mail page");
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        managed.observe_passive_attachment_metadata(&page, MESSAGE_ID, Duration::from_secs(1),),
        Err(BrowserDriverError::Protocol)
    );
    managed
        .require_mail_shell(&page)
        .expect("safe shell observation remains possible after enable error");
    drop(managed);
    let log = fs::read_to_string(root.join("attachment-log.txt"))
        .expect("read synthetic Network lifecycle");
    assert_eq!(log, "enable\ndisable\n");
    fs::remove_dir_all(&root).expect("remove synthetic attachment root");
}

#[test]
fn consumed_detail_request_ids_reject_all_late_lifecycle_events() {
    let mut capture = AttachmentMetadataNetworkCapture::new("session-a");
    capture
        .observe(&request_event("session-a", "detail", "GET", URL))
        .expect("start app-owned read");
    capture
        .observe(&response_event(
            "session-a",
            "detail",
            URL,
            200,
            "application/json",
        ))
        .expect("observe exact read response");
    capture
        .observe(&finished_event("session-a", "detail"))
        .expect("complete exact read response");
    assert_eq!(
        capture.take_finished_requests(),
        vec![(String::from("detail"), String::from("attachment-1"))]
    );
    assert_eq!(capture.tracked_request_count(), 0);
    let debug = format!("{capture:?}");
    assert!(!debug.contains("detail"));
    assert!(!debug.contains("attachment-1"));
    for late in [
        request_event("session-a", "detail", "GET", URL),
        request_event("session-a", "detail", "POST", URL),
        response_event("session-a", "detail", URL, 200, "application/json"),
        finished_event("session-a", "detail"),
        failed_event("session-a", "detail"),
    ] {
        assert_eq!(
            capture.observe(&late),
            Err(AttachmentMetadataNetworkError::InvalidSequence)
        );
    }
    assert_eq!(capture.take_finished_requests().len(), 0);
}

#[test]
fn consumed_detail_request_markers_count_toward_capacity() {
    let mut capture = AttachmentMetadataNetworkCapture::new("session-a");
    for index in 0u8..16 {
        let request_id = format!("sensitive-{index}");
        capture
            .observe(&request_event("session-a", &request_id, "GET", URL))
            .expect("start bounded request");
        capture
            .observe(&response_event(
                "session-a",
                &request_id,
                URL,
                200,
                "application/json",
            ))
            .expect("match completed response");
        capture
            .observe(&finished_event("session-a", &request_id))
            .expect("finish bounded response");
        assert_eq!(
            capture.take_finished_requests(),
            vec![(request_id, String::from("attachment-1"))]
        );
        assert_eq!(capture.tracked_request_count(), 0);
    }
    assert!(!format!("{capture:?}").contains("sensitive-"));
    assert_eq!(
        capture.observe(&request_event("session-a", "overflow", "GET", URL)),
        Err(AttachmentMetadataNetworkError::CapacityExceeded)
    );
}

#[test]
fn completed_detail_id_reused_during_disable_fails_closed() {
    // jig-ignore-next-line: canonical rustfmt line.
    use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};
    let _guard = ATTACHMENT_BROWSER_TEST_LOCK
        .lock()
        .expect("lock synthetic browser fixture");
    let root = attachment_browser_root("reused-during-disable");
    fs::create_dir_all(&root).expect("create synthetic browser root");
    let browser = fake_attachment_browser(&root, true, MESSAGE_ID, true);
    // jig-ignore-next-line: canonical rustfmt line.
    let script = fs::read_to_string(&browser).expect("read synthetic browser fixture");
    assert!(script.contains("metadata-late"));
    fs::write(&browser, script.replace("metadata-late", "metadata-1"))
        .expect("install replayed synthetic CDP request ID");
    let plan = ManagedBrowserPlan::under_data_home(
        browser.to_str().expect("synthetic browser path UTF-8"),
        &root.join("data"),
    )
    .expect("build synthetic browser plan");
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&plan).expect("launch synthetic browser");
    let page = managed.provider_page().expect("discover fake Mail page");
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        managed.observe_passive_attachment_metadata(&page, MESSAGE_ID, Duration::from_secs(1)),
        Err(BrowserDriverError::AttachmentMetadataNetwork(
            AttachmentMetadataNetworkError::InvalidSequence,
        ))
    );
    managed
        .require_mail_shell(&page)
        .expect("safe Mail shell remains inspectable after replay rejection");
    drop(managed);
    // jig-ignore-next-line: canonical rustfmt line.
    let log = fs::read_to_string(root.join("attachment-log.txt")).expect("read Network lifecycle");
    assert_eq!(log, "enable\nbody\ndisable\n");
    fs::remove_dir_all(&root).expect("remove synthetic browser root");
}

#[test]
fn exact_detail_request_id_is_bounded_before_tracking() {
    for id in [String::new(), "x".repeat(513)] {
        let mut capture = AttachmentMetadataNetworkCapture::new("session-a");
        assert_eq!(
            capture.observe(&request_event("session-a", &id, "GET", URL)),
            Err(AttachmentMetadataNetworkError::MalformedEvent)
        );
        assert_eq!(capture.tracked_request_count(), 0);
        assert_eq!(capture.take_finished_requests().len(), 0);
    }
    let mut capture = AttachmentMetadataNetworkCapture::new("session-a");
    capture
        .observe(&request_event(
            "session-a",
            &"x".repeat(1024),
            "GET",
            "https://mail.proton.me/api/mail/v4/attachments",
        ))
        .expect("unrelated browser traffic is ignored");
    assert_eq!(capture.tracked_request_count(), 0);
}

#[test]
fn completed_response_cannot_be_erased_by_late_failure_before_consumption() {
    let mut capture = AttachmentMetadataNetworkCapture::new("session-a");
    capture
        .observe(&request_event("session-a", "ready", "GET", URL))
        .expect("start exact GET");
    capture
        .observe(&response_event(
            "session-a",
            "ready",
            URL,
            200,
            "application/json",
        ))
        .expect("match response");
    capture
        .observe(&finished_event("session-a", "ready"))
        .expect("finish response");
    assert_eq!(
        capture.observe(&failed_event("session-a", "ready")),
        Err(AttachmentMetadataNetworkError::InvalidSequence),
    );
    assert_eq!(
        capture.take_finished_requests(),
        [(String::from("ready"), String::from("attachment-1"))]
    );
}

#[test]
fn detail_url_backslash_is_not_a_safe_opaque_id_separator() {
    let mut capture = AttachmentMetadataNetworkCapture::new("session-a");
    let unsafe_url = URL.replace("attachment-1", "attachment-1\\adjacent");
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        capture.observe(&request_event("session-a", "bad-path", "GET", &unsafe_url)),
        Err(AttachmentMetadataNetworkError::MalformedEvent)
    );
    assert_eq!(capture.take_finished_requests().len(), 0);
}

#[test]
fn metadata_identity_rejects_unsafe_route_and_caller_ids() {
    for bad in [
        "encoded%2Fslash",
        "%2e",
        "%2E%2E",
        "direction\u{202e}flip",
        "invisible\u{200b}join",
        "isolated\u{2066}id\u{2069}",
        "soft\u{ad}hyphen",
        "combining\u{34f}joiner",
        "mongolian\u{180e}separator",
        "invisible\u{2061}function",
        "deprecated\u{206a}direction",
        "unicode\u{e0020}tag",
        "bad/id",
        "bad?id",
        "bad#id",
        "bad\\id",
        "bad id",
        "bad\nid",
        "bad\tid",
        "bad\rid",
        "bad\u{a0}id",
        "bad\u{7f}id",
        ".",
        "..",
    ] {
        // jig-ignore-next-line: canonical rustfmt line.
        let invalid_url = format!("https://mail.proton.me/api/mail/v4/attachments/{bad}/metadata");
        assert_eq!(
            ObservedAttachmentMetadataResponse::parse(
                "GET",
                &invalid_url,
                MESSAGE_ID,
                &metadata_body().to_string()
            ),
            Err(AttachmentMetadataResponseError::UnexpectedEndpoint)
        );
        let mut capture = AttachmentMetadataNetworkCapture::new("session-a");
        assert_eq!(
            capture.observe(&request_event(
                "session-a",
                "bad-request",
                "GET",
                &invalid_url
            )),
            Err(AttachmentMetadataNetworkError::MalformedEvent)
        );
        assert_eq!(
            ObservedAttachmentMetadataResponse::parse(
                "GET",
                URL,
                bad,
                &metadata_body().to_string()
            ),
            Err(AttachmentMetadataResponseError::InvalidExpectedMessageId)
        );
        let mut attachment = metadata_body();
        attachment["Attachment"]["ID"] = json!(bad);
        assert_eq!(
            ObservedAttachmentMetadataResponse::parse(
                "GET",
                URL,
                MESSAGE_ID,
                &attachment.to_string()
            ),
            Err(AttachmentMetadataResponseError::Malformed)
        );
        let mut parent = metadata_body();
        parent["Attachment"]["MessageID"] = json!(bad);
        assert_eq!(
            // jig-ignore-next-line: canonical rustfmt line.
            ObservedAttachmentMetadataResponse::parse("GET", URL, MESSAGE_ID, &parent.to_string()),
            Err(AttachmentMetadataResponseError::Malformed)
        );
    }
    let invalid_envelope = json!({
        "base64Encoded":false,"body":metadata_body().to_string()
    });
    assert_eq!(
        ObservedAttachmentMetadataResponse::parse_cdp_body(
            "bad\nid",
            MESSAGE_ID,
            &invalid_envelope
        ),
        Err(AttachmentMetadataResponseError::UnexpectedEndpoint)
    );
}

#[test]
fn metadata_identity_preserves_printable_opaque_identifiers() {
    let mut body = metadata_body();
    body["Attachment"]["ID"] = json!("attach+_~=");
    body["Attachment"]["MessageID"] = json!("parent+_~=");
    // jig-ignore-next-line: canonical rustfmt line.
    let url = "https://mail.proton.me/api/mail/v4/attachments/attach+_~=/metadata";
    let projected =
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedAttachmentMetadataResponse::parse("GET", url, "parent+_~=", &body.to_string())
            .expect("accept safe opaque attachment and parent IDs");
    assert_eq!(projected.metadata().attachment_id(), "attach+_~=");
    assert_eq!(projected.metadata().message_id(), "parent+_~=");
    assert_eq!(projected.metadata().mime_type(), "application/pdf");
}

#[test]
fn attachment_mime_rejects_controls_and_header_injection() {
    for invalid in [
        "text/plain\r\nX-Injected: yes",
        "application/pdf\u{0}",
        "image/\u{7f}png",
        "text/plain\n",
        "not-a-media-type",
    ] {
        let mut body = metadata_body();
        body["Attachment"]["MIMEType"] = json!(invalid);
        let observed =
            // jig-ignore-next-line: canonical rustfmt metadata boundary call.
            ObservedAttachmentMetadataResponse::parse("GET", URL, MESSAGE_ID, &body.to_string());
        assert_eq!(observed, Err(AttachmentMetadataResponseError::Malformed));
    }
}

#[test]
fn attachment_metadata_body_envelope_rejects_unexpected_cdp_fields() {
    let mut result = json!({
        "body":metadata_body().to_string(),"base64Encoded":false
    });
    assert!(
        // jig-ignore-next-line: canonical rustfmt envelope test.
        ObservedAttachmentMetadataResponse::parse_cdp_body("attachment-1", MESSAGE_ID, &result)
            .is_ok()
    );
    result["unrecognized"] = json!(true);
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt envelope test.
        ObservedAttachmentMetadataResponse::parse_cdp_body("attachment-1", MESSAGE_ID, &result),
        Err(AttachmentMetadataResponseError::Malformed)
    );
}

#[test]
fn mime_parameters_reject_ambiguous_or_incomplete_values() {
    for invalid in [
        "text/plain; charset",
        "text/plain; charset=",
        "text/plain; =UTF-8",
        "text/plain; charset=UTF-8;",
        "text/plain; charset=U TF-8",
        "text/plain; charset=UTF-8; broken",
        "text/plain; charset=\"unterminated",
        "text/plain; charset=UTF-8; CHARSET=ISO-8859-1",
    ] {
        let mut body = metadata_body();
        body["Attachment"]["MIMEType"] = json!(invalid);
        let raw = body.to_string();
        // jig-ignore-next-line: canonical rustfmt metadata parser call.
        let observed = ObservedAttachmentMetadataResponse::parse("GET", URL, MESSAGE_ID, &raw);
        assert_eq!(observed, Err(AttachmentMetadataResponseError::Malformed));
    }
}

#[test]
fn mime_parameters_accept_valid_quoted_and_token_values() {
    for valid in [
        "text/plain; charset=UTF-8",
        "text/plain; charset=\"UTF-8\"",
        "application/pdf; name=sample.pdf",
        "application/pdf; name=\"sample; 2026.pdf\"",
        "multipart/mixed; boundary=\"part\\\"next\"",
    ] {
        let mut body = metadata_body();
        body["Attachment"]["MIMEType"] = json!(valid);
        let observed =
            // jig-ignore-next-line: canonical rustfmt metadata parser call.
            ObservedAttachmentMetadataResponse::parse("GET", URL, MESSAGE_ID, &body.to_string());
        assert!(
            observed.is_ok(),
            "valid synthetic MIME parameter must parse"
        );
    }
}

#[test]
fn mime_parameter_names_compare_case_insensitively_at_bounded_scale() {
    use std::fmt::Write as _;

    let mut distinct = String::from("application/octet-stream");
    for index in 0usize..60 {
        write!(&mut distinct, "; k{index}=v").expect("synthetic MIME name");
    }
    assert!(distinct.len() <= 512);
    let mut body = metadata_body();
    body["Attachment"]["MIMEType"] = json!(&distinct);
    assert!(
        // jig-ignore-next-line: rustfmt keeps the MIME parser call together.
        ObservedAttachmentMetadataResponse::parse("GET", URL, MESSAGE_ID, &body.to_string())
            .is_ok()
    );

    // The first occurrence is far away from the second, and names differ
    // only in ASCII case. No duplicate may be concealed among other keys.
    let duplicate = format!("{distinct}; K7=overridden");
    assert!(duplicate.len() <= 512);
    body["Attachment"]["MIMEType"] = json!(duplicate);
    assert_eq!(
        // jig-ignore-next-line: rustfmt keeps the MIME parser call together.
        ObservedAttachmentMetadataResponse::parse("GET", URL, MESSAGE_ID, &body.to_string()),
        Err(AttachmentMetadataResponseError::Malformed)
    );

    // A quoted parameter value with delimiters is not another parameter.
    body["Attachment"]["MIMEType"] =
        json!("application/pdf; name=\"Report; DRAFT.pdf\"; NAME2=present");
    assert!(
        // jig-ignore-next-line: rustfmt keeps the MIME parser call together.
        ObservedAttachmentMetadataResponse::parse("GET", URL, MESSAGE_ID, &body.to_string())
            .is_ok()
    );
}

#[test]
fn cdp_body_projection_matches_exact_get_without_rebuilding_private_url() {
    let body = metadata_body().to_string();
    let envelope = json!({"body": body, "base64Encoded": false});
    let exact = ObservedAttachmentMetadataResponse::parse(
        "GET",
        URL,
        MESSAGE_ID,
        envelope["body"].as_str().expect("synthetic body"),
    );
    let from_cdp = ObservedAttachmentMetadataResponse::parse_cdp_body;
    let captured = from_cdp("attachment-1", MESSAGE_ID, &envelope);
    assert_eq!(captured, exact);
}

#[test]
fn borrowed_attachment_fields_refuse_late_mime_injection_without_leakage() {
    let mut body = metadata_body();
    body["Attachment"]["MIMEType"] = json!("text/plain\r\nX-Secret: unsafe");
    let from_url = ObservedAttachmentMetadataResponse::parse;
    let observed = from_url("GET", URL, MESSAGE_ID, &body.to_string());
    assert_eq!(observed, Err(AttachmentMetadataResponseError::Malformed));
    let diagnostic = format!("{observed:?}");
    assert!(!diagnostic.contains("attachment-1"));
    assert!(!diagnostic.contains("X-Secret"));
}
