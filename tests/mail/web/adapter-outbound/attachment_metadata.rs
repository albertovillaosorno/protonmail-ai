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
use mail_web_adapter::{AttachmentMetadataResponseError, ObservedAttachmentMetadataResponse};
use serde_json::json;

// jig-ignore-next-line: canonical rustfmt line.
const URL: &str = "https://mail.proton.me/api/mail/v4/attachments/attachment-1/metadata";
const MESSAGE_ID: &str = "message-1";

fn metadata_body() -> serde_json::Value {
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
