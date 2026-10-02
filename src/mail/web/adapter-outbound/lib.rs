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
//   - Proton Mail web-profile custody and semantic UI safety policy.
// - Must-Not:
//   - Mutate mailbox state, automate login challenges, read personal browser
//     profiles, or expose browser session state outside the adapter.
// - Allows:
//   - Launch a dedicated visible profile and gate mailbox UI targets.
// - Split-When:
//   - Browser-driver integration and UI policy require independent ownership.
// - Merge-When:
//   - One reviewed outbound adapter owns all web-provider behavior.
// - Summary:
//   - Defines the Free-plan Proton Mail web adapter boundary.
// - Description:
//   - Keeps browser session custody and semantic side-effect gates out of the
//     runtime composition root.
// - Usage:
//   - Runtime composition invokes the adapter after explicit human CLI actions.
// - Defaults:
//   - Bounded visible reads only; no mutation, send, challenge automation, or
//     remote-debugging TCP listener.
//

//! User-controlled Proton Mail web adapter.

#![forbid(unsafe_code)]

mod attachment_metadata;
mod catalog_cursor_codec;
mod conversation_detail;
mod conversation_list_response;
mod driver;
mod event_cursor_codec;
mod lease;
mod list_messages_readiness;
mod mailbox_catalog;
mod mailbox_catalog_page;
mod mailbox_event_watermark;
mod mailbox_list;
mod mailbox_mode;
mod mailbox_page;
mod mailbox_pagination;
mod mailbox_sort;
mod message_detail;
mod message_list_response;
mod policy;
mod profile;
mod shell;

pub use attachment_metadata::AttachmentMetadataNetworkCapture;
pub use attachment_metadata::AttachmentMetadataNetworkError;
pub use attachment_metadata::AttachmentMetadataResponseError;
pub use attachment_metadata::ObservedAttachmentMetadata;
pub use attachment_metadata::ObservedAttachmentMetadataResponse;
pub use catalog_cursor_codec::WebCatalogCursorCodecError;
pub use conversation_detail::ConversationDetailNetworkCapture;
pub use conversation_detail::ConversationDetailNetworkError;
pub use conversation_detail::ConversationDetailResponseError;
pub use conversation_detail::ObservedConversationDetail;
pub use conversation_detail::ObservedConversationDetailResponse;
pub use conversation_detail::ObservedConversationMember;
pub use conversation_list_response::ConversationListNetworkCapture;
pub use conversation_list_response::ConversationListNetworkError;
pub use conversation_list_response::ConversationListResponseError;
pub use conversation_list_response::ObservedConversationListMetadata;
pub use conversation_list_response::ObservedConversationListResponse;
pub use driver::SerializedMailboxChangePage;
pub use driver::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};
pub use driver::{MailboxEventCancellation, ProviderPage};
pub use event_cursor_codec::WebEventCursorCodecError;
pub use lease::{AutomationProfileLease, ProfileLeaseError};
pub use list_messages_readiness::{ListMessagesBlocker, ListMessagesReadiness};
pub use mailbox_catalog::MailboxCatalogKind;
pub use mailbox_catalog::MailboxCatalogNetworkCapture;
pub use mailbox_catalog::MailboxCatalogNetworkError;
pub use mailbox_catalog::MailboxCatalogResponseError;
pub use mailbox_catalog::ObservedMailboxCatalog;
pub use mailbox_catalog::ObservedMailboxCatalogItem;
pub use mailbox_catalog::ObservedMailboxCatalogResponse;
pub use mailbox_catalog_page::MailboxCatalogPageError;
pub use mailbox_catalog_page::MailboxCatalogPageKind;
pub use mailbox_catalog_page::SerializedMailboxCatalogPage;
pub use mailbox_event_watermark::LatestMailboxEventNetworkCapture;
pub use mailbox_event_watermark::MailboxEventSequenceError;
pub use mailbox_event_watermark::MailboxEventWatermarkError;
pub use mailbox_event_watermark::ObservedLatestMailboxEventWatermark;
pub use mailbox_event_watermark::ObservedMailboxChange;
pub use mailbox_event_watermark::ObservedMailboxChangePage;
pub use mailbox_event_watermark::ObservedMailboxEventSequence;
pub use mailbox_event_watermark::ObservedMailboxEventWatermark;
pub use mailbox_event_watermark::{MailboxChangeEntity, MailboxChangeKind};
// jig-ignore-next-line: canonical rustfmt line.
pub use mailbox_event_watermark::{MailboxEventNetworkCapture, MailboxEventNetworkError};
pub use mailbox_list::NextPageControl;
pub use mailbox_list::{MailboxListEvidence, MailboxListState};
pub use mailbox_mode::MailboxRenderMode;
pub use mailbox_mode::{MailboxModeError, MailboxModeEvidence};
pub use mailbox_page::VisibleMessagePageSnapshot;
pub use mailbox_page::{MailboxPageSnapshot, VisibleMailboxRow};
pub use mailbox_pagination::NextPageActivation;
pub use mailbox_sort::MailboxSortOrder;
pub use message_detail::MessageDetailNetworkCapture;
pub use message_detail::MessageDetailNetworkError;
pub use message_detail::MessageDetailResponseError;
pub use message_detail::ObservedAttachmentDescriptor;
pub use message_detail::ObservedMessageDetail;
pub use message_detail::ObservedMessageDetailResponse;
pub use message_detail::ObservedMessageRecipient;
pub use message_list_response::MessageListReconciliationError;
pub use message_list_response::ObservedMessageMetadata;
pub use message_list_response::ReconciledVisibleMessageMetadata;
// jig-ignore-next-line: canonical rustfmt line.
pub use message_list_response::{MessageListNetworkCapture, MessageListNetworkError};
// jig-ignore-next-line: canonical rustfmt line.
pub use message_list_response::{MessageListResponseError, ObservedMessageListResponse};
pub use policy::authorize_ui_target;
pub use policy::{AuthSurface, AuthenticatedMailSurface, PageOrigin};
pub use policy::{UiEvidence, UiGateError, UiTarget, WebSurface};
pub use profile::{DedicatedBrowserProfile, WebLoginError, WebLoginPlan};
pub use shell::MailShellEvidence;
