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
//   - Managed Chromium process and private `DevTools` pipe transport.
// - Must-Not:
//   - Open a debugging TCP port, automate login, or expose session material.
// - Allows:
//   - Launch the dedicated profile and issue bounded browser-level CDP calls.
// - Split-When:
//   - Semantic Mail page extraction becomes independently substantial.
// - Merge-When:
//   - One outbound adapter owns browser lifecycle and semantic inspection.
// - Summary:
//   - Runs managed Chromium over a private file-descriptor `DevTools` pipe.
// - Description:
//   - Uses FD 3/4 ASCIIZ CDP framing and only the dedicated browser profile.
// - Usage:
//   - Start after visible login has been completed and the profile is closed.
// - Defaults:
//   - No TCP listener, no DOM mutation, and no authentication automation.
//

//! Managed Chromium `DevTools` pipe for the dedicated Proton Mail profile.

use crate::strict_json;
use nix::errno::Errno;

use std::collections::HashSet;
use std::fmt;
use std::io::{Error as IoError, ErrorKind, Read as _, Write as _};
use std::mem::take;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::slice::from_ref;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use command_fds::{CommandFdExt as _, FdMapping};
use mail_capability_domain::EventCursorBindingError;
use mail_capability_domain::EventCursorResumeFailure;
use mail_capability_domain::{EventCursorScope, ScopedEventCursor};
use serde_json::{Value, json};
use zeroize::{Zeroize as _, Zeroizing};

use crate::attachment_metadata::AttachmentMetadataNetworkCapture;
use crate::attachment_metadata::AttachmentMetadataNetworkError;
use crate::attachment_metadata::AttachmentMetadataResponseError;
use crate::attachment_metadata::ObservedAttachmentMetadataResponse;
use crate::attachment_metadata::validate_expected_message_id;
use crate::catalog_cursor_codec::validate_catalog_account;
// jig-ignore-next-line: canonical rustfmt line.
use crate::catalog_cursor_codec::{WebCatalogCursorCodec, WebCatalogCursorCodecError};
use crate::conversation_detail::ConversationDetailNetworkCapture;
use crate::conversation_detail::ConversationDetailNetworkError;
use crate::conversation_detail::ConversationDetailResponseError;
use crate::conversation_detail::ObservedConversationDetailResponse;
use crate::conversation_list_response::CapturedConversationListRequest;
use crate::conversation_list_response::ConversationListNetworkCapture;
use crate::conversation_list_response::ConversationListNetworkError;
use crate::conversation_list_response::ConversationListReconciliationError;
use crate::conversation_list_response::ConversationListResponseError;
use crate::conversation_list_response::ObservedConversationListResponse;
use crate::conversation_list_response::ReconciledVisibleConversationMetadata;
use crate::event_cursor_codec::{WebEventCursorCodec, WebEventCursorCodecError};
use crate::lease::{AutomationProfileLease, ProfileLeaseError};
use crate::list_messages_readiness::ListMessagesReadiness;
use crate::mailbox_catalog::MailboxCatalogNetworkCapture;
use crate::mailbox_catalog::MailboxCatalogNetworkError;
use crate::mailbox_catalog::MailboxCatalogResponseError;
use crate::mailbox_catalog::ObservedMailboxCatalog;
use crate::mailbox_catalog::ObservedMailboxCatalogResponse;
use crate::mailbox_catalog_page::MailboxCatalogPageError;
use crate::mailbox_catalog_page::MailboxCatalogPageKind;
use crate::mailbox_catalog_page::MailboxCatalogSnapshot;
use crate::mailbox_catalog_page::MailboxCatalogSnapshotPage;
use crate::mailbox_catalog_page::SerializedMailboxCatalogPage;
use crate::mailbox_catalog_page::validate_page_size;
use crate::mailbox_event_watermark::LatestMailboxEventNetworkCapture;
use crate::mailbox_event_watermark::MailboxEventNetworkCapture;
use crate::mailbox_event_watermark::MailboxEventNetworkError;
use crate::mailbox_event_watermark::MailboxEventSequenceError;
use crate::mailbox_event_watermark::MailboxEventWatermarkError;
use crate::mailbox_event_watermark::ObservedLatestMailboxEventWatermark;
use crate::mailbox_event_watermark::ObservedMailboxChange;
use crate::mailbox_event_watermark::ObservedMailboxChangePage;
use crate::mailbox_event_watermark::ObservedMailboxEventSequence;
use crate::mailbox_event_watermark::ObservedMailboxEventWatermark;
use crate::mailbox_list::NextPageControl;
use crate::mailbox_list::{MailboxListEvidence, MailboxListState};
use crate::mailbox_mode::{MailboxModeEvidence, MailboxRenderMode};
use crate::mailbox_page::{MailboxPageSnapshot, VisibleMessagePageSnapshot};
use crate::mailbox_pagination::NextPageActivation;
use crate::mailbox_sort::MailboxSortOrder;
use crate::message_detail::MessageDetailNetworkCapture;
use crate::message_detail::MessageDetailNetworkError;
use crate::message_detail::MessageDetailResponseError;
use crate::message_detail::ObservedMessageDetailResponse;
use crate::message_list_response::MessageListNetworkCapture;
use crate::message_list_response::MessageListNetworkError;
use crate::message_list_response::MessageListReconciliationError;
use crate::message_list_response::MessageListResponseError;
use crate::message_list_response::ObservedMessageListResponse;
use crate::message_list_response::ObservedMessageMetadata;
use crate::message_list_response::ReconciledVisibleMessageMetadata;
use crate::policy::PageOrigin;
use crate::profile::PRIVATE_PROFILE_FLAGS;
use crate::profile::user_data_dir_argument;
use crate::profile::{DedicatedBrowserProfile, WebLoginError, WebLoginPlan};
use crate::shell::MailShellEvidence;

const MAIL_URL: &str = "https://mail.proton.me/";
const LOCATION_EXPRESSION: &str = concat!(
    "({protocol:location.protocol,hostname:location.hostname,",
    "port:location.port})"
);
const DEVTOOLS_READ_FD: i32 = 3;
const DEVTOOLS_WRITE_FD: i32 = 4;
const MAX_FRAME_BYTES: usize = 1_048_576;
const CDP_READ_CACHE_BYTES: usize = 8192;
const MAX_UNSOLICITED: u16 = 128;
const PIPE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_TEXT_BUSY_RETRIES: u8 = 12;
const SHUTDOWN_DELAY: Duration = Duration::from_millis(20);
const SHUTDOWN_POLLS: u16 = 100;
const PAGE_ADVANCE_DELAY: Duration = Duration::from_millis(50);
const SORT_MENU_DELAY: Duration = Duration::from_millis(20);
const SORT_MENU_TIMEOUT: Duration = Duration::from_secs(2);
const PAGE_ADVANCE_TIMEOUT: Duration = Duration::from_secs(10);
const MESSAGE_LIST_CAPTURE_TIMEOUT: Duration = Duration::from_secs(10);
const CONVERSATION_DETAIL_MAX_WAIT: Duration = Duration::from_secs(30);
const CONVERSATION_LIST_MAX_WAIT: Duration = Duration::from_secs(30);
const CONVERSATION_DETAIL_TOTAL_BUFFER_BYTES: usize = 16_777_216;
const CONVERSATION_LIST_TOTAL_BUFFER_BYTES: usize = 1_048_576;
const MESSAGE_DETAIL_MAX_WAIT: Duration = Duration::from_secs(30);
const MESSAGE_DETAIL_TOTAL_BUFFER_BYTES: usize = 16_777_216;
const ATTACHMENT_METADATA_MAX_WAIT: Duration = Duration::from_secs(30);
const ATTACHMENT_METADATA_TOTAL_BUFFER_BYTES: usize = 1_048_576;
const MAILBOX_CATALOG_CAPTURE_TIMEOUT: Duration = Duration::from_secs(10);
const MAILBOX_CATALOG_TOTAL_BUFFER_BYTES: usize = 1_048_576;
const MESSAGE_LIST_TOTAL_BUFFER_BYTES: usize = 1_048_576;
const MAILBOX_EVENT_MAX_WAIT: Duration = Duration::from_secs(30);
const MAILBOX_EVENT_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(10);
const MAILBOX_EVENT_CANCEL_POLL: Duration = Duration::from_millis(25);
const WEB_ADAPTER_CURSOR_SCOPE_ID: &str = "proton-mail-web-v1";
const WEB_ADAPTER_GENERATION_BYTES: usize = 16;
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
const MAILBOX_EVENT_TOTAL_BUFFER_BYTES: usize = 1_048_576;

struct CompletedMessageListRequest {
    request_id: String,
    continuation: bool,
    limit: usize,
    page: Option<u32>,
    sort_key: String,
    descending: bool,
    anchor: Option<u64>,
    anchor_id: Option<String>,
}

#[expect(
    clippy::missing_trait_methods,
    reason = "Drop is the explicit scrub-on-drop contract"
)]
impl Drop for CompletedMessageListRequest {
    fn drop(&mut self) {
        self.request_id.zeroize();
        self.sort_key.zeroize();
        if let Some(anchor) = self.anchor_id.as_mut() {
            anchor.zeroize();
        }
    }
}

struct CapturedConversationListResponse {
    response: ObservedConversationListResponse,
    requested_page: Option<u32>,
    anchor_continuation: bool,
    initial_page_shape: bool,
}

struct CapturedMessageListResponses {
    responses: Vec<ObservedMessageListResponse>,
    initial_page: u32,
    initial_limit: usize,
    initial_sort_key: String,
    initial_descending: bool,
}

#[expect(
    clippy::missing_trait_methods,
    reason = "Drop is the explicit scrub-on-drop contract"
)]
impl Drop for CapturedMessageListResponses {
    fn drop(&mut self) {
        self.initial_sort_key.zeroize();
        // Owned response rows scrub their identifiers individually.
    }
}

impl CapturedMessageListResponses {
    fn received_at_descending(&self) -> bool {
        self.initial_sort_key == "Time" && self.initial_descending
    }

    fn provider_neutral_tie_break_proven(&self) -> bool {
        if !self.received_at_descending() || self.initial_page != 0 {
            return false;
        }
        let Some(first) = self.responses.first() else {
            return false;
        };
        let Ok(limit) = u64::try_from(self.initial_limit) else {
            return false;
        };
        if first.total() <= limit {
            return true;
        }
        let Some(last) = first.messages().last() else {
            return false;
        };
        let Some(next) = self
            .responses
            .get(1)
            .and_then(|response| response.messages().first())
        else {
            return false;
        };
        last.time() != next.time()
    }
}

struct InitialMailboxEventCapture {
    latest: LatestMailboxEventNetworkCapture,
    events: MailboxEventNetworkCapture,
}

impl InitialMailboxEventCapture {
    fn new(session: &str) -> Self {
        Self {
            latest: LatestMailboxEventNetworkCapture::new(session),
            events: MailboxEventNetworkCapture::new(session),
        }
    }
}

impl CdpEventObserver for InitialMailboxEventCapture {
    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_event(&mut self, event: &Value) -> Result<(), BrowserDriverError> {
        self.latest
            .observe(event)
            .map_err(BrowserDriverError::MailboxEventNetwork)?;
        self.events
            .observe(event)
            .map_err(BrowserDriverError::MailboxEventNetwork)
    }
}

/// Cooperative cancellation handle for one bounded passive mailbox-event wait.
#[derive(Clone, Debug, Default)]
pub struct MailboxEventCancellation {
    cancelled: Arc<AtomicBool>,
}

impl MailboxEventCancellation {
    /// Creates a non-cancelled handle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation of an in-progress bounded wait.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Returns whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// Opaque generation identity for one managed web-adapter lifetime.
#[derive(Clone, Eq, PartialEq)]
struct WebAdapterGeneration(String);

#[expect(
    clippy::missing_trait_methods,
    reason = "Drop is the explicit scrub-on-drop contract"
)]
impl Drop for WebAdapterGeneration {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl WebAdapterGeneration {
    fn fresh() -> Result<Self, BrowserDriverError> {
        fresh_web_adapter_tag().map(Self)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for WebAdapterGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted-web-adapter-generation>")
    }
}

/// Immutable launch settings for one managed dedicated-profile browser.
#[derive(Clone, Eq, PartialEq)]
pub struct ManagedBrowserPlan {
    browser: String,
    profile: DedicatedBrowserProfile,
}

impl fmt::Debug for ManagedBrowserPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedBrowserPlan")
            .field("browser", &"<redacted>")
            .field("profile", &self.profile)
            .finish()
    }
}

impl ManagedBrowserPlan {
    /// Resolves browser executable and dedicated profile from process context.
    ///
    /// # Errors
    ///
    /// Returns the same fail-closed setup errors as visible login planning.
    pub fn from_environment() -> Result<Self, WebLoginError> {
        let login = WebLoginPlan::from_environment()?;
        Ok(Self {
            browser: String::from(login.browser()),
            profile: login.profile().clone(),
        })
    }

    /// Creates a plan beneath an explicit absolute data home.
    ///
    /// The fixed `protonmail-ai/browser-profile` suffix is always appended.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty browser executable or relative data home.
    // jig-ignore-next-line: canonical rustfmt line.
    pub fn under_data_home(browser: &str, data_home: &Path) -> Result<Self, WebLoginError> {
        if browser.is_empty() {
            return Err(WebLoginError::BrowserUnavailable);
        }
        Ok(Self {
            browser: String::from(browser),
            profile: DedicatedBrowserProfile::under_data_home(data_home)?,
        })
    }

    /// Returns the fixed dedicated profile directory.
    #[must_use]
    pub fn profile_dir(&self) -> &Path {
        self.profile.path()
    }
}

/// One provider page discovered without exposing its title or full URL.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderPage {
    origin: PageOrigin,
    target_id: String,
}

impl fmt::Debug for ProviderPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderPage")
            .field("origin", &self.origin)
            .field("target_id", &"<redacted>")
            .finish()
    }
}

#[expect(
    clippy::missing_trait_methods,
    reason = "Drop is the explicit scrub-on-drop contract"
)]
impl Drop for ProviderPage {
    fn drop(&mut self) {
        self.target_id.zeroize();
    }
}

impl ProviderPage {
    /// Returns the trusted provider origin classification.
    #[must_use]
    pub const fn origin(&self) -> PageOrigin {
        self.origin
    }
}

/// Provider-neutral mailbox changes with one authenticated opaque next cursor.
#[derive(Clone, Eq, PartialEq)]
pub struct SerializedMailboxChangePage {
    changes: Vec<ObservedMailboxChange>,
    count_changes: bool,
    next_cursor: String,
}

#[expect(
    clippy::missing_trait_methods,
    reason = "Drop is the explicit scrub-on-drop contract"
)]
impl Drop for SerializedMailboxChangePage {
    fn drop(&mut self) {
        self.next_cursor.zeroize();
        // Normalized changes scrub their identifiers on drop.
    }
}

impl SerializedMailboxChangePage {
    /// Returns ordered normalized mailbox changes.
    #[must_use]
    pub fn changes(&self) -> &[ObservedMailboxChange] {
        &self.changes
    }

    /// Returns whether count-only mailbox change signals were also observed.
    #[must_use]
    pub const fn count_changes(&self) -> bool {
        self.count_changes
    }

    /// Returns the authenticated opaque cursor for the next bounded wait.
    #[must_use]
    pub fn next_cursor(&self) -> &str {
        &self.next_cursor
    }
}

impl fmt::Debug for SerializedMailboxChangePage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SerializedMailboxChangePage")
            .field("change_count", &self.changes.len())
            .field("count_changes", &self.count_changes)
            .field("next_cursor", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SortMenuActivation {
    AlreadyOpen,
    Opened,
}

impl SortMenuActivation {
    fn from_value(value: &Value) -> Result<Self, BrowserDriverError> {
        if value.as_object().is_none_or(|fields| fields.len() != 2) {
            return Err(BrowserDriverError::MailboxSortIncompatible);
        }
        let already_open = value.get("alreadyOpen").and_then(Value::as_bool);
        let clicked = value.get("clicked").and_then(Value::as_bool);
        match (already_open, clicked) {
            (Some(true), Some(false)) => Ok(Self::AlreadyOpen),
            (Some(false), Some(true)) => Ok(Self::Opened),
            _ => Err(BrowserDriverError::MailboxSortIncompatible),
        }
    }
}

// A standard BufReader leaves provider frame bytes in its internal allocation
// after consume(), even though read_frame() owns a zeroizing output. Retain
// bounded read-ahead for coalesced CDP replies, but scrub each consumed prefix
// immediately; the remaining unread suffix is erased when the reader drops.
struct SensitiveFrameReader {
    stream: UnixStream,
    cache: Zeroizing<[u8; CDP_READ_CACHE_BYTES]>,
    offset: usize,
    filled: usize,
}

impl SensitiveFrameReader {
    fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            cache: Zeroizing::new([0; CDP_READ_CACHE_BYTES]),
            offset: 0,
            filled: 0,
        }
    }

    const fn get_ref(&self) -> &UnixStream {
        &self.stream
    }

    const fn get_mut(&mut self) -> &mut UnixStream {
        &mut self.stream
    }

    fn fill_buf(&mut self) -> Result<&[u8], IoError> {
        if self.offset == self.filled {
            // consume() has already scrubbed every byte in the old cache.
            // Reset both bounds *before* I/O: a timeout must not make the
            // next read expose the prior (now zeroed) buffer as new data.
            self.offset = 0;
            self.filled = 0;
            self.filled = self.stream.read(&mut self.cache[..])?;
        }
        Ok(&self.cache[self.offset..self.filled])
    }

    fn consume(&mut self, amount: usize) {
        // Match BufRead::consume's saturation semantics for a bad caller.
        let end = self.offset.saturating_add(amount).min(self.filled);
        self.cache[self.offset..end].zeroize();
        self.offset = end;
    }
}

/// Managed Chromium process connected over private `DevTools` file descriptors.
pub struct ManagedBrowser {
    child: Child,
    catalog_cursor_codec: WebCatalogCursorCodec,
    cursor_codec: WebEventCursorCodec,
    generation: WebAdapterGeneration,
    label_catalog_snapshot: Option<MailboxCatalogSnapshot>,
    mailbox_catalog_snapshot: Option<MailboxCatalogSnapshot>,
    next_id: u64,
    reader: SensitiveFrameReader,
    writer: UnixStream,
    _lease: AutomationProfileLease,
}

impl fmt::Debug for ManagedBrowser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedBrowser")
            .field("generation", &self.generation)
            .field("cursor_codec", &self.cursor_codec)
            .field("catalog_cursor_codec", &self.catalog_cursor_codec)
            .field(
                "mailbox_catalog_present",
                &self.mailbox_catalog_snapshot.is_some(),
            )
            .field(
                "label_catalog_present",
                &self.label_catalog_snapshot.is_some(),
            )
            .finish_non_exhaustive()
    }
}

trait CdpEventObserver {
    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_event(&mut self, event: &Value) -> Result<(), BrowserDriverError>;
}

impl CdpEventObserver for ConversationListNetworkCapture {
    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_event(&mut self, event: &Value) -> Result<(), BrowserDriverError> {
        self.observe(event)
            .map_err(BrowserDriverError::ConversationListNetwork)
    }
}

impl CdpEventObserver for ConversationDetailNetworkCapture {
    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_event(&mut self, event: &Value) -> Result<(), BrowserDriverError> {
        self.observe(event)
            .map_err(BrowserDriverError::ConversationDetailNetwork)
    }
}

impl CdpEventObserver for AttachmentMetadataNetworkCapture {
    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_event(&mut self, event: &Value) -> Result<(), BrowserDriverError> {
        self.observe(event)
            .map_err(BrowserDriverError::AttachmentMetadataNetwork)
    }
}

impl CdpEventObserver for MailboxCatalogNetworkCapture {
    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_event(&mut self, event: &Value) -> Result<(), BrowserDriverError> {
        self.observe(event)
            .map_err(BrowserDriverError::MailboxCatalogNetwork)
    }
}

impl CdpEventObserver for MessageDetailNetworkCapture {
    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_event(&mut self, event: &Value) -> Result<(), BrowserDriverError> {
        self.observe(event)
            .map_err(BrowserDriverError::MessageDetailNetwork)
    }
}

impl CdpEventObserver for MessageListNetworkCapture {
    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_event(&mut self, event: &Value) -> Result<(), BrowserDriverError> {
        self.observe(event)
            .map_err(BrowserDriverError::MessageListNetwork)
    }
}

impl CdpEventObserver for LatestMailboxEventNetworkCapture {
    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_event(&mut self, event: &Value) -> Result<(), BrowserDriverError> {
        self.observe(event)
            .map_err(BrowserDriverError::MailboxEventNetwork)
    }
}

impl CdpEventObserver for MailboxEventNetworkCapture {
    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_event(&mut self, event: &Value) -> Result<(), BrowserDriverError> {
        self.observe(event)
            .map_err(BrowserDriverError::MailboxEventNetwork)
    }
}

impl ManagedBrowser {
    // jig-ignore-next-line: canonical rustfmt line.
    /// Launches Chromium with the dedicated profile and private `DevTools` pipe.
    ///
    /// # Errors
    ///
    /// Fails if profile ownership, pipe setup, browser launch, or the initial
    /// `Browser.getVersion` handshake cannot be verified.
    // jig-ignore-next-line: canonical rustfmt line.
    pub fn launch(plan: &ManagedBrowserPlan) -> Result<Self, BrowserDriverError> {
        let generation = WebAdapterGeneration::fresh()?;
        let cursor_codec =
            // jig-ignore-next-line: canonical rustfmt line.
            WebEventCursorCodec::fresh().map_err(|_error| BrowserDriverError::GenerationEntropy)?;
        let catalog_cursor_codec = WebCatalogCursorCodec::fresh()
            .map_err(|_error| BrowserDriverError::GenerationEntropy)?;
        let lease = AutomationProfileLease::acquire(&plan.profile)
            .map_err(BrowserDriverError::ProfileLease)?;
        let (writer, child_read) =
            UnixStream::pair().map_err(|_error| BrowserDriverError::PipeSetup)?;
        let (child_write, reader) =
            UnixStream::pair().map_err(|_error| BrowserDriverError::PipeSetup)?;
        reader
            .set_read_timeout(Some(PIPE_TIMEOUT))
            .map_err(|_error| BrowserDriverError::PipeSetup)?;
        writer
            .set_write_timeout(Some(PIPE_TIMEOUT))
            .map_err(|_error| BrowserDriverError::PipeSetup)?;

        let child = spawn_browser(plan, child_read, child_write)?;
        let mut browser = Self {
            child,
            catalog_cursor_codec,
            cursor_codec,
            generation,
            label_catalog_snapshot: None,
            mailbox_catalog_snapshot: None,
            next_id: 1,
            reader: SensitiveFrameReader::new(reader),
            writer,
            _lease: lease,
        };
        browser.verify_handshake()?;
        Ok(browser)
    }

    /// Creates the event-cursor scope for this managed browser generation.
    ///
    /// The caller supplies the authenticated account identity. Adapter identity
    /// is fixed to this web adapter and generation rotates on every browser
    /// launch, so cursors cannot silently cross adapter/browser restarts.
    ///
    /// # Errors
    ///
    /// Returns the provider-neutral scope validation error for an invalid
    /// authenticated account identifier.
    pub fn event_cursor_scope(
        &self,
        account: &str,
    ) -> Result<EventCursorScope, EventCursorBindingError> {
        EventCursorScope::new(
            account,
            WEB_ADAPTER_CURSOR_SCOPE_ID,
            self.generation.as_str(),
        )
    }

    /// Serializes one exact scoped event cursor into an opaque public token.
    ///
    /// # Errors
    ///
    /// Fails for scope drift, invalid provider state, entropy failure, or an
    /// unexpected authenticated-encryption failure.
    pub fn encode_event_cursor(
        &self,
        cursor: &ScopedEventCursor<String>,
        current_scope: &EventCursorScope,
    ) -> Result<String, WebEventCursorCodecError> {
        self.cursor_codec
            .encode(self.generation.as_str(), cursor, current_scope)
    }

    /// Authenticates one public event cursor for this managed browser.
    ///
    /// # Errors
    ///
    /// Returns `InvalidCursor` for malformed, tampered, account, or adapter
    /// drift and `CursorExpired` for an older web-adapter generation.
    pub fn decode_event_cursor(
        &self,
        token: &str,
        current_scope: &EventCursorScope,
    ) -> Result<ScopedEventCursor<String>, WebEventCursorCodecError> {
        self.cursor_codec
            .decode(self.generation.as_str(), token, current_scope)
    }

    /// Returns the single Proton provider page currently exposed by Chromium.
    ///
    /// Titles and complete URLs remain inside the adapter and are never part of
    /// this result.
    ///
    /// # Errors
    ///
    /// Fails closed if no provider page exists, more than one exists, or CDP
    /// returns malformed target metadata.
    // jig-ignore-next-line: canonical rustfmt line.
    pub fn provider_page(&mut self) -> Result<ProviderPage, BrowserDriverError> {
        let result = self.call("Target.getTargets", &json!({}))?;
        let infos = result
            .get("targetInfos")
            .and_then(Value::as_array)
            .ok_or(BrowserDriverError::Protocol)?;
        // One dedicated browser profile should not expose an unbounded target
        // catalog to a mail observer; fail before parsing page identities.
        if infos.len() > MAX_DISCOVERABLE_TARGETS {
            return Err(BrowserDriverError::Protocol);
        }
        let mut selected = None;
        for info in infos {
            let Some(page) = provider_page_from_target(info)? else {
                continue;
            };
            if selected.is_some() {
                return Err(BrowserDriverError::AmbiguousProviderPages);
            }
            selected = Some(page);
        }
        selected.ok_or(BrowserDriverError::MissingProviderPage)
    }

    /// Re-checks provider origin inside the selected page execution context.
    ///
    /// Only location protocol, hostname, and port are evaluated. No DOM,
    /// storage, cookie, message, or authentication value is requested.
    ///
    /// # Errors
    ///
    /// Fails if target metadata and live page location disagree.
    pub fn verify_provider_origin(
        &mut self,
        page: &ProviderPage,
    ) -> Result<PageOrigin, BrowserDriverError> {
        let session = self.attach(page)?;
        let observed = self.runtime_origin(&session);
        let detached = self.detach(&session);
        let origin = observed?;
        detached?;
        if origin != page.origin {
            return Err(BrowserDriverError::OriginDrift {
                expected: page.origin,
                observed: origin,
            });
        }
        Ok(origin)
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn attach(&mut self, page: &ProviderPage) -> Result<Zeroizing<String>, BrowserDriverError> {
        // Both the source params and returned session token must scrub on drop.
        let params = strict_json::SensitiveValue::from_owned(
            json!({"targetId": page.target_id, "flatten": true}),
        );
        let result = self.call("Target.attachToTarget", &params)?;
        result
            .get("sessionId")
            .and_then(Value::as_str)
            .filter(|id| safe_cdp_endpoint_id(id))
            .map(|id| Zeroizing::new(String::from(id)))
            .ok_or(BrowserDriverError::Protocol)
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn runtime_origin(&mut self, session: &str) -> Result<PageOrigin, BrowserDriverError> {
        let value = self.runtime_value(session, LOCATION_EXPRESSION)?;
        // The static projection emits exactly these three properties.
        // Accepting an extended object would silently widen origin evidence.
        if value.as_object().is_none_or(|fields| fields.len() != 3) {
            return Err(BrowserDriverError::Protocol);
        }
        let protocol = value
            .get("protocol")
            .and_then(Value::as_str)
            .ok_or(BrowserDriverError::Protocol)?;
        let hostname = value
            .get("hostname")
            .and_then(Value::as_str)
            .ok_or(BrowserDriverError::Protocol)?;
        let port = value
            .get("port")
            .and_then(Value::as_str)
            .ok_or(BrowserDriverError::Protocol)?;
        Ok(PageOrigin::from_location(protocol, hostname, port))
    }

    fn runtime_value(
        &mut self,
        session: &str,
        expression: &str,
    ) -> Result<strict_json::SensitiveValue, BrowserDriverError> {
        if !allowed_mail_runtime_expression(expression) {
            return Err(BrowserDriverError::Protocol);
        }
        let params = json!({
            "expression": expression,
            "returnByValue": true
        });
        // jig-ignore-next-line: canonical rustfmt line.
        let mut result = self.call_in_session(session, "Runtime.evaluate", &params)?;
        if result.get("exceptionDetails").is_some()
            || result
                .get("wasThrown")
                .is_some_and(|thrown| thrown.as_bool() != Some(false))
        {
            return Err(BrowserDriverError::Protocol);
        }
        let remote = result
            .get("result")
            .filter(|remote| remote.is_object())
            .ok_or(BrowserDriverError::Protocol)?;
        let value = remote.get("value").ok_or(BrowserDriverError::Protocol)?;
        // By-value evidence cannot simultaneously be a remote object handle
        // or an unserializable primitive. Such a reply has contradictory
        // transport semantics, even if its embedded value looks plausible.
        let has_remote_handle = remote.get("objectId").is_some();
        // jig-ignore-next-line: canonical Rust method call and CDP field.
        let has_unserializable_value = remote.get("unserializableValue").is_some();
        if has_remote_handle || has_unserializable_value {
            return Err(BrowserDriverError::Protocol);
        }
        // Chromium's RemoteObject.type must agree with the returned by-value
        // JSON. A contradictory explicit type cannot authorize page evidence.
        // Some synthetic/older replies omit type; retain that compatibility.
        let is_composite = value.is_object() || value.is_array();
        let type_matches = match remote.get("type") {
            None => true,
            Some(Value::String(kind)) => match kind.as_str() {
                "object" => is_composite || value.is_null(),
                "string" => value.is_string(),
                "boolean" => value.is_boolean(),
                "number" => value.is_number(),
                _ => false,
            },
            Some(_) => false,
        };
        // A by-value array or null may declare an object subtype. Other
        // explicit subtypes cannot describe our audited JSON evidence.
        let subtype_matches = match remote.get("subtype") {
            None => true,
            Some(Value::String(kind)) => {
                remote.get("type").and_then(Value::as_str) == Some("object")
                    && match kind.as_str() {
                        "array" => value.is_array(),
                        "null" => value.is_null(),
                        _ => false,
                    }
            }
            Some(_) => false,
        };
        if !type_matches || !subtype_matches {
            return Err(BrowserDriverError::Protocol);
        }
        let mut remote = result
            .take_object_field("result")
            .ok_or(BrowserDriverError::Protocol)?;
        remote
            .take_object_field("value")
            .ok_or(BrowserDriverError::Protocol)
    }

    fn query_ax_role(
        &mut self,
        session: &str,
        node_id: u64,
        role: &str,
    ) -> Result<strict_json::SensitiveValue, BrowserDriverError> {
        self.call_in_session(
            session,
            "Accessibility.queryAXTree",
            &json!({"nodeId": node_id, "role": role}),
        )
    }

    fn detach(&mut self, session: &str) -> Result<(), BrowserDriverError> {
        let params = strict_json::SensitiveValue::from_owned(json!({
            "sessionId": session
        }));
        self.call("Target.detachFromTarget", &params)?;
        Ok(())
    }

    /// Reads translation-free structural evidence from the Proton Mail AX tree.
    ///
    /// Accessible names and values are intentionally discarded. The result
    /// contains only navigation/search presence and dialog-blocker state.
    ///
    /// # Errors
    ///
    /// Fails before AX inspection for non-Mail origins, origin drift, malformed
    /// protocol output, or a failed target detach.
    pub fn inspect_mail_shell(
        &mut self,
        page: &ProviderPage,
    ) -> Result<MailShellEvidence, BrowserDriverError> {
        if page.origin != PageOrigin::ProtonMail {
            return Err(BrowserDriverError::MailOriginRequired);
        }
        let session = self.attach(page)?;
        let inspected = self.inspect_mail_shell_in_session(page, &session);
        let detached = self.detach(&session);
        let evidence = inspected?;
        detached?;
        Ok(evidence)
    }

    /// Requires a ready Mail-shell snapshot at the time of inspection.
    ///
    /// This is not a durable action grant. A later mailbox workflow must
    /// re-attach and revalidate origin and required page state in its own
    /// execution path before reading content or creating a side effect.
    ///
    /// # Errors
    ///
    /// Returns the underlying inspection error or `MailShellNotReady` when
    /// required structural landmarks are absent or a dialog blocker is visible.
    pub fn require_mail_shell(
        &mut self,
        page: &ProviderPage,
    ) -> Result<MailShellEvidence, BrowserDriverError> {
        let evidence = self.inspect_mail_shell(page)?;
        if !evidence.ready() {
            return Err(BrowserDriverError::MailShellNotReady);
        }
        Ok(evidence)
    }

    fn inspect_mail_shell_in_session(
        &mut self,
        page: &ProviderPage,
        session: &str,
    ) -> Result<MailShellEvidence, BrowserDriverError> {
        self.ensure_page_origin(page, session)?;
        let root = self.call_in_session(
            session,
            "DOM.getDocument",
            &json!({"depth": 0i32, "pierce": false}),
        )?;
        let node_id = root
            .get("root")
            .and_then(|node| node.get("nodeId"))
            .and_then(Value::as_u64)
            .filter(|id| *id > 0)
            .ok_or(BrowserDriverError::Protocol)?;
        let navigation = self.query_ax_role(session, node_id, "navigation")?;
        let search = self.query_ax_role(session, node_id, "search")?;
        let dialog = self.query_ax_role(session, node_id, "dialog")?;
        let alertdialog = self.query_ax_role(session, node_id, "alertdialog")?;
        let evidence =
            // jig-ignore-next-line: canonical rustfmt line.
            MailShellEvidence::from_role_queries(&navigation, &search, &dialog, &alertdialog)
                .map_err(|_error| BrowserDriverError::Protocol)?;
        self.ensure_page_origin(page, session)?;
        Ok(evidence)
    }

    fn ensure_page_origin(
        &mut self,
        page: &ProviderPage,
        session: &str,
    ) -> Result<(), BrowserDriverError> {
        let observed = self.runtime_origin(session)?;
        if observed != page.origin {
            return Err(BrowserDriverError::OriginDrift {
                expected: page.origin,
                observed,
            });
        }
        Ok(())
    }

    /// Passively captures the complete mail folder/label catalog during reload.
    ///
    /// Only the browser application's own exact core-v4 label GETs are used.
    // jig-ignore-next-line: canonical rustfmt line.
    /// Contact groups and unrelated traffic are ignored, and response bodies are
    /// projected immediately to bounded IDs, names, order, kind, and folder
    /// parent IDs. No provider request is injected by the adapter.
    ///
    /// # Errors
    ///
    /// Fails closed for a non-Mail/unready page, missing or duplicated category
    /// responses, unsafe Network lifecycle/body data, or origin drift.
    pub fn observe_mailbox_catalog(
        &mut self,
        page: &ProviderPage,
    ) -> Result<ObservedMailboxCatalog, BrowserDriverError> {
        if page.origin != PageOrigin::ProtonMail {
            return Err(BrowserDriverError::MailOriginRequired);
        }
        let session = self.attach(page)?;
        let observed = self.observe_mailbox_catalog_in_session(page, &session);
        let detached = self.detach(&session);
        let catalog = observed?;
        detached?;
        Ok(catalog)
    }

    /// Captures one complete catalog snapshot and returns its first local page.
    ///
    /// The snapshot remains immutable in memory for exact continuation without
    /// another provider read. Starting another chain of the same kind replaces
    /// that retained snapshot and expires its older cursors; the other catalog
    /// kind remains independently resumable.
    ///
    /// # Errors
    ///
    /// Rejects invalid page size/account binding before provider observation,
    /// plus every fail-closed catalog capture, cursor, or entropy error.
    pub fn observe_mailbox_catalog_page(
        &mut self,
        page: &ProviderPage,
        account: &str,
        kind: MailboxCatalogPageKind,
        requested_page_size: Option<u16>,
    ) -> Result<SerializedMailboxCatalogPage, BrowserDriverError> {
        let page_size = validate_page_size(requested_page_size)
            .map_err(BrowserDriverError::MailboxCatalogPage)?;
        // jig-ignore-next-line: canonical rustfmt line.
        validate_catalog_account(account).map_err(BrowserDriverError::MailboxCatalogCursor)?;
        let catalog = self.observe_mailbox_catalog(page)?;
        let boundary = fresh_web_adapter_tag()?;
        // jig-ignore-next-line: canonical rustfmt line.
        let snapshot = MailboxCatalogSnapshot::from_catalog(&boundary, kind, &catalog)
            .map_err(BrowserDriverError::MailboxCatalogPage)?;
        let page = snapshot
            .first_page(Some(page_size))
            .map_err(BrowserDriverError::MailboxCatalogPage)?;
        let serialized = self.serialize_mailbox_catalog_page(account, page)?;
        match kind {
            // jig-ignore-next-line: canonical rustfmt line.
            MailboxCatalogPageKind::Mailboxes => self.mailbox_catalog_snapshot = Some(snapshot),
            // jig-ignore-next-line: canonical rustfmt line.
            MailboxCatalogPageKind::Labels => self.label_catalog_snapshot = Some(snapshot),
        }
        Ok(serialized)
    }

    /// Resumes one retained immutable catalog snapshot without provider I/O.
    ///
    /// # Errors
    ///
    /// Wrong account, kind, page size, malformed, or tampered tokens are
    /// invalid.
    /// Prior browser generations and replaced/missing snapshots are expired.
    pub fn resume_mailbox_catalog_page(
        &self,
        account: &str,
        kind: MailboxCatalogPageKind,
        requested_page_size: Option<u16>,
        token: &str,
    ) -> Result<SerializedMailboxCatalogPage, BrowserDriverError> {
        let page_size = validate_page_size(requested_page_size)
            .map_err(BrowserDriverError::MailboxCatalogPage)?;
        let state = self
            .catalog_cursor_codec
            .decode(self.generation.as_str(), account, kind, page_size, token)
            .map_err(BrowserDriverError::MailboxCatalogCursor)?;
        let snapshot = match kind {
            // jig-ignore-next-line: canonical rustfmt line.
            MailboxCatalogPageKind::Mailboxes => self.mailbox_catalog_snapshot.as_ref(),
            // jig-ignore-next-line: canonical rustfmt line.
            MailboxCatalogPageKind::Labels => self.label_catalog_snapshot.as_ref(),
        }
        .ok_or(BrowserDriverError::MailboxCatalogCursor(
            WebCatalogCursorCodecError::CursorExpired,
        ))?;
        let page = snapshot
            .resume_page(&state)
            .map_err(map_catalog_page_error)?;
        self.serialize_mailbox_catalog_page(account, page)
    }

    fn serialize_mailbox_catalog_page(
        &self,
        account: &str,
        page: MailboxCatalogSnapshotPage,
    ) -> Result<SerializedMailboxCatalogPage, BrowserDriverError> {
        let (items, next_state) = page.into_parts();
        let next_cursor = next_state
            .as_ref()
            .map(|state| {
                self.catalog_cursor_codec
                    .encode(self.generation.as_str(), account, state)
                    .map_err(BrowserDriverError::MailboxCatalogCursor)
            })
            .transpose()?;
        Ok(SerializedMailboxCatalogPage::new(items, next_cursor))
    }

    fn observe_mailbox_catalog_in_session(
        &mut self,
        page: &ProviderPage,
        session: &str,
    ) -> Result<ObservedMailboxCatalog, BrowserDriverError> {
        let before = self.inspect_mail_shell_in_session(page, session)?;
        if !before.ready() {
            return Err(BrowserDriverError::MailShellNotReady);
        }
        let network_params = json!({
            "maxPostDataSize": 0u16,
            // jig-ignore-next-line: canonical rustfmt line.
            "maxResourceBufferSize": ObservedMailboxCatalogResponse::MAX_BODY_BYTES,
            "maxTotalBufferSize": MAILBOX_CATALOG_TOTAL_BUFFER_BYTES
        });
        let mut capture = MailboxCatalogNetworkCapture::new(session);
        self.enable_network_observing(session, &network_params, &mut capture)?;
        let deadline = Instant::now()
            .checked_add(MAILBOX_CATALOG_CAPTURE_TIMEOUT)
            .ok_or(BrowserDriverError::MailboxCatalogUnavailable)?;
        let observed = (|| {
            self.call_in_session_observing(
                session,
                "Page.reload",
                &json!({"ignoreCache": false}),
                &mut capture,
            )?;
            let responses =
                // jig-ignore-next-line: canonical rustfmt line.
                self.capture_mailbox_catalog_responses(session, &mut capture, deadline)?;
            ObservedMailboxCatalog::from_responses(responses)
                .map_err(BrowserDriverError::MailboxCatalogResponse)
        })();
        let disabled =
            // jig-ignore-next-line: canonical rustfmt line.
            self.call_in_session_observing(session, "Network.disable", &json!({}), &mut capture);
        let residual = capture.tracked_request_count();
        let catalog = observed?;
        disabled?;
        if residual != 0 {
            return Err(BrowserDriverError::MailboxCatalogAmbiguous);
        }
        let after = self.inspect_mail_shell_in_session(page, session)?;
        if !after.ready() {
            return Err(BrowserDriverError::MailShellNotReady);
        }
        self.ensure_page_origin(page, session)?;
        Ok(catalog)
    }

    fn capture_mailbox_catalog_responses(
        &mut self,
        session: &str,
        capture: &mut MailboxCatalogNetworkCapture,
        deadline: Instant,
    ) -> Result<Vec<ObservedMailboxCatalogResponse>, BrowserDriverError> {
        // jig-ignore-next-line: canonical rustfmt line.
        let mut responses: Vec<ObservedMailboxCatalogResponse> = Vec::with_capacity(3);
        for _event in 0..MAX_UNSOLICITED {
            let finished = capture
                .take_finished_requests()
                .into_iter()
                // Error paths must erase ID copies, even on catalog ambiguity.
                .map(|(id, kind)| (Zeroizing::new(id), kind))
                .collect::<Vec<_>>();
            for (index, (_request_id, kind)) in finished.iter().enumerate() {
                // jig-ignore-next-line: canonical rustfmt line.
                let already_projected = responses.iter().any(|response| response.kind() == *kind);
                let repeated_here = finished[..index]
                    .iter()
                    .any(|(_prior_id, prior_kind)| prior_kind == kind);
                if already_projected || repeated_here {
                    return Err(BrowserDriverError::MailboxCatalogAmbiguous);
                }
            }
            for (request_id, kind) in finished {
                let body = self.read_cdp_body(session, &request_id, capture)?;
                // jig-ignore-next-line: canonical rustfmt line.
                let response = ObservedMailboxCatalogResponse::parse_cdp_body(kind, &body)
                    .map_err(BrowserDriverError::MailboxCatalogResponse)?;
                responses.push(response);
            }
            if responses.len() == 3 {
                return Ok(responses);
            }
            if Instant::now() >= deadline {
                return Err(BrowserDriverError::MailboxCatalogUnavailable);
            }
            let frame = read_frame(&mut self.reader)?;
            let message = decode_cdp_frame(&frame)?;
            validate_cdp_notification(&message)?;
            capture.observe_event(&message)?;
        }
        Err(BrowserDriverError::MailboxCatalogUnavailable)
    }

    /// Reads content-free evidence for the currently rendered mailbox list.
    ///
    /// Origin and Mail-shell readiness are revalidated in the same target
    /// session before the list observation, and origin is checked again after.
    ///
    /// # Errors
    ///
    /// Fails closed for a non-Mail page, unready shell, malformed/contradictory
    /// list evidence, or origin drift around the observation.
    pub fn inspect_mailbox_list(
        &mut self,
        page: &ProviderPage,
    ) -> Result<MailboxListEvidence, BrowserDriverError> {
        if page.origin != PageOrigin::ProtonMail {
            return Err(BrowserDriverError::MailOriginRequired);
        }
        let session = self.attach(page)?;
        let inspected = self.inspect_mailbox_list_in_session(page, &session);
        let detached = self.detach(&session);
        let evidence = inspected?;
        detached?;
        Ok(evidence)
    }

    fn inspect_mailbox_list_in_session(
        &mut self,
        page: &ProviderPage,
        session: &str,
    ) -> Result<MailboxListEvidence, BrowserDriverError> {
        let shell = self.inspect_mail_shell_in_session(page, session)?;
        if !shell.ready() {
            return Err(BrowserDriverError::MailShellNotReady);
        }
        let evidence = self.mailbox_list_in_session(session)?;
        self.ensure_page_origin(page, session)?;
        Ok(evidence)
    }

    /// Reads location-only mailbox-mode evidence from the current Mail page.
    ///
    /// # Errors
    ///
    /// Fails closed for a non-Mail page, unready shell, malformed location, or
    /// origin drift around the observation.
    pub fn inspect_mailbox_mode(
        &mut self,
        page: &ProviderPage,
    ) -> Result<MailboxModeEvidence, BrowserDriverError> {
        if page.origin != PageOrigin::ProtonMail {
            return Err(BrowserDriverError::MailOriginRequired);
        }
        let session = self.attach(page)?;
        let inspected = self.inspect_mailbox_mode_in_session(page, &session);
        let detached = self.detach(&session);
        let evidence = inspected?;
        detached?;
        Ok(evidence)
    }

    fn inspect_mailbox_mode_in_session(
        &mut self,
        page: &ProviderPage,
        session: &str,
    ) -> Result<MailboxModeEvidence, BrowserDriverError> {
        let shell = self.inspect_mail_shell_in_session(page, session)?;
        if !shell.ready() {
            return Err(BrowserDriverError::MailShellNotReady);
        }
        let evidence = self.mailbox_mode_in_session(session)?;
        self.ensure_page_origin(page, session)?;
        Ok(evidence)
    }

    fn mailbox_mode_in_session(
        &mut self,
        session: &str,
    ) -> Result<MailboxModeEvidence, BrowserDriverError> {
        let expression = MailboxModeEvidence::expression();
        let value = self.runtime_value(session, expression)?;
        MailboxModeEvidence::from_value(&value)
            .map_err(|_error| BrowserDriverError::MailboxModeIncompatible)
    }

    /// Inspects Mail's visible sort selection without changing it.
    ///
    /// If the filter/sort menu is closed, the adapter opens it only long enough
    /// to read non-localized `aria-pressed` state and then closes it again.
    ///
    /// # Errors
    ///
    /// Fails for an unready Mail shell, missing/duplicated sort controls,
    /// multiple active options, menu transition timeout, or origin drift.
    pub fn inspect_mailbox_sort(
        &mut self,
        page: &ProviderPage,
    ) -> Result<MailboxSortOrder, BrowserDriverError> {
        if page.origin != PageOrigin::ProtonMail {
            return Err(BrowserDriverError::MailOriginRequired);
        }
        let session = self.attach(page)?;
        let inspected = self.inspect_mailbox_sort_in_session(page, &session);
        let detached = self.detach(&session);
        let sort = inspected?;
        detached?;
        Ok(sort)
    }

    /// Returns an initial bounded change page with an authenticated cursor.
    ///
    /// # Errors
    ///
    /// Returns the underlying bounded observation failures, invalid account
    /// scope, or a cursor encoding failure.
    pub fn observe_initial_mailbox_changes_serialized(
        &mut self,
        page: &ProviderPage,
        account: &str,
        wait: Duration,
    ) -> Result<SerializedMailboxChangePage, BrowserDriverError> {
        let scope = self
            .event_cursor_scope(account)
            // jig-ignore-next-line: canonical rustfmt line.
            .map_err(|error| BrowserDriverError::EventCursorResume(error.resume_failure()))?;
        // jig-ignore-next-line: canonical rustfmt line.
        let observed = self.observe_initial_mailbox_changes(page, scope.clone(), wait)?;
        self.serialize_mailbox_change_page(observed, &scope)
    }

    /// Initial serialized change wait with cooperative cancellation.
    ///
    /// # Errors
    ///
    /// Returns the same failures as
    /// [`Self::observe_initial_mailbox_changes_serialized`] plus cancellation.
    pub fn observe_initial_mailbox_changes_serialized_cancellable(
        &mut self,
        page: &ProviderPage,
        account: &str,
        wait: Duration,
        cancellation: &MailboxEventCancellation,
    ) -> Result<SerializedMailboxChangePage, BrowserDriverError> {
        let scope = self
            .event_cursor_scope(account)
            // jig-ignore-next-line: canonical rustfmt line.
            .map_err(|error| BrowserDriverError::EventCursorResume(error.resume_failure()))?;
        let observed = self.observe_initial_mailbox_changes_cancellable(
            page,
            scope.clone(),
            wait,
            cancellation,
        )?;
        self.serialize_mailbox_change_page(observed, &scope)
    }

    /// Resumes one bounded change wait from an authenticated opaque cursor.
    ///
    /// # Errors
    ///
    /// Malformed/account-drifted tokens are invalid, prior browser generations
    /// are expired, and all exact passive-resume errors remain fail-closed.
    pub fn observe_mailbox_changes_from_token(
        &mut self,
        page: &ProviderPage,
        token: &str,
        account: &str,
        wait: Duration,
    ) -> Result<SerializedMailboxChangePage, BrowserDriverError> {
        let scope = self
            .event_cursor_scope(account)
            // jig-ignore-next-line: canonical rustfmt line.
            .map_err(|error| BrowserDriverError::EventCursorResume(error.resume_failure()))?;
        let cursor = self
            .decode_event_cursor(token, &scope)
            .map_err(map_event_cursor_codec_error)?;
        // jig-ignore-next-line: canonical rustfmt line.
        let observed = self.observe_mailbox_changes_from_cursor(page, &cursor, &scope, wait)?;
        self.serialize_mailbox_change_page(observed, &scope)
    }

    /// Resumed serialized change wait with cooperative cancellation.
    ///
    /// # Errors
    ///
    // jig-ignore-next-line: canonical rustfmt line.
    /// Returns the same failures as [`Self::observe_mailbox_changes_from_token`]
    /// plus cancellation after successful token authentication.
    pub fn observe_mailbox_changes_from_token_cancellable(
        &mut self,
        page: &ProviderPage,
        token: &str,
        account: &str,
        wait: Duration,
        cancellation: &MailboxEventCancellation,
    ) -> Result<SerializedMailboxChangePage, BrowserDriverError> {
        let scope = self
            .event_cursor_scope(account)
            // jig-ignore-next-line: canonical rustfmt line.
            .map_err(|error| BrowserDriverError::EventCursorResume(error.resume_failure()))?;
        let cursor = self
            .decode_event_cursor(token, &scope)
            .map_err(map_event_cursor_codec_error)?;
        let observed = self.observe_mailbox_changes_from_cursor_cancellable(
            page,
            &cursor,
            &scope,
            wait,
            cancellation,
        )?;
        self.serialize_mailbox_change_page(observed, &scope)
    }

    fn serialize_mailbox_change_page(
        &self,
        page: ObservedMailboxChangePage,
        scope: &EventCursorScope,
    ) -> Result<SerializedMailboxChangePage, BrowserDriverError> {
        let (changes, count_changes, next_cursor) = page.into_parts();
        let next_cursor = self
            .encode_event_cursor(&next_cursor, scope)
            .map_err(map_event_cursor_codec_error)?;
        Ok(SerializedMailboxChangePage {
            changes,
            count_changes,
            next_cursor,
        })
    }

    /// Observes an initial bounded mailbox-change page without a prior cursor.
    ///
    /// Bootstrap latest-event capture and the first v5 wait share one Network
    // jig-ignore-next-line: canonical rustfmt line.
    /// observation, so no provider event lifecycle can fall into an enable/disable
    /// gap. A timeout is a successful empty page carrying the bootstrap cursor.
    ///
    /// # Errors
    ///
    /// Rejects waits above 30 seconds, non-Mail/unready pages, bootstrap/v5
    // jig-ignore-next-line: canonical rustfmt line.
    /// lifecycle ambiguity, bootstrap-to-v5 cursor drift, refresh, cancellation,
    /// origin drift, or transport failures.
    pub fn observe_initial_mailbox_changes(
        &mut self,
        page: &ProviderPage,
        scope: EventCursorScope,
        wait: Duration,
    ) -> Result<ObservedMailboxChangePage, BrowserDriverError> {
        // jig-ignore-next-line: canonical rustfmt line.
        self.observe_initial_mailbox_changes_with_cancellation(page, scope, wait, None)
    }

    // jig-ignore-next-line: canonical rustfmt line.
    /// Initial bounded mailbox-change observation with cooperative cancellation.
    ///
    /// # Errors
    ///
    // jig-ignore-next-line: canonical rustfmt line.
    /// Returns every error documented by [`Self::observe_initial_mailbox_changes`]
    /// plus `MailboxEventCancelled` when cancellation is requested.
    pub fn observe_initial_mailbox_changes_cancellable(
        &mut self,
        page: &ProviderPage,
        scope: EventCursorScope,
        wait: Duration,
        cancellation: &MailboxEventCancellation,
    ) -> Result<ObservedMailboxChangePage, BrowserDriverError> {
        self.observe_initial_mailbox_changes_with_cancellation(
            page,
            scope,
            wait,
            Some(cancellation),
        )
    }

    fn observe_initial_mailbox_changes_with_cancellation(
        &mut self,
        page: &ProviderPage,
        scope: EventCursorScope,
        wait: Duration,
        cancellation: Option<&MailboxEventCancellation>,
    ) -> Result<ObservedMailboxChangePage, BrowserDriverError> {
        if page.origin != PageOrigin::ProtonMail {
            return Err(BrowserDriverError::MailOriginRequired);
        }
        if wait > MAILBOX_EVENT_MAX_WAIT {
            return Err(BrowserDriverError::MailboxEventWaitTooLong);
        }
        ensure_event_wait_not_cancelled(cancellation)?;
        let session = self.attach(page)?;
        let observed = self.observe_initial_mailbox_changes_in_session(
            page,
            &session,
            scope,
            wait,
            cancellation,
        );
        let detached = self.detach(&session);
        let change_page = observed?;
        detached?;
        Ok(change_page)
    }

    fn observe_initial_mailbox_changes_in_session(
        &mut self,
        page: &ProviderPage,
        session: &str,
        scope: EventCursorScope,
        wait: Duration,
        cancellation: Option<&MailboxEventCancellation>,
    ) -> Result<ObservedMailboxChangePage, BrowserDriverError> {
        let shell = self.inspect_mail_shell_in_session(page, session)?;
        if !shell.ready() {
            return Err(BrowserDriverError::MailShellNotReady);
        }
        let network_params = json!({
            "maxPostDataSize": 0u16,
            // jig-ignore-next-line: canonical rustfmt line.
            "maxResourceBufferSize": ObservedMailboxEventWatermark::MAX_BODY_BYTES,
            "maxTotalBufferSize": MAILBOX_EVENT_TOTAL_BUFFER_BYTES
        });
        let mut capture = InitialMailboxEventCapture::new(session);
        self.enable_network_observing(session, &network_params, &mut capture)?;
        let bootstrap_deadline = Instant::now()
            .checked_add(MAILBOX_EVENT_BOOTSTRAP_TIMEOUT)
            .ok_or(BrowserDriverError::MailboxEventResponseUnavailable)?;
        let observed = (|| {
            ensure_event_wait_not_cancelled(cancellation)?;
            // jig-ignore-next-line: canonical rustfmt line.
            self.call_in_session_observing(session, "Page.reload", &json!({}), &mut capture)?;
            let latest_request = self.wait_for_initial_latest_request(
                &mut capture,
                bootstrap_deadline,
                cancellation,
            )?;
            let latest_request = guard_selected_request(latest_request);
            ensure_event_wait_not_cancelled(cancellation)?;
            // jig-ignore-next-line: canonical event capture request invocation.
            let latest_body = self.read_cdp_body(session, &latest_request, &mut capture)?;
            // jig-ignore-next-line: canonical rustfmt line.
            let bootstrap = ObservedLatestMailboxEventWatermark::parse_cdp_body(&latest_body)
                .map_err(BrowserDriverError::MailboxEventWatermark)?;
            let deadline = Instant::now()
                .checked_add(wait)
                .ok_or(BrowserDriverError::MailboxEventWaitTooLong)?;
            let sequence = self.capture_initial_mailbox_event_sequence(
                session,
                &mut capture,
                deadline,
                cancellation,
            )?;
            if let Some(sequence) = sequence {
                if sequence.start_event_id() != bootstrap.event_id() {
                    return Err(BrowserDriverError::MailboxEventBootstrapDrift);
                }
                // jig-ignore-next-line: canonical rustfmt line.
                let page = ObservedMailboxChangePage::from_sequence(scope, sequence)
                    .map_err(BrowserDriverError::MailboxEventSequence)?;
                Ok((page, true))
            } else {
                Ok((
                    // jig-ignore-next-line: canonical rustfmt line.
                    ObservedMailboxChangePage::from_bootstrap(scope, &bootstrap),
                    false,
                ))
            }
        })();
        let disabled =
            // jig-ignore-next-line: canonical rustfmt line.
            self.call_in_session_observing(session, "Network.disable", &json!({}), &mut capture);
        let latest_residual = capture.latest.tracked_request_count();
        let event_residual = capture.events.tracked_request_count();
        let (change_page, had_sequence) = observed?;
        disabled?;
        if latest_residual != 0 {
            return Err(BrowserDriverError::MailboxEventResponseAmbiguous);
        }
        if had_sequence && event_residual != 0 {
            return Err(BrowserDriverError::MailboxEventResponseAmbiguous);
        }
        self.ensure_page_origin(page, session)?;
        Ok(change_page)
    }

    /// Reloads Mail and captures its own legacy bootstrap event watermark.
    ///
    /// This enables bounded Network observation before `Page.reload`, accepts
    /// only one exact `GET /api/core/v4/events/latest` lifecycle, projects the
    /// decoded body immediately, disables Network, and revalidates page origin.
    /// No Proton API request is injected by the adapter.
    ///
    /// # Errors
    ///
    /// Rejects non-Mail or unready pages, bootstrap lifecycle ambiguity, body
    /// projection failure, timeout, origin drift, or transport failures.
    pub fn observe_mailbox_event_bootstrap(
        &mut self,
        page: &ProviderPage,
    ) -> Result<ObservedLatestMailboxEventWatermark, BrowserDriverError> {
        if page.origin != PageOrigin::ProtonMail {
            return Err(BrowserDriverError::MailOriginRequired);
        }
        let session = self.attach(page)?;
        // jig-ignore-next-line: canonical rustfmt line.
        let observed = self.observe_mailbox_event_bootstrap_in_session(page, &session);
        let detached = self.detach(&session);
        let watermark = observed?;
        detached?;
        Ok(watermark)
    }

    fn observe_mailbox_event_bootstrap_in_session(
        &mut self,
        page: &ProviderPage,
        session: &str,
    ) -> Result<ObservedLatestMailboxEventWatermark, BrowserDriverError> {
        let shell = self.inspect_mail_shell_in_session(page, session)?;
        if !shell.ready() {
            return Err(BrowserDriverError::MailShellNotReady);
        }
        let network_params = json!({
            "maxPostDataSize": 0u16,
            // jig-ignore-next-line: canonical rustfmt line.
            "maxResourceBufferSize": ObservedMailboxEventWatermark::MAX_BODY_BYTES,
            "maxTotalBufferSize": MAILBOX_EVENT_TOTAL_BUFFER_BYTES
        });
        let mut capture = LatestMailboxEventNetworkCapture::new(session);
        self.enable_network_observing(session, &network_params, &mut capture)?;
        let deadline = Instant::now()
            .checked_add(MAILBOX_EVENT_BOOTSTRAP_TIMEOUT)
            .ok_or(BrowserDriverError::MailboxEventResponseUnavailable)?;
        let observed = (|| {
            // jig-ignore-next-line: canonical rustfmt line.
            self.call_in_session_observing(session, "Page.reload", &json!({}), &mut capture)?;
            // jig-ignore-next-line: canonical rustfmt line.
            let request_id = self.wait_for_latest_mailbox_event_request(&mut capture, deadline)?;
            let request_id = guard_selected_request(request_id);
            let body = self.read_cdp_body(session, &request_id, &mut capture)?;
            ObservedLatestMailboxEventWatermark::parse_cdp_body(&body)
                .map_err(BrowserDriverError::MailboxEventWatermark)
        })();
        let disabled =
            // jig-ignore-next-line: canonical rustfmt line.
            self.call_in_session_observing(session, "Network.disable", &json!({}), &mut capture);
        let residual_requests = capture.tracked_request_count();
        let watermark = observed?;
        disabled?;
        if residual_requests != 0 {
            return Err(BrowserDriverError::MailboxEventResponseAmbiguous);
        }
        self.ensure_page_origin(page, session)?;
        Ok(watermark)
    }

    /// Passively observes the browser's own next legacy Mail event sequence.
    ///
    /// No provider API request is injected. Network events are classified
    /// inline, response bodies are projected immediately, and raw headers,
    /// cookies, message/conversation objects, and unrelated traffic are not
    /// retained. A timeout before the first event is a successful `None`.
    ///
    /// # Errors
    ///
    /// Rejects waits above 30 seconds, non-Mail/unready pages, event lifecycle
    /// ambiguity, malformed response bodies, cursor gaps, refresh, or transport
    /// failures.
    pub fn observe_mailbox_event_sequence(
        &mut self,
        page: &ProviderPage,
        wait: Duration,
    ) -> Result<Option<ObservedMailboxEventSequence>, BrowserDriverError> {
        self.observe_mailbox_event_sequence_with_cancellation(page, wait, None)
    }

    /// Passively observes the browser event loop with cooperative cancellation.
    ///
    /// # Errors
    ///
    /// Returns `MailboxEventCancelled` when cancellation is requested and every
    /// error documented by [`Self::observe_mailbox_event_sequence`].
    pub fn observe_mailbox_event_sequence_cancellable(
        &mut self,
        page: &ProviderPage,
        wait: Duration,
        cancellation: &MailboxEventCancellation,
    ) -> Result<Option<ObservedMailboxEventSequence>, BrowserDriverError> {
        // jig-ignore-next-line: canonical rustfmt line.
        self.observe_mailbox_event_sequence_with_cancellation(page, wait, Some(cancellation))
    }

    fn observe_mailbox_event_sequence_with_cancellation(
        &mut self,
        page: &ProviderPage,
        wait: Duration,
        cancellation: Option<&MailboxEventCancellation>,
    ) -> Result<Option<ObservedMailboxEventSequence>, BrowserDriverError> {
        if page.origin != PageOrigin::ProtonMail {
            return Err(BrowserDriverError::MailOriginRequired);
        }
        if wait > MAILBOX_EVENT_MAX_WAIT {
            return Err(BrowserDriverError::MailboxEventWaitTooLong);
        }
        ensure_event_wait_not_cancelled(cancellation)?;
        let session = self.attach(page)?;
        let observed =
            // jig-ignore-next-line: canonical rustfmt line.
            self.observe_mailbox_event_sequence_in_session(page, &session, wait, cancellation);
        let detached = self.detach(&session);
        let sequence = observed?;
        detached?;
        Ok(sequence)
    }

    /// Passively observes only if the browser resumes from the acknowledged
    /// provider event watermark exactly.
    ///
    /// This never seeks or injects an event request. A mismatch between the
    /// acknowledged watermark and the browser-owned next request fails as a
    /// cursor gap rather than silently skipping forward.
    ///
    /// # Errors
    ///
    /// Rejects malformed expected watermarks and every error documented by
    /// [`Self::observe_mailbox_event_sequence`].
    pub fn observe_mailbox_event_sequence_from(
        &mut self,
        page: &ProviderPage,
        expected_event_id: &str,
        wait: Duration,
    ) -> Result<Option<ObservedMailboxEventSequence>, BrowserDriverError> {
        // jig-ignore-next-line: canonical rustfmt line.
        self.observe_mailbox_event_sequence_from_expected(page, expected_event_id, wait, None)
    }

    fn observe_mailbox_event_sequence_from_expected(
        &mut self,
        page: &ProviderPage,
        expected_event_id: &str,
        wait: Duration,
        cancellation: Option<&MailboxEventCancellation>,
    ) -> Result<Option<ObservedMailboxEventSequence>, BrowserDriverError> {
        // jig-ignore-next-line: canonical rustfmt line.
        if ObservedMailboxEventWatermark::validate_event_id(expected_event_id).is_err() {
            return Err(BrowserDriverError::EventCursorResume(
                EventCursorResumeFailure::InvalidCursor,
            ));
        }
        let observed =
            // jig-ignore-next-line: canonical rustfmt line.
            match self.observe_mailbox_event_sequence_with_cancellation(page, wait, cancellation) {
                Err(BrowserDriverError::MailboxEventSequence(
                    MailboxEventSequenceError::CursorGap
                    | MailboxEventSequenceError::RefreshRequired,
                )) => {
                    return Err(BrowserDriverError::EventCursorResume(
                        EventCursorResumeFailure::CursorExpired,
                    ));
                }
                result => result?,
            };
        if let Some(sequence) = observed.as_ref()
            && sequence.start_event_id() != expected_event_id
        {
            return Err(BrowserDriverError::EventCursorResume(
                EventCursorResumeFailure::CursorExpired,
            ));
        }
        Ok(observed)
    }

    /// Returns one bounded provider-neutral change page from a scoped cursor.
    ///
    // jig-ignore-next-line: canonical rustfmt line.
    /// A successful event sequence advances the page cursor. If no event arrives
    /// before the requested bound, the result is an empty page carrying the
    /// unchanged acknowledged cursor.
    ///
    /// # Errors
    ///
    /// Returns `InvalidCursor` or `CursorExpired` through `EventCursorResume`
    /// when exact resume is impossible, plus the bounded passive-wait failures.
    pub fn observe_mailbox_changes_from_cursor(
        &mut self,
        page: &ProviderPage,
        cursor: &ScopedEventCursor<String>,
        current_scope: &EventCursorScope,
        wait: Duration,
    ) -> Result<ObservedMailboxChangePage, BrowserDriverError> {
        let sequence =
            // jig-ignore-next-line: canonical rustfmt line.
            self.observe_mailbox_event_sequence_from_cursor(page, cursor, current_scope, wait)?;
        sequence.map_or_else(
            || Ok(ObservedMailboxChangePage::from_timeout(cursor.clone())),
            |sequence| {
                // jig-ignore-next-line: canonical rustfmt line.
                ObservedMailboxChangePage::from_sequence(current_scope.clone(), sequence)
                    .map_err(BrowserDriverError::MailboxEventSequence)
            },
        )
    }

    /// Resumed provider-neutral change page with cooperative cancellation.
    ///
    /// # Errors
    ///
    /// Returns the same exact-resume failures as
    /// [`Self::observe_mailbox_changes_from_cursor`] plus
    /// `MailboxEventCancelled` when cancellation is requested.
    pub fn observe_mailbox_changes_from_cursor_cancellable(
        &mut self,
        page: &ProviderPage,
        cursor: &ScopedEventCursor<String>,
        current_scope: &EventCursorScope,
        wait: Duration,
        cancellation: &MailboxEventCancellation,
    ) -> Result<ObservedMailboxChangePage, BrowserDriverError> {
        let expected = cursor
            .state_for(current_scope)
            // jig-ignore-next-line: canonical rustfmt line.
            .map_err(|error| BrowserDriverError::EventCursorResume(error.resume_failure()))?;
        let sequence = self.observe_mailbox_event_sequence_from_expected(
            page,
            expected,
            wait,
            Some(cancellation),
        )?;
        sequence.map_or_else(
            || Ok(ObservedMailboxChangePage::from_timeout(cursor.clone())),
            |sequence| {
                // jig-ignore-next-line: canonical rustfmt line.
                ObservedMailboxChangePage::from_sequence(current_scope.clone(), sequence)
                    .map_err(BrowserDriverError::MailboxEventSequence)
            },
        )
    }

    /// Passively resumes from one account/adapter/generation-bound cursor.
    ///
    /// # Errors
    ///
    /// Rejects scope drift before provider observation, then applies the exact
    /// provider-watermark checks of `observe_mailbox_event_sequence_from`.
    pub fn observe_mailbox_event_sequence_from_cursor(
        &mut self,
        page: &ProviderPage,
        cursor: &ScopedEventCursor<String>,
        current_scope: &EventCursorScope,
        wait: Duration,
    ) -> Result<Option<ObservedMailboxEventSequence>, BrowserDriverError> {
        let expected = cursor
            .state_for(current_scope)
            // jig-ignore-next-line: canonical rustfmt line.
            .map_err(|error| BrowserDriverError::EventCursorResume(error.resume_failure()))?;
        // jig-ignore-next-line: canonical rustfmt line.
        self.observe_mailbox_event_sequence_from_expected(page, expected, wait, None)
    }

    fn observe_mailbox_event_sequence_in_session(
        &mut self,
        page: &ProviderPage,
        session: &str,
        wait: Duration,
        cancellation: Option<&MailboxEventCancellation>,
    ) -> Result<Option<ObservedMailboxEventSequence>, BrowserDriverError> {
        let shell = self.inspect_mail_shell_in_session(page, session)?;
        if !shell.ready() {
            return Err(BrowserDriverError::MailShellNotReady);
        }
        let network_params = json!({
            "maxPostDataSize": 0u16,
            // jig-ignore-next-line: canonical rustfmt line.
            "maxResourceBufferSize": ObservedMailboxEventWatermark::MAX_BODY_BYTES,
            "maxTotalBufferSize": MAILBOX_EVENT_TOTAL_BUFFER_BYTES
        });
        let mut capture = MailboxEventNetworkCapture::new(session);
        self.enable_network_observing(session, &network_params, &mut capture)?;
        let deadline = Instant::now()
            .checked_add(wait)
            .ok_or(BrowserDriverError::MailboxEventWaitTooLong)?;
        let observed =
            // jig-ignore-next-line: canonical rustfmt line.
            self.capture_mailbox_event_sequence(session, &mut capture, deadline, cancellation);
        let disabled =
            // jig-ignore-next-line: canonical rustfmt line.
            self.call_in_session_observing(session, "Network.disable", &json!({}), &mut capture);
        let residual_requests = capture.tracked_request_count();
        let sequence = observed?;
        disabled?;
        if residual_requests != 0 {
            return Err(BrowserDriverError::MailboxEventResponseAmbiguous);
        }
        self.ensure_page_origin(page, session)?;
        Ok(sequence)
    }

    fn capture_mailbox_event_sequence(
        &mut self,
        session: &str,
        capture: &mut MailboxEventNetworkCapture,
        deadline: Instant,
        cancellation: Option<&MailboxEventCancellation>,
    ) -> Result<Option<ObservedMailboxEventSequence>, BrowserDriverError> {
        let Some(first_request) =
            // jig-ignore-next-line: canonical rustfmt line.
            self.wait_for_mailbox_event_request(capture, deadline, cancellation)?
        else {
            return Ok(None);
        };
        let first_request = guard_selected_request(first_request);
        ensure_event_wait_not_cancelled(cancellation)?;
        // jig-ignore-next-line: canonical rustfmt line.
        let first = self.read_mailbox_event_body(session, &first_request, capture)?;
        let mut sequence = ObservedMailboxEventSequence::start(first)
            .map_err(BrowserDriverError::MailboxEventSequence)?;
        while !sequence.settled() {
            let request = self
                // jig-ignore-next-line: canonical rustfmt line.
                .wait_for_mailbox_event_request(capture, deadline, cancellation)?
                .ok_or(BrowserDriverError::MailboxEventResponseUnavailable)?;
            let request = guard_selected_request(request);
            ensure_event_wait_not_cancelled(cancellation)?;
            // jig-ignore-next-line: canonical rustfmt line.
            let page = self.read_mailbox_event_body(session, &request, capture)?;
            sequence
                .push(page)
                .map_err(BrowserDriverError::MailboxEventSequence)?;
        }
        Ok(Some(sequence))
    }

    fn read_mailbox_event_body(
        &mut self,
        session: &str,
        request: &(String, String),
        capture: &mut MailboxEventNetworkCapture,
    ) -> Result<ObservedMailboxEventWatermark, BrowserDriverError> {
        let body = self.read_cdp_body(session, request.0.as_str(), capture)?;
        ObservedMailboxEventWatermark::parse_cdp_body(&request.1, &body)
            .map_err(BrowserDriverError::MailboxEventWatermark)
    }

    fn wait_for_initial_latest_request(
        &mut self,
        capture: &mut InitialMailboxEventCapture,
        deadline: Instant,
        cancellation: Option<&MailboxEventCancellation>,
    ) -> Result<String, BrowserDriverError> {
        if let Some(request_id) =
            take_one_finished_latest_mailbox_event_request(&mut capture.latest)?
        {
            return Ok(request_id);
        }
        let mut unsolicited = 0u16;
        while Instant::now() < deadline {
            ensure_event_wait_not_cancelled(cancellation)?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let read_wait = cancellation.map_or_else(
                || remaining.min(PIPE_TIMEOUT),
                // jig-ignore-next-line: canonical rustfmt line.
                |_handle| remaining.min(PIPE_TIMEOUT).min(MAILBOX_EVENT_CANCEL_POLL),
            );
            self.reader
                .get_mut()
                .set_read_timeout(Some(read_wait))
                .map_err(|_error| BrowserDriverError::PipeSetup)?;
            let frame = read_frame_waiting(&mut self.reader);
            self.reader
                .get_mut()
                .set_read_timeout(Some(PIPE_TIMEOUT))
                .map_err(|_error| BrowserDriverError::PipeSetup)?;
            let Some(frame) = frame? else {
                continue;
            };
            unsolicited = unsolicited
                .checked_add(1)
                .ok_or(BrowserDriverError::MailboxEventResponseUnavailable)?;
            if unsolicited > MAX_UNSOLICITED {
                return Err(BrowserDriverError::MailboxEventResponseUnavailable);
            }
            let message = decode_cdp_frame(&frame)?;
            validate_cdp_notification(&message)?;
            capture.observe_event(&message)?;
            if let Some(request_id) =
                // jig-ignore-next-line: canonical rustfmt line.
                take_one_finished_latest_mailbox_event_request(&mut capture.latest)?
            {
                return Ok(request_id);
            }
        }
        Err(BrowserDriverError::MailboxEventResponseUnavailable)
    }

    fn capture_initial_mailbox_event_sequence(
        &mut self,
        session: &str,
        capture: &mut InitialMailboxEventCapture,
        deadline: Instant,
        cancellation: Option<&MailboxEventCancellation>,
    ) -> Result<Option<ObservedMailboxEventSequence>, BrowserDriverError> {
        let Some(first_request) =
            // jig-ignore-next-line: canonical rustfmt line.
            self.wait_for_initial_mailbox_event_request(capture, deadline, cancellation)?
        else {
            return Ok(None);
        };
        let first_request = guard_selected_request(first_request);
        ensure_event_wait_not_cancelled(cancellation)?;
        // jig-ignore-next-line: canonical rustfmt line.
        let first = self.read_initial_mailbox_event_body(session, &first_request, capture)?;
        let mut sequence = ObservedMailboxEventSequence::start(first)
            .map_err(BrowserDriverError::MailboxEventSequence)?;
        while !sequence.settled() {
            let request = self
                // jig-ignore-next-line: canonical rustfmt line.
                .wait_for_initial_mailbox_event_request(capture, deadline, cancellation)?
                .ok_or(BrowserDriverError::MailboxEventResponseUnavailable)?;
            let request = guard_selected_request(request);
            ensure_event_wait_not_cancelled(cancellation)?;
            // jig-ignore-next-line: canonical rustfmt line.
            let page = self.read_initial_mailbox_event_body(session, &request, capture)?;
            sequence
                .push(page)
                .map_err(BrowserDriverError::MailboxEventSequence)?;
        }
        Ok(Some(sequence))
    }

    fn read_initial_mailbox_event_body(
        &mut self,
        session: &str,
        request: &(String, String),
        capture: &mut InitialMailboxEventCapture,
    ) -> Result<ObservedMailboxEventWatermark, BrowserDriverError> {
        let body = self.read_cdp_body(session, request.0.as_str(), capture)?;
        ObservedMailboxEventWatermark::parse_cdp_body(&request.1, &body)
            .map_err(BrowserDriverError::MailboxEventWatermark)
    }

    fn wait_for_initial_mailbox_event_request(
        &mut self,
        capture: &mut InitialMailboxEventCapture,
        deadline: Instant,
        cancellation: Option<&MailboxEventCancellation>,
    ) -> Result<Option<(String, String)>, BrowserDriverError> {
        // jig-ignore-next-line: canonical rustfmt line.
        if let Some(request) = take_one_finished_mailbox_event_request(&mut capture.events)? {
            return Ok(Some(request));
        }
        let mut unsolicited = 0u16;
        while Instant::now() < deadline {
            ensure_event_wait_not_cancelled(cancellation)?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let read_wait = cancellation.map_or_else(
                || remaining.min(PIPE_TIMEOUT),
                // jig-ignore-next-line: canonical rustfmt line.
                |_handle| remaining.min(PIPE_TIMEOUT).min(MAILBOX_EVENT_CANCEL_POLL),
            );
            self.reader
                .get_mut()
                .set_read_timeout(Some(read_wait))
                .map_err(|_error| BrowserDriverError::PipeSetup)?;
            let frame = read_frame_waiting(&mut self.reader);
            self.reader
                .get_mut()
                .set_read_timeout(Some(PIPE_TIMEOUT))
                .map_err(|_error| BrowserDriverError::PipeSetup)?;
            let Some(frame) = frame? else {
                ensure_event_wait_not_cancelled(cancellation)?;
                continue;
            };
            unsolicited = unsolicited
                .checked_add(1)
                .ok_or(BrowserDriverError::MailboxEventResponseUnavailable)?;
            if unsolicited > MAX_UNSOLICITED {
                return Err(BrowserDriverError::MailboxEventResponseUnavailable);
            }
            let message = decode_cdp_frame(&frame)?;
            validate_cdp_notification(&message)?;
            capture.observe_event(&message)?;
            // jig-ignore-next-line: canonical rustfmt line.
            if let Some(request) = take_one_finished_mailbox_event_request(&mut capture.events)? {
                return Ok(Some(request));
            }
        }
        Ok(None)
    }

    fn wait_for_latest_mailbox_event_request(
        &mut self,
        capture: &mut LatestMailboxEventNetworkCapture,
        deadline: Instant,
    ) -> Result<String, BrowserDriverError> {
        // jig-ignore-next-line: canonical rustfmt line.
        if let Some(request_id) = take_one_finished_latest_mailbox_event_request(capture)? {
            return Ok(request_id);
        }
        let mut unsolicited = 0u16;
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            self.reader
                .get_mut()
                .set_read_timeout(Some(remaining.min(PIPE_TIMEOUT)))
                .map_err(|_error| BrowserDriverError::PipeSetup)?;
            let frame = read_frame_waiting(&mut self.reader);
            self.reader
                .get_mut()
                .set_read_timeout(Some(PIPE_TIMEOUT))
                .map_err(|_error| BrowserDriverError::PipeSetup)?;
            let Some(frame) = frame? else {
                continue;
            };
            unsolicited = unsolicited
                .checked_add(1)
                .ok_or(BrowserDriverError::MailboxEventResponseUnavailable)?;
            if unsolicited > MAX_UNSOLICITED {
                return Err(BrowserDriverError::MailboxEventResponseUnavailable);
            }
            let message = decode_cdp_frame(&frame)?;
            validate_cdp_notification(&message)?;
            capture
                .observe(&message)
                .map_err(BrowserDriverError::MailboxEventNetwork)?;
            // jig-ignore-next-line: canonical rustfmt line.
            if let Some(request_id) = take_one_finished_latest_mailbox_event_request(capture)? {
                return Ok(request_id);
            }
        }
        Err(BrowserDriverError::MailboxEventResponseUnavailable)
    }

    fn wait_for_mailbox_event_request(
        &mut self,
        capture: &mut MailboxEventNetworkCapture,
        deadline: Instant,
        cancellation: Option<&MailboxEventCancellation>,
    ) -> Result<Option<(String, String)>, BrowserDriverError> {
        // jig-ignore-next-line: canonical rustfmt line.
        if let Some(request) = take_one_finished_mailbox_event_request(capture)? {
            return Ok(Some(request));
        }
        let mut unsolicited = 0u16;
        while Instant::now() < deadline {
            ensure_event_wait_not_cancelled(cancellation)?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let read_wait = cancellation.map_or_else(
                || remaining.min(PIPE_TIMEOUT),
                // jig-ignore-next-line: canonical rustfmt line.
                |_handle| remaining.min(PIPE_TIMEOUT).min(MAILBOX_EVENT_CANCEL_POLL),
            );
            self.reader
                .get_mut()
                .set_read_timeout(Some(read_wait))
                .map_err(|_error| BrowserDriverError::PipeSetup)?;
            let frame = read_frame_waiting(&mut self.reader);
            self.reader
                .get_mut()
                .set_read_timeout(Some(PIPE_TIMEOUT))
                .map_err(|_error| BrowserDriverError::PipeSetup)?;
            let Some(frame) = frame? else {
                ensure_event_wait_not_cancelled(cancellation)?;
                continue;
            };
            unsolicited = unsolicited
                .checked_add(1)
                .ok_or(BrowserDriverError::MailboxEventResponseUnavailable)?;
            if unsolicited > MAX_UNSOLICITED {
                return Err(BrowserDriverError::MailboxEventResponseUnavailable);
            }
            let message = decode_cdp_frame(&frame)?;
            validate_cdp_notification(&message)?;
            capture
                .observe(&message)
                .map_err(BrowserDriverError::MailboxEventNetwork)?;
            // jig-ignore-next-line: canonical rustfmt line.
            if let Some(request) = take_one_finished_mailbox_event_request(capture)? {
                return Ok(Some(request));
            }
        }
        Ok(None)
    }

    /// Reports why the current web page is not yet public `list_messages`.
    ///
    /// This preflight proves message mode and visible sort state, then performs
    /// the bounded Network list observation needed to verify provider ordering.
    /// It still reports every remaining provider-neutral contract gap.
    ///
    /// # Errors
    ///
    /// Fails closed if message mode, Mail-shell, visible/provider sort,
    /// Network-list evidence, response projection, or origin evidence drifts.
    pub fn inspect_list_messages_readiness(
        &mut self,
        page: &ProviderPage,
    ) -> Result<ListMessagesReadiness, BrowserDriverError> {
        if page.origin != PageOrigin::ProtonMail {
            return Err(BrowserDriverError::MailOriginRequired);
        }
        let session = self.attach(page)?;
        let inspected = self.list_messages_readiness_in_session(page, &session);
        let detached = self.detach(&session);
        let readiness = inspected?;
        detached?;
        Ok(readiness)
    }

    fn list_messages_readiness_in_session(
        &mut self,
        page: &ProviderPage,
        session: &str,
    ) -> Result<ListMessagesReadiness, BrowserDriverError> {
        let before_mode = self.inspect_mailbox_mode_in_session(page, session)?;
        if before_mode.mode() != MailboxRenderMode::Messages {
            return Err(BrowserDriverError::MailboxMessageModeRequired);
        }
        let sort = self.inspect_mailbox_sort_in_session(page, session)?;
        // jig-ignore-next-line: canonical rustfmt line.
        let observed = self.observe_message_list_responses_in_session(page, session)?;
        let after_mode = self.mailbox_mode_in_session(session)?;
        self.ensure_page_origin(page, session)?;
        if after_mode != before_mode {
            return Err(BrowserDriverError::MailboxModeChanged);
        }
        Ok(ListMessagesReadiness::current(
            sort,
            observed.received_at_descending(),
            observed.provider_neutral_tie_break_proven(),
        ))
    }

    /// Passively observes the next complete browser-owned conversation GET.
    ///
    /// This does not click, navigate, reload, or inject a provider API request.
    /// Only exact unparameterized conversation GETs are eligible. A clean
    /// timeout is `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Rejects waits above 30 seconds, non-Mail/unready pages, ambiguous or
    /// unsafe conversation lifecycles, incomplete response projection, or
    /// origin drift.
    pub fn observe_passive_conversation_detail(
        &mut self,
        page: &ProviderPage,
        wait: Duration,
        // jig-ignore-next-line: canonical rustfmt line.
    ) -> Result<Option<ObservedConversationDetailResponse>, BrowserDriverError> {
        if wait > CONVERSATION_DETAIL_MAX_WAIT {
            return Err(BrowserDriverError::ConversationDetailWaitTooLong);
        }
        if page.origin != PageOrigin::ProtonMail {
            return Err(BrowserDriverError::MailOriginRequired);
        }
        let session = self.attach(page)?;
        // jig-ignore-next-line: canonical rustfmt line.
        let observed = self.observe_passive_conversation_detail_in_session(page, &session, wait);
        let detached = self.detach(&session);
        let detail = observed?;
        detached?;
        Ok(detail)
    }

    fn observe_passive_conversation_detail_in_session(
        &mut self,
        page: &ProviderPage,
        session: &str,
        wait: Duration,
        // jig-ignore-next-line: canonical rustfmt line.
    ) -> Result<Option<ObservedConversationDetailResponse>, BrowserDriverError> {
        let before = self.inspect_mail_shell_in_session(page, session)?;
        if !before.ready() {
            return Err(BrowserDriverError::MailShellNotReady);
        }
        let network_params = json!({
            "maxPostDataSize": 0u16,
            // jig-ignore-next-line: canonical rustfmt line.
            "maxResourceBufferSize": ObservedConversationDetailResponse::MAX_BODY_BYTES,
            "maxTotalBufferSize": CONVERSATION_DETAIL_TOTAL_BUFFER_BYTES
        });
        let mut capture = ConversationDetailNetworkCapture::new(session);
        self.enable_network_observing(session, &network_params, &mut capture)?;
        let deadline = Instant::now()
            .checked_add(wait)
            .ok_or(BrowserDriverError::ConversationDetailWaitTooLong)?;
        // jig-ignore-next-line: canonical rustfmt line.
        let observed = self.capture_passive_conversation_detail(session, &mut capture, deadline);
        let disabled =
            // jig-ignore-next-line: canonical rustfmt line.
            self.call_in_session_observing(session, "Network.disable", &json!({}), &mut capture);
        let residual = capture.tracked_request_count();
        let detail = observed?;
        disabled?;
        if residual != 0 {
            return Err(BrowserDriverError::ConversationDetailAmbiguous);
        }
        let after = self.inspect_mail_shell_in_session(page, session)?;
        if !after.ready() {
            return Err(BrowserDriverError::MailShellNotReady);
        }
        self.ensure_page_origin(page, session)?;
        Ok(detail)
    }

    fn capture_passive_conversation_detail(
        &mut self,
        session: &str,
        capture: &mut ConversationDetailNetworkCapture,
        deadline: Instant,
        // jig-ignore-next-line: canonical rustfmt line.
    ) -> Result<Option<ObservedConversationDetailResponse>, BrowserDriverError> {
        let Some((request_id, conversation_id)) =
            self.wait_for_conversation_detail_request(capture, deadline)?
        else {
            return Ok(None);
        };
        let request_id = guard_selected_request(request_id);
        let conversation_id = guard_selected_request(conversation_id);
        let body = self.read_cdp_body(session, &request_id, capture)?;
        // jig-ignore-next-line: canonical rustfmt line.
        ObservedConversationDetailResponse::parse_cdp_body(&conversation_id, &body)
            .map(Some)
            .map_err(BrowserDriverError::ConversationDetailResponse)
    }

    fn wait_for_conversation_detail_request(
        &mut self,
        capture: &mut ConversationDetailNetworkCapture,
        deadline: Instant,
    ) -> Result<Option<(String, String)>, BrowserDriverError> {
        // jig-ignore-next-line: canonical rustfmt line.
        if let Some(request) = take_one_finished_conversation_detail_request(capture)? {
            return Ok(Some(request));
        }
        let mut unsolicited = 0u16;
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            self.reader
                .get_mut()
                .set_read_timeout(Some(remaining.min(PIPE_TIMEOUT)))
                .map_err(|_error| BrowserDriverError::PipeSetup)?;
            let frame = read_frame_waiting(&mut self.reader);
            self.reader
                .get_mut()
                .set_read_timeout(Some(PIPE_TIMEOUT))
                .map_err(|_error| BrowserDriverError::PipeSetup)?;
            let Some(frame) = frame? else {
                continue;
            };
            unsolicited = unsolicited
                .checked_add(1)
                .ok_or(BrowserDriverError::ConversationDetailAmbiguous)?;
            if unsolicited > MAX_UNSOLICITED {
                return Err(BrowserDriverError::ConversationDetailAmbiguous);
            }
            let message = decode_cdp_frame(&frame)?;
            validate_cdp_notification(&message)?;
            capture
                .observe(&message)
                .map_err(BrowserDriverError::ConversationDetailNetwork)?;
            // jig-ignore-next-line: canonical rustfmt line.
            if let Some(request) = take_one_finished_conversation_detail_request(capture)? {
                return Ok(Some(request));
            }
        }
        Ok(None)
    }

    /// Passively observes the next browser-owned conversation-list GET.
    ///
    /// This does not click, navigate, reload, or inject a provider API request.
    /// Only exact conversation-list GETs are eligible. A clean
    /// timeout is `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Rejects waits above 30 seconds, non-Mail/unready pages, ambiguous or
    /// unsafe conversation lifecycles, invalid response projection, or
    /// origin drift.
    pub fn observe_passive_conversation_list(
        &mut self,
        page: &ProviderPage,
        wait: Duration,
    ) -> Result<Option<ObservedConversationListResponse>, BrowserDriverError> {
        if wait > CONVERSATION_LIST_MAX_WAIT {
            return Err(BrowserDriverError::ConversationListWaitTooLong);
        }
        if page.origin != PageOrigin::ProtonMail {
            return Err(BrowserDriverError::MailOriginRequired);
        }
        let session = self.attach(page)?;
        let observed =
            // jig-ignore-next-line: canonical rustfmt line.
            self.observe_passive_conversation_list_in_session(page, &session, wait, None);
        let detached = self.detach(&session);
        let list = observed?;
        detached?;
        Ok(list.map(|captured| captured.response))
    }

    fn observe_passive_conversation_list_in_session(
        &mut self,
        page: &ProviderPage,
        session: &str,
        wait: Duration,
        expected_page: Option<&MailboxListEvidence>,
    ) -> Result<Option<CapturedConversationListResponse>, BrowserDriverError> {
        let before = self.inspect_mail_shell_in_session(page, session)?;
        if !before.ready() {
            return Err(BrowserDriverError::MailShellNotReady);
        }
        let network_params = json!({
            "maxPostDataSize": 0u16,
            // jig-ignore-next-line: canonical rustfmt line.
            "maxResourceBufferSize": ObservedConversationListResponse::MAX_BODY_BYTES,
            "maxTotalBufferSize": CONVERSATION_LIST_TOTAL_BUFFER_BYTES
        });
        let mut capture = ConversationListNetworkCapture::new(session);
        self.enable_network_observing(session, &network_params, &mut capture)?;
        let deadline = Instant::now()
            .checked_add(wait)
            .ok_or(BrowserDriverError::ConversationListWaitTooLong)?;
        let observed =
            // jig-ignore-next-line: canonical rustfmt line.
            self.capture_passive_conversation_list(session, &mut capture, deadline, expected_page);
        let disabled =
            // jig-ignore-next-line: canonical rustfmt line.
            self.call_in_session_observing(session, "Network.disable", &json!({}), &mut capture);
        let residual = capture.tracked_request_count();
        let list = observed?;
        disabled?;
        if residual != 0 {
            return Err(BrowserDriverError::ConversationListAmbiguous);
        }
        let after = self.inspect_mail_shell_in_session(page, session)?;
        if !after.ready() {
            return Err(BrowserDriverError::MailShellNotReady);
        }
        self.ensure_page_origin(page, session)?;
        Ok(list)
    }

    fn capture_passive_conversation_list(
        &mut self,
        session: &str,
        capture: &mut ConversationListNetworkCapture,
        deadline: Instant,
        expected_page: Option<&MailboxListEvidence>,
    ) -> Result<Option<CapturedConversationListResponse>, BrowserDriverError> {
        // jig-ignore-next-line: canonical rustfmt line.
        let Some((request_id, requested_page, anchor_continuation, initial_page_shape)) =
            self.wait_for_conversation_list_request(capture, deadline)?
        else {
            return Ok(None);
        };
        let request_id = guard_selected_request(request_id);
        // Never decode an irrelevant provider body when the already-visible
        // pagination evidence rules out a match to this request.
        if expected_page.is_some_and(|visible| {
            anchor_continuation
                || !initial_page_shape
                || !conversation_request_page_matches(visible, requested_page)
        }) {
            return Err(BrowserDriverError::ConversationListPageUnproven);
        }
        let body = self.read_cdp_body(session, &request_id, capture)?;
        let response = ObservedConversationListResponse::parse_cdp_body(&body)
            .map_err(BrowserDriverError::ConversationListResponse)?;
        Ok(Some(CapturedConversationListResponse {
            response,
            requested_page,
            anchor_continuation,
            initial_page_shape,
        }))
    }

    fn wait_for_conversation_list_request(
        &mut self,
        capture: &mut ConversationListNetworkCapture,
        deadline: Instant,
    ) -> Result<Option<CapturedConversationListRequest>, BrowserDriverError> {
        // jig-ignore-next-line: canonical rustfmt line.
        if let Some(request) = take_one_finished_conversation_list_request(capture)? {
            return Ok(Some(request));
        }
        let mut unsolicited = 0u16;
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            self.reader
                .get_mut()
                .set_read_timeout(Some(remaining.min(PIPE_TIMEOUT)))
                .map_err(|_error| BrowserDriverError::PipeSetup)?;
            let frame = read_frame_waiting(&mut self.reader);
            self.reader
                .get_mut()
                .set_read_timeout(Some(PIPE_TIMEOUT))
                .map_err(|_error| BrowserDriverError::PipeSetup)?;
            let Some(frame) = frame? else {
                continue;
            };
            unsolicited = unsolicited
                .checked_add(1)
                .ok_or(BrowserDriverError::ConversationListAmbiguous)?;
            if unsolicited > MAX_UNSOLICITED {
                return Err(BrowserDriverError::ConversationListAmbiguous);
            }
            let message = decode_cdp_frame(&frame)?;
            validate_cdp_notification(&message)?;
            capture
                .observe(&message)
                .map_err(BrowserDriverError::ConversationListNetwork)?;
            // jig-ignore-next-line: canonical rustfmt line.
            if let Some(request) = take_one_finished_conversation_list_request(capture)? {
                return Ok(Some(request));
            }
        }
        Ok(None)
    }

    // jig-ignore-next-line: canonical rustfmt line.
    /// Matches stable visible row IDs to one passive conversation-list response.
    ///
    /// No read triggers a click, reload, provider request, or mailbox mutation.
    /// The current page must not be provably in message mode; this does not
    /// establish that an unknown-mode page displays conversations. Matching
    /// alone never establishes a durable snapshot or public thread listing.
    ///
    /// # Errors
    ///
    /// Fails closed for message-mode pages, unsettled or changing row IDs,
    /// unmatched provider metadata, invalid Network traffic, or origin drift.
    pub fn observe_visible_conversation_metadata(
        &mut self,
        page: &ProviderPage,
        wait: Duration,
        // jig-ignore-next-line: canonical rustfmt line.
    ) -> Result<Option<ReconciledVisibleConversationMetadata>, BrowserDriverError> {
        if wait > CONVERSATION_LIST_MAX_WAIT {
            return Err(BrowserDriverError::ConversationListWaitTooLong);
        }
        if page.origin != PageOrigin::ProtonMail {
            return Err(BrowserDriverError::MailOriginRequired);
        }
        let session = self.attach(page)?;
        // jig-ignore-next-line: canonical rustfmt line.
        let observed = self.observe_visible_conversation_metadata_in_session(page, &session, wait);
        let detached = self.detach(&session);
        let metadata = observed?;
        detached?;
        Ok(metadata)
    }

    fn observe_visible_conversation_metadata_in_session(
        &mut self,
        page: &ProviderPage,
        session: &str,
        wait: Duration,
        // jig-ignore-next-line: canonical rustfmt line.
    ) -> Result<Option<ReconciledVisibleConversationMetadata>, BrowserDriverError> {
        let before_mode = self.inspect_mailbox_mode_in_session(page, session)?;
        if before_mode.mode() == MailboxRenderMode::Messages {
            return Err(BrowserDriverError::ConversationListMessageMode);
        }
        let before = self.inspect_mailbox_list_in_session(page, session)?;
        match before.state() {
            // jig-ignore-next-line: canonical rustfmt line.
            MailboxListState::SettledRows | MailboxListState::SettledExplicitEmpty => {}
            // jig-ignore-next-line: canonical rustfmt line.
            MailboxListState::Loading | MailboxListState::SettledNoRowsUnproven => {
                return Err(BrowserDriverError::MailboxPageNotSettled);
            }
        }
        let observed =
            // jig-ignore-next-line: canonical rustfmt line.
            self.observe_passive_conversation_list_in_session(page, session, wait, Some(&before))?;
        let after_mode = self.inspect_mailbox_mode_in_session(page, session)?;
        if after_mode != before_mode {
            return Err(BrowserDriverError::MailboxModeChanged);
        }
        let after = self.inspect_mailbox_list_in_session(page, session)?;
        if before != after {
            return Err(BrowserDriverError::MailboxPageChanged);
        }
        let Some(response) = observed else {
            return Ok(None);
        };
        if response.anchor_continuation
            || !response.initial_page_shape
            // jig-ignore-next-line: canonical rustfmt line.
            || !conversation_request_page_matches(&before, response.requested_page)
        {
            return Err(BrowserDriverError::ConversationListPageUnproven);
        }
        let ids = before
            .row_ids()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        // jig-ignore-next-line: canonical rustfmt line.
        ReconciledVisibleConversationMetadata::reconcile(&ids, &response.response)
            .map(Some)
            .map_err(BrowserDriverError::ConversationListReconciliation)
    }

    /// Passively observes the next browser-owned attachment metadata GET.
    ///
    /// This does not click, navigate, reload, or inject a provider API request.
    /// The response must bind its attachment to `expected_message_id`. A clean
    /// timeout is `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Rejects waits above 30 seconds, invalid parent IDs, non-Mail/unready
    /// pages, ambiguous or unsafe metadata lifecycles, response projection
    /// failure, parent-message mismatch, or origin drift.
    pub fn observe_passive_attachment_metadata(
        &mut self,
        page: &ProviderPage,
        expected_message_id: &str,
        wait: Duration,
        // jig-ignore-next-line: canonical rustfmt line.
    ) -> Result<Option<ObservedAttachmentMetadataResponse>, BrowserDriverError> {
        if wait > ATTACHMENT_METADATA_MAX_WAIT {
            return Err(BrowserDriverError::AttachmentMetadataWaitTooLong);
        }
        validate_expected_message_id(expected_message_id)
            .map_err(BrowserDriverError::AttachmentMetadataResponse)?;
        if page.origin != PageOrigin::ProtonMail {
            return Err(BrowserDriverError::MailOriginRequired);
        }
        let session = self.attach(page)?;
        let observed = self.observe_passive_attachment_metadata_in_session(
            page,
            &session,
            expected_message_id,
            wait,
        );
        let detached = self.detach(&session);
        let metadata = observed?;
        detached?;
        Ok(metadata)
    }

    fn observe_passive_attachment_metadata_in_session(
        &mut self,
        page: &ProviderPage,
        session: &str,
        expected_message_id: &str,
        wait: Duration,
        // jig-ignore-next-line: canonical rustfmt line.
    ) -> Result<Option<ObservedAttachmentMetadataResponse>, BrowserDriverError> {
        let before = self.inspect_mail_shell_in_session(page, session)?;
        if !before.ready() {
            return Err(BrowserDriverError::MailShellNotReady);
        }
        let network_params = json!({
            "maxPostDataSize": 0u16,
            // jig-ignore-next-line: canonical rustfmt line.
            "maxResourceBufferSize": ObservedAttachmentMetadataResponse::MAX_BODY_BYTES,
            "maxTotalBufferSize": ATTACHMENT_METADATA_TOTAL_BUFFER_BYTES
        });
        let mut capture = AttachmentMetadataNetworkCapture::new(session);
        self.enable_network_observing(session, &network_params, &mut capture)?;
        let deadline = Instant::now()
            .checked_add(wait)
            .ok_or(BrowserDriverError::AttachmentMetadataWaitTooLong)?;
        let observed = self.capture_passive_attachment_metadata(
            session,
            &mut capture,
            expected_message_id,
            deadline,
        );
        let disabled =
            // jig-ignore-next-line: canonical rustfmt line.
            self.call_in_session_observing(session, "Network.disable", &json!({}), &mut capture);
        let residual = capture.tracked_request_count();
        let metadata = observed?;
        disabled?;
        if residual != 0 {
            return Err(BrowserDriverError::AttachmentMetadataAmbiguous);
        }
        let after = self.inspect_mail_shell_in_session(page, session)?;
        if !after.ready() {
            return Err(BrowserDriverError::MailShellNotReady);
        }
        self.ensure_page_origin(page, session)?;
        Ok(metadata)
    }

    fn capture_passive_attachment_metadata(
        &mut self,
        session: &str,
        capture: &mut AttachmentMetadataNetworkCapture,
        expected_message_id: &str,
        deadline: Instant,
        // jig-ignore-next-line: canonical rustfmt line.
    ) -> Result<Option<ObservedAttachmentMetadataResponse>, BrowserDriverError> {
        let Some((request_id, attachment_id)) =
            self.wait_for_attachment_metadata_request(capture, deadline)?
        else {
            return Ok(None);
        };
        let request_id = guard_selected_request(request_id);
        let attachment_id = guard_selected_request(attachment_id);
        let body = self.read_cdp_body(session, &request_id, capture)?;
        ObservedAttachmentMetadataResponse::parse_cdp_body(
            &attachment_id,
            expected_message_id,
            &body,
        )
        .map(Some)
        .map_err(BrowserDriverError::AttachmentMetadataResponse)
    }

    fn wait_for_attachment_metadata_request(
        &mut self,
        capture: &mut AttachmentMetadataNetworkCapture,
        deadline: Instant,
    ) -> Result<Option<(String, String)>, BrowserDriverError> {
        // jig-ignore-next-line: canonical rustfmt line.
        if let Some(request) = take_one_finished_attachment_metadata_request(capture)? {
            return Ok(Some(request));
        }
        let mut unsolicited = 0u16;
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            self.reader
                .get_mut()
                .set_read_timeout(Some(remaining.min(PIPE_TIMEOUT)))
                .map_err(|_error| BrowserDriverError::PipeSetup)?;
            let frame = read_frame_waiting(&mut self.reader);
            self.reader
                .get_mut()
                .set_read_timeout(Some(PIPE_TIMEOUT))
                .map_err(|_error| BrowserDriverError::PipeSetup)?;
            let Some(frame) = frame? else {
                continue;
            };
            unsolicited = unsolicited
                .checked_add(1)
                .ok_or(BrowserDriverError::AttachmentMetadataAmbiguous)?;
            if unsolicited > MAX_UNSOLICITED {
                return Err(BrowserDriverError::AttachmentMetadataAmbiguous);
            }
            let message = decode_cdp_frame(&frame)?;
            validate_cdp_notification(&message)?;
            capture
                .observe(&message)
                .map_err(BrowserDriverError::AttachmentMetadataNetwork)?;
            // jig-ignore-next-line: canonical rustfmt line.
            if let Some(request) = take_one_finished_attachment_metadata_request(capture)? {
                return Ok(Some(request));
            }
        }
        Ok(None)
    }

    /// Passively observes the next browser-owned single-message detail GET.
    ///
    /// This method does not click, navigate, reload, or inject a provider API
    /// request. It only waits for Proton Mail itself to issue one exact detail
    /// GET while Network observation is active, then projects its response. A
    /// clean timeout is `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Rejects waits above 30 seconds, non-Mail/unready pages, ambiguous or
    /// unsafe detail request lifecycles, response projection failure, or origin
    /// drift.
    pub fn observe_passive_message_detail(
        &mut self,
        page: &ProviderPage,
        wait: Duration,
    ) -> Result<Option<ObservedMessageDetailResponse>, BrowserDriverError> {
        if wait > MESSAGE_DETAIL_MAX_WAIT {
            return Err(BrowserDriverError::MessageDetailWaitTooLong);
        }
        if page.origin != PageOrigin::ProtonMail {
            return Err(BrowserDriverError::MailOriginRequired);
        }
        let session = self.attach(page)?;
        // jig-ignore-next-line: canonical rustfmt line.
        let observed = self.observe_passive_message_detail_in_session(page, &session, wait);
        let detached = self.detach(&session);
        let detail = observed?;
        detached?;
        Ok(detail)
    }

    fn observe_passive_message_detail_in_session(
        &mut self,
        page: &ProviderPage,
        session: &str,
        wait: Duration,
    ) -> Result<Option<ObservedMessageDetailResponse>, BrowserDriverError> {
        let before = self.inspect_mail_shell_in_session(page, session)?;
        if !before.ready() {
            return Err(BrowserDriverError::MailShellNotReady);
        }
        let network_params = json!({
            "maxPostDataSize": 0u16,
            // jig-ignore-next-line: canonical rustfmt line.
            "maxResourceBufferSize": ObservedMessageDetailResponse::MAX_BODY_BYTES,
            "maxTotalBufferSize": MESSAGE_DETAIL_TOTAL_BUFFER_BYTES
        });
        let mut capture = MessageDetailNetworkCapture::new(session);
        self.enable_network_observing(session, &network_params, &mut capture)?;
        let deadline = Instant::now()
            .checked_add(wait)
            .ok_or(BrowserDriverError::MessageDetailWaitTooLong)?;
        // jig-ignore-next-line: canonical rustfmt line.
        let observed = self.capture_passive_message_detail(session, &mut capture, deadline);
        let disabled =
            // jig-ignore-next-line: canonical rustfmt line.
            self.call_in_session_observing(session, "Network.disable", &json!({}), &mut capture);
        let residual = capture.tracked_request_count();
        let detail = observed?;
        disabled?;
        if residual != 0 {
            return Err(BrowserDriverError::MessageDetailAmbiguous);
        }
        let after = self.inspect_mail_shell_in_session(page, session)?;
        if !after.ready() {
            return Err(BrowserDriverError::MailShellNotReady);
        }
        self.ensure_page_origin(page, session)?;
        Ok(detail)
    }

    fn capture_passive_message_detail(
        &mut self,
        session: &str,
        capture: &mut MessageDetailNetworkCapture,
        deadline: Instant,
    ) -> Result<Option<ObservedMessageDetailResponse>, BrowserDriverError> {
        let Some((request_id, message_id)) =
            self.wait_for_message_detail_request(capture, deadline)?
        else {
            return Ok(None);
        };
        let request_id = guard_selected_request(request_id);
        let message_id = guard_selected_request(message_id);
        let body = self.read_cdp_body(session, &request_id, capture)?;
        ObservedMessageDetailResponse::parse_cdp_body(&message_id, &body)
            .map(Some)
            .map_err(BrowserDriverError::MessageDetailResponse)
    }

    fn wait_for_message_detail_request(
        &mut self,
        capture: &mut MessageDetailNetworkCapture,
        deadline: Instant,
    ) -> Result<Option<(String, String)>, BrowserDriverError> {
        // jig-ignore-next-line: canonical rustfmt line.
        if let Some(request) = take_one_finished_message_detail_request(capture)? {
            return Ok(Some(request));
        }
        let mut unsolicited = 0u16;
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            self.reader
                .get_mut()
                .set_read_timeout(Some(remaining.min(PIPE_TIMEOUT)))
                .map_err(|_error| BrowserDriverError::PipeSetup)?;
            let frame = read_frame_waiting(&mut self.reader);
            self.reader
                .get_mut()
                .set_read_timeout(Some(PIPE_TIMEOUT))
                .map_err(|_error| BrowserDriverError::PipeSetup)?;
            let Some(frame) = frame? else {
                continue;
            };
            unsolicited = unsolicited
                .checked_add(1)
                .ok_or(BrowserDriverError::MessageDetailAmbiguous)?;
            if unsolicited > MAX_UNSOLICITED {
                return Err(BrowserDriverError::MessageDetailAmbiguous);
            }
            let message = decode_cdp_frame(&frame)?;
            validate_cdp_notification(&message)?;
            capture
                .observe(&message)
                .map_err(BrowserDriverError::MessageDetailNetwork)?;
            // jig-ignore-next-line: canonical rustfmt line.
            if let Some(request) = take_one_finished_message_detail_request(capture)? {
                return Ok(Some(request));
            }
        }
        Ok(None)
    }

    /// Reloads a proven message-mode Mail page and projects one exact list
    /// response through the bounded CDP Network observer.
    ///
    /// Network request/response headers, cookies, POST bodies, and unrelated
    /// response bodies are never retained. The returned value contains only
    /// provider message ID, numeric Time, Order, and the provider-reported
    /// total. This diagnostic evidence does not establish public cursor or
    /// snapshot semantics.
    ///
    /// # Errors
    ///
    /// Fails for non-Mail/message-mode pages, origin or mode drift, Network
    /// lifecycle ambiguity, unsupported body encoding, malformed list data,
    /// or any CDP transport/protocol failure.
    pub fn observe_message_list_response(
        &mut self,
        page: &ProviderPage,
    ) -> Result<ObservedMessageListResponse, BrowserDriverError> {
        if page.origin != PageOrigin::ProtonMail {
            return Err(BrowserDriverError::MailOriginRequired);
        }
        let session = self.attach(page)?;
        // jig-ignore-next-line: canonical rustfmt line.
        let observed = self.observe_message_list_response_in_session(page, &session);
        let detached = self.detach(&session);
        let response = observed?;
        detached?;
        Ok(response)
    }

    /// Captures one exact list response and reconciles it to stable visible
    /// rows.
    ///
    /// This remains diagnostic evidence only. A single captured response may
    /// fail coverage when `WebClients` splits the visible list across batches.
    ///
    /// # Errors
    ///
    /// Returns the underlying Network, stable-page, or reconciliation error.
    pub fn observe_visible_message_metadata(
        &mut self,
        page: &ProviderPage,
    ) -> Result<ReconciledVisibleMessageMetadata, BrowserDriverError> {
        if page.origin != PageOrigin::ProtonMail {
            return Err(BrowserDriverError::MailOriginRequired);
        }
        let session = self.attach(page)?;
        // jig-ignore-next-line: canonical rustfmt line.
        let observed = self.observe_visible_message_metadata_in_session(page, &session);
        let detached = self.detach(&session);
        let metadata = observed?;
        detached?;
        Ok(metadata)
    }

    fn observe_visible_message_metadata_in_session(
        &mut self,
        page: &ProviderPage,
        session: &str,
    ) -> Result<ReconciledVisibleMessageMetadata, BrowserDriverError> {
        // jig-ignore-next-line: canonical rustfmt line.
        let observed = self.observe_message_list_responses_in_session(page, session)?;
        let snapshot = self.read_message_page_in_session(page, session)?;
        ensure_message_list_page_matches(&snapshot, observed.initial_page)?;
        let first = observed
            .responses
            .first()
            .ok_or(BrowserDriverError::Protocol)?;
        let limit = u64::try_from(observed.initial_limit)
            .map_err(|_error| BrowserDriverError::MessageListPageMismatch)?;
        let page_end = (u64::from(observed.initial_page) + 1)
            .checked_mul(limit)
            .ok_or(BrowserDriverError::MessageListPageMismatch)?;
        let total_exhausted = first.total() <= page_end;
        let next_enabled = snapshot.next_page() == NextPageControl::Enabled;
        if total_exhausted && next_enabled {
            return Err(BrowserDriverError::MessageListPageMismatch);
        }
        snapshot
            .reconcile_metadata(from_ref(first))
            .map_err(BrowserDriverError::MessageListReconciliation)
    }

    fn observe_message_list_response_in_session(
        &mut self,
        page: &ProviderPage,
        session: &str,
    ) -> Result<ObservedMessageListResponse, BrowserDriverError> {
        // jig-ignore-next-line: canonical rustfmt line.
        let observed = self.observe_message_list_responses_in_session(page, session)?;
        if observed.responses.len() != 1 {
            return Err(BrowserDriverError::MessageListResponseAmbiguous);
        }
        let mut observed = observed;
        take(&mut observed.responses)
            .into_iter()
            .next()
            .ok_or(BrowserDriverError::Protocol)
    }

    fn observe_message_list_responses_in_session(
        &mut self,
        page: &ProviderPage,
        session: &str,
    ) -> Result<CapturedMessageListResponses, BrowserDriverError> {
        let before_mode = self.inspect_mailbox_mode_in_session(page, session)?;
        if before_mode.mode() != MailboxRenderMode::Messages {
            return Err(BrowserDriverError::MailboxMessageModeRequired);
        }
        let network_params = json!({
            "maxPostDataSize": 0u16,
            // jig-ignore-next-line: canonical rustfmt line.
            "maxResourceBufferSize": ObservedMessageListResponse::MAX_BODY_BYTES,
            "maxTotalBufferSize": MESSAGE_LIST_TOTAL_BUFFER_BYTES
        });
        self.enable_network_in_session(session, &network_params)?;
        let mut capture = MessageListNetworkCapture::new(session);
        // jig-ignore-next-line: canonical rustfmt line.
        let observed = self.reload_and_capture_message_lists(session, &mut capture);
        let disabled =
            // jig-ignore-next-line: canonical rustfmt line.
            self.call_in_session_observing(session, "Network.disable", &json!({}), &mut capture);
        let residual_requests = capture.tracked_request_count();
        let captured = observed?;
        disabled?;
        if residual_requests != 0 {
            return Err(BrowserDriverError::MessageListResponseAmbiguous);
        }
        let after_mode = self.mailbox_mode_in_session(session)?;
        self.ensure_page_origin(page, session)?;
        if after_mode != before_mode {
            return Err(BrowserDriverError::MailboxModeChanged);
        }
        Ok(captured)
    }

    fn reload_and_capture_message_lists(
        &mut self,
        session: &str,
        capture: &mut MessageListNetworkCapture,
    ) -> Result<CapturedMessageListResponses, BrowserDriverError> {
        self.call_in_session_observing(
            session,
            "Page.reload",
            &json!({"ignoreCache": false}),
            capture,
        )?;
        let first_request = self.wait_for_message_list_request(capture)?;
        if first_request.continuation {
            return Err(BrowserDriverError::MessageListBatchIncompatible);
        }
        let initial_page = first_request
            .page
            .ok_or(BrowserDriverError::MessageListBatchIncompatible)?;
        let initial_sort_key = first_request.sort_key.clone();
        let initial_descending = first_request.descending;
        // jig-ignore-next-line: canonical rustfmt line.
        let first = self.read_message_list_body(session, &first_request, capture)?;
        let (expected_first, expected_second) =
            // jig-ignore-next-line: canonical rustfmt line.
            expected_message_list_batch_lengths(initial_page, first_request.limit, first.total())?;
        if first.messages().len() != expected_first
            || !response_matches_declared_time_order(&first_request, &first)
        {
            return Err(BrowserDriverError::MessageListBatchIncompatible);
        }
        // When Total ends exactly on a full batch boundary, the initial
        // response already covers the final page. Do not require a second
        // empty anchored request, but refuse an unexpected extra request.
        let final_batch_is_exact = expected_second == 0;
        let underfilled = first.messages().len() < first_request.limit;
        if underfilled || final_batch_is_exact {
            if capture.tracked_request_count() != 0 {
                return Err(BrowserDriverError::MessageListResponseAmbiguous);
            }
            return Ok(CapturedMessageListResponses {
                responses: vec![first],
                initial_page,
                initial_limit: first_request.limit,
                initial_sort_key,
                initial_descending,
            });
        }

        let second_request = self.wait_for_message_list_request(capture)?;
        let last_message = first
            .messages()
            .last()
            .ok_or(BrowserDriverError::MessageListBatchIncompatible)?;
        if !second_request.continuation
            || second_request.limit != first_request.limit
            || second_request.sort_key != first_request.sort_key
            || second_request.descending != first_request.descending
            || second_request.anchor != Some(last_message.time())
            || second_request.anchor_id.as_deref() != Some(last_message.id())
        {
            return Err(BrowserDriverError::MessageListBatchIncompatible);
        }
        // jig-ignore-next-line: canonical rustfmt line.
        let second = self.read_message_list_body(session, &second_request, capture)?;
        // Prefetched rows cannot prove the currently visible page, but they
        // must not silently repeat an ID from the accepted initial batch.
        let initial_ids = first
            .messages()
            .iter()
            .map(ObservedMessageMetadata::id)
            .collect::<HashSet<_>>();
        let duplicated = second
            .messages()
            .iter()
            .any(|message| initial_ids.contains(message.id()));
        if duplicated
            || second.messages().len() != expected_second
            || !response_matches_declared_time_order(&second_request, &second)
            // jig-ignore-next-line: canonical rustfmt line.
            || !batch_boundary_matches_time_order(&first_request, &first, &second)
        {
            return Err(BrowserDriverError::MessageListBatchIncompatible);
        }
        if capture.tracked_request_count() != 0 {
            return Err(BrowserDriverError::MessageListResponseAmbiguous);
        }
        Ok(CapturedMessageListResponses {
            responses: vec![first, second],
            initial_page,
            initial_limit: first_request.limit,
            initial_sort_key,
            initial_descending,
        })
    }

    fn read_message_list_body(
        &mut self,
        session: &str,
        request: &CompletedMessageListRequest,
        capture: &mut MessageListNetworkCapture,
    ) -> Result<ObservedMessageListResponse, BrowserDriverError> {
        // jig-ignore-next-line: canonical list capture request invocation.
        let body = self.read_cdp_body(session, request.request_id.as_str(), capture)?;
        ObservedMessageListResponse::parse_cdp_body(&body)
            .map_err(BrowserDriverError::MessageListResponse)
    }

    fn wait_for_message_list_request(
        &mut self,
        capture: &mut MessageListNetworkCapture,
    ) -> Result<CompletedMessageListRequest, BrowserDriverError> {
        if let Some(request) = take_one_finished_request(capture)? {
            return Ok(request);
        }
        let deadline = Instant::now()
            .checked_add(MESSAGE_LIST_CAPTURE_TIMEOUT)
            .ok_or(BrowserDriverError::MessageListResponseUnavailable)?;
        for _event in 0..MAX_UNSOLICITED {
            if Instant::now() >= deadline {
                return Err(BrowserDriverError::MessageListResponseUnavailable);
            }
            let frame = read_frame(&mut self.reader)?;
            let message = decode_cdp_frame(&frame)?;
            validate_cdp_notification(&message)?;
            capture
                .observe(&message)
                .map_err(BrowserDriverError::MessageListNetwork)?;
            if let Some(request) = take_one_finished_request(capture)? {
                return Ok(request);
            }
        }
        Err(BrowserDriverError::MessageListResponseUnavailable)
    }

    fn inspect_mailbox_sort_in_session(
        &mut self,
        page: &ProviderPage,
        session: &str,
    ) -> Result<MailboxSortOrder, BrowserDriverError> {
        let shell = self.inspect_mail_shell_in_session(page, session)?;
        if !shell.ready() {
            return Err(BrowserDriverError::MailShellNotReady);
        }
        self.ensure_page_origin(page, session)?;
        let expression = MailboxSortOrder::open_expression();
        let activation_value = self.runtime_value(session, expression)?;
        let activation = SortMenuActivation::from_value(&activation_value)?;
        let inspected = self.wait_for_mailbox_sort(session);
        let cleanup = match activation {
            SortMenuActivation::AlreadyOpen => Ok(()),
            // jig-ignore-next-line: canonical rustfmt line.
            SortMenuActivation::Opened => self.close_mailbox_sort_menu(page, session),
        };
        let sort = inspected?;
        cleanup?;
        self.ensure_page_origin(page, session)?;
        Ok(sort)
    }

    fn wait_for_mailbox_sort(
        &mut self,
        session: &str,
    ) -> Result<MailboxSortOrder, BrowserDriverError> {
        let deadline = Instant::now()
            .checked_add(SORT_MENU_TIMEOUT)
            .ok_or(BrowserDriverError::MailboxSortTimeout)?;
        loop {
            let expression = MailboxSortOrder::expression();
            let value = self.runtime_value(session, expression)?;
            match MailboxSortOrder::from_value(&value) {
                Ok(Some(sort)) => return Ok(sort),
                Ok(None) => {}
                Err(()) => {
                    return Err(BrowserDriverError::MailboxSortIncompatible);
                }
            }
            if Instant::now() >= deadline {
                return Err(BrowserDriverError::MailboxSortTimeout);
            }
            thread::sleep(SORT_MENU_DELAY);
        }
    }

    fn close_mailbox_sort_menu(
        &mut self,
        page: &ProviderPage,
        session: &str,
    ) -> Result<(), BrowserDriverError> {
        self.ensure_page_origin(page, session)?;
        let close = MailboxSortOrder::close_expression();
        let clicked = self.runtime_value(session, close)?;
        if clicked.as_bool() != Some(true) {
            return Err(BrowserDriverError::MailboxSortIncompatible);
        }
        let deadline = Instant::now()
            .checked_add(SORT_MENU_TIMEOUT)
            .ok_or(BrowserDriverError::MailboxSortTimeout)?;
        loop {
            let closed_expression = MailboxSortOrder::closed_expression();
            let closed = self.runtime_value(session, closed_expression)?;
            match closed.as_bool() {
                Some(true) => return Ok(()),
                Some(false) => {}
                None => return Err(BrowserDriverError::MailboxSortIncompatible),
            }
            if Instant::now() >= deadline {
                return Err(BrowserDriverError::MailboxSortTimeout);
            }
            thread::sleep(SORT_MENU_DELAY);
        }
    }

    /// Reads a stable visible page only when message mode is externally proven.
    ///
    /// Row identifiers in the returned snapshot are message identifiers because
    /// `WebClients` forces individual-message rows for the proven location.
    ///
    /// # Errors
    ///
    /// Fails when message mode is not proven, changes during the read, or any
    /// existing shell/list/origin snapshot invariant fails.
    pub fn read_visible_message_page(
        &mut self,
        page: &ProviderPage,
    ) -> Result<VisibleMessagePageSnapshot, BrowserDriverError> {
        if page.origin != PageOrigin::ProtonMail {
            return Err(BrowserDriverError::MailOriginRequired);
        }
        let session = self.attach(page)?;
        let read = self.read_message_page_in_session(page, &session);
        let detached = self.detach(&session);
        let snapshot = read?;
        detached?;
        Ok(snapshot)
    }

    fn read_message_page_in_session(
        &mut self,
        page: &ProviderPage,
        session: &str,
    ) -> Result<VisibleMessagePageSnapshot, BrowserDriverError> {
        let before_mode = self.inspect_mailbox_mode_in_session(page, session)?;
        if before_mode.mode() != MailboxRenderMode::Messages {
            return Err(BrowserDriverError::MailboxMessageModeRequired);
        }
        let snapshot = self.read_mailbox_page_in_session(page, session)?;
        let after_mode = self.mailbox_mode_in_session(session)?;
        self.ensure_page_origin(page, session)?;
        if after_mode != before_mode {
            return Err(BrowserDriverError::MailboxModeChanged);
        }
        Ok(VisibleMessagePageSnapshot::new(snapshot))
    }

    /// Advances exactly one visible message page and returns its stable rows.
    ///
    /// This is read-only mailbox navigation: it activates only Mail's verified
    /// next-page control and does not target any mailbox mutation control.
    ///
    /// # Errors
    ///
    /// Fails unless message mode is proven and current page is explicit,
    /// Next is enabled, the control remains valid at click time, and the list
    /// settles on exactly the following page with unchanged provider semantics.
    pub fn read_next_visible_message_page(
        &mut self,
        page: &ProviderPage,
    ) -> Result<VisibleMessagePageSnapshot, BrowserDriverError> {
        if page.origin != PageOrigin::ProtonMail {
            return Err(BrowserDriverError::MailOriginRequired);
        }
        let session = self.attach(page)?;
        let read = self.read_next_message_page_in_session(page, &session);
        let detached = self.detach(&session);
        let snapshot = read?;
        detached?;
        Ok(snapshot)
    }

    fn read_next_message_page_in_session(
        &mut self,
        page: &ProviderPage,
        session: &str,
    ) -> Result<VisibleMessagePageSnapshot, BrowserDriverError> {
        let before = self.read_message_page_in_session(page, session)?;
        if before.next_page() != NextPageControl::Enabled {
            return Err(BrowserDriverError::MailboxNextPageUnavailable);
        }
        let current = before
            .current_page()
            .ok_or(BrowserDriverError::MailboxPaginationIncompatible)?;
        let expected = current
            .checked_add(1)
            .ok_or(BrowserDriverError::MailboxPaginationIncompatible)?;
        let activation = self.activate_next_page(session)?;
        if activation != NextPageActivation::Clicked {
            return Err(BrowserDriverError::MailboxPaginationChanged);
        }
        self.wait_for_message_page(page, session, current, expected)?;
        let after = self.read_message_page_in_session(page, session)?;
        if after.current_page() != Some(expected) {
            return Err(BrowserDriverError::MailboxPaginationChanged);
        }
        Ok(after)
    }

    fn activate_next_page(
        &mut self,
        session: &str,
    ) -> Result<NextPageActivation, BrowserDriverError> {
        let expression = NextPageActivation::expression();
        let value = self.runtime_value(session, expression)?;
        NextPageActivation::from_value(&value)
            .map_err(|_error| BrowserDriverError::MailboxPaginationIncompatible)
    }

    fn wait_for_message_page(
        &mut self,
        page: &ProviderPage,
        session: &str,
        previous: u32,
        expected: u32,
    ) -> Result<(), BrowserDriverError> {
        let deadline = Instant::now()
            .checked_add(PAGE_ADVANCE_TIMEOUT)
            .ok_or(BrowserDriverError::MailboxPaginationTimeout)?;
        loop {
            if Instant::now() >= deadline {
                return Err(BrowserDriverError::MailboxPaginationTimeout);
            }
            self.ensure_page_origin(page, session)?;
            if Instant::now() >= deadline {
                return Err(BrowserDriverError::MailboxPaginationTimeout);
            }
            let mode = self.mailbox_mode_in_session(session)?;
            if mode.mode() != MailboxRenderMode::Messages {
                return Err(BrowserDriverError::MailboxModeChanged);
            }
            if Instant::now() >= deadline {
                return Err(BrowserDriverError::MailboxPaginationTimeout);
            }
            let evidence = self.mailbox_list_in_session(session)?;
            match evidence.state() {
                // jig-ignore-next-line: Clippy-required or-pattern.
                MailboxListState::Loading | MailboxListState::SettledNoRowsUnproven => {}
                // jig-ignore-next-line: Clippy-required or-pattern.
                MailboxListState::SettledRows | MailboxListState::SettledExplicitEmpty => {
                    match evidence.current_page() {
                        Some(number) if number == expected => return Ok(()),
                        Some(number) if number == previous => {}
                        _ => return Err(pagination_changed()),
                    }
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(BrowserDriverError::MailboxPaginationTimeout);
            }
            thread::sleep(PAGE_ADVANCE_DELAY.min(remaining));
        }
    }

    /// Reads a stable snapshot of the currently visible mailbox page.
    ///
    /// The same target session revalidates origin and Mail-shell readiness,
    /// captures list evidence before and after content projection, and requires
    /// provider row IDs to remain identical in rendered order.
    ///
    /// # Errors
    ///
    /// Fails closed while loading, for unproven empty state, list changes,
    /// malformed visible rows, an unready shell, or origin drift.
    pub fn read_visible_mailbox_page(
        &mut self,
        page: &ProviderPage,
    ) -> Result<MailboxPageSnapshot, BrowserDriverError> {
        if page.origin != PageOrigin::ProtonMail {
            return Err(BrowserDriverError::MailOriginRequired);
        }
        let session = self.attach(page)?;
        let read = self.read_mailbox_page_in_session(page, &session);
        let detached = self.detach(&session);
        let snapshot = read?;
        detached?;
        Ok(snapshot)
    }

    fn read_mailbox_page_in_session(
        &mut self,
        page: &ProviderPage,
        session: &str,
    ) -> Result<MailboxPageSnapshot, BrowserDriverError> {
        let shell = self.inspect_mail_shell_in_session(page, session)?;
        if !shell.ready() {
            return Err(BrowserDriverError::MailShellNotReady);
        }
        let before = self.mailbox_list_in_session(session)?;
        let rows_value = match before.state() {
            MailboxListState::SettledRows => {
                // jig-ignore-next-line: canonical rustfmt line.
                Some(self.runtime_value(session, MailboxPageSnapshot::expression())?)
            }
            MailboxListState::SettledExplicitEmpty => None,
            // jig-ignore-next-line: canonical rustfmt line.
            MailboxListState::Loading | MailboxListState::SettledNoRowsUnproven => {
                return Err(BrowserDriverError::MailboxPageNotSettled);
            }
        };
        // Two consecutive read-only projections must agree on row content as
        // well as identity; unchanged list IDs alone miss edits to a subject,
        // correspondent address, or unread state during projection.
        let second_rows_value = if rows_value.is_some() {
            // jig-ignore-next-line: canonical rustfmt line.
            Some(self.runtime_value(session, MailboxPageSnapshot::expression())?)
        } else {
            None
        };
        let after = self.mailbox_list_in_session(session)?;
        // Authentication can expire without changing visible row identities.
        // Recheck the signed-in Mail shell before returning any row content.
        let after_shell = self.inspect_mail_shell_in_session(page, session)?;
        if !after_shell.ready() {
            return Err(BrowserDriverError::MailShellNotReady);
        }
        // Shell inspection takes time; reject lists which drift during that
        // final authentication check instead of releasing stale row content.
        let final_list = self.mailbox_list_in_session(session)?;
        if after != final_list {
            return Err(BrowserDriverError::MailboxPageChanged);
        }
        MailboxPageSnapshot::from_observations(
            &before,
            rows_value.as_deref(),
            second_rows_value.as_deref(),
            &final_list,
        )
    }

    fn mailbox_list_in_session(
        &mut self,
        session: &str,
    ) -> Result<MailboxListEvidence, BrowserDriverError> {
        // jig-ignore-next-line: canonical rustfmt line.
        let value = self.runtime_value(session, MailboxListEvidence::expression())?;
        MailboxListEvidence::from_runtime_value(&value)
            .map_err(|_error| BrowserDriverError::MailboxListIncompatible)
    }

    /// Requests a clean browser shutdown and waits for Chromium to exit.
    ///
    /// # Errors
    ///
    /// Returns an error if the close command cannot be sent or the browser does
    /// not exit within the bounded shutdown window.
    pub fn shutdown(mut self) -> Result<(), BrowserDriverError> {
        let id = self.allocate_id()?;
        self.send_request(id, None, "Browser.close", &json!({}))?;
        for _poll in 0..SHUTDOWN_POLLS {
            match self.child.try_wait() {
                Ok(Some(_status)) => return Ok(()),
                Ok(None) => thread::sleep(SHUTDOWN_DELAY),
                Err(_error) => return Err(BrowserDriverError::ProcessControl),
            }
        }
        let _ignored = self.child.kill();
        let _ignored = self.child.wait();
        Err(BrowserDriverError::ProcessControl)
    }

    fn verify_handshake(&mut self) -> Result<(), BrowserDriverError> {
        let result = self.call("Browser.getVersion", &json!({}))?;
        if result
            .get("product")
            .and_then(Value::as_str)
            .is_none_or(|product| product.is_empty() || product.len() > 256)
        {
            return Err(BrowserDriverError::Protocol);
        }
        Ok(())
    }

    fn call(
        &mut self,
        method: &str,
        params: &Value,
    ) -> Result<strict_json::SensitiveValue, BrowserDriverError> {
        self.call_with_session(None, method, params)
    }

    fn call_in_session(
        &mut self,
        session: &str,
        method: &str,
        params: &Value,
    ) -> Result<strict_json::SensitiveValue, BrowserDriverError> {
        self.call_with_session(Some(session), method, params)
    }

    fn call_with_session(
        &mut self,
        session: Option<&str>,
        method: &str,
        params: &Value,
    ) -> Result<strict_json::SensitiveValue, BrowserDriverError> {
        self.call_with_session_observer(session, method, params, None)
    }

    fn call_in_session_observing(
        &mut self,
        session: &str,
        method: &str,
        params: &Value,
        capture: &mut dyn CdpEventObserver,
    ) -> Result<strict_json::SensitiveValue, BrowserDriverError> {
        // jig-ignore-next-line: canonical rustfmt line.
        self.call_with_session_observer(Some(session), method, params, Some(capture))
    }

    // Request identifiers are private correlation selectors. Keep the
    // source parameter JSON guarded just like the encoded CDP frame.
    fn read_cdp_body(
        &mut self,
        session: &str,
        request_id: &str,
        capture: &mut dyn CdpEventObserver,
    ) -> Result<strict_json::SensitiveValue, BrowserDriverError> {
        let params = strict_json::SensitiveValue::from_owned(json!({
            "requestId": request_id
        }));
        let method = "Network.getResponseBody";
        self.call_in_session_observing(session, method, &params, capture)
    }

    /// Enables a reload-based Network capture, disabling on protocol rejection.
    fn enable_network_in_session(
        &mut self,
        session: &str,
        params: &Value,
    ) -> Result<(), BrowserDriverError> {
        // jig-ignore-next-line: canonical rustfmt line.
        if let Err(error) = self.call_in_session(session, "Network.enable", params) {
            self.call_in_session(session, "Network.disable", &json!({}))?;
            return Err(error);
        }
        Ok(())
    }

    /// Activates a bounded Network capture, cleaning up on CDP event failure.
    ///
    /// A malformed event may precede the successful enable reply. The observer
    /// drains that reply, then this helper disables Network before returning
    /// the original redacted error instead of leaking an active capture.
    fn enable_network_observing(
        &mut self,
        session: &str,
        params: &Value,
        capture: &mut dyn CdpEventObserver,
    ) -> Result<(), BrowserDriverError> {
        // jig-ignore-next-line: canonical rustfmt line.
        let enabled = self.call_in_session_observing(session, "Network.enable", params, capture);
        if let Err(error) = enabled {
            self.call_in_session(session, "Network.disable", &json!({}))?;
            return Err(error);
        }
        Ok(())
    }

    fn call_with_session_observer(
        &mut self,
        session: Option<&str>,
        method: &str,
        params: &Value,
        mut capture: Option<&mut dyn CdpEventObserver>,
    ) -> Result<strict_json::SensitiveValue, BrowserDriverError> {
        let id = self.allocate_id()?;
        self.send_request(id, session, method, params)?;

        // Drain the command reply even when an observed Network event fails.
        // This keeps the CDP stream synchronized for mandatory cleanup.
        let mut observation_error = None;
        for _event in 0..MAX_UNSOLICITED {
            let frame = read_frame(&mut self.reader)?;
            // Invalid JSON still occupies one bounded CDP frame. Remember
            // the protocol failure, but drain the genuine command reply before
            // Network cleanup rather than leaving the pipe out of sync.
            let Ok(mut message) = decode_cdp_frame(&frame) else {
                observation_error.get_or_insert(BrowserDriverError::Protocol);
                continue;
            };
            // jig-ignore-next-line: canonical rustfmt line.
            let Some(response_id) = message.get("id").and_then(Value::as_u64) else {
                if let Err(error) = validate_cdp_notification(&message) {
                    observation_error.get_or_insert(error);
                } else if observation_error.is_none()
                    && let Some(observer) = capture.as_deref_mut()
                {
                    observation_error = observer.observe_event(&message).err();
                }
                continue;
            };
            // A flattened target-session reply must echo the exact session.
            // A browser-scoped reply must not carry a session at all.
            let reply_scope = message.get("sessionId");
            let matching_reply_session = session.map_or_else(
                || reply_scope.is_none(),
                |expected| {
                    let observed = reply_scope.and_then(Value::as_str);
                    observed == Some(expected)
                },
            );
            // CDP command replies have no extension fields. An otherwise
            // plausible reply with extra keys cannot prove command success.
            let reply = message.as_object();
            let reply_fields = reply.ok_or(BrowserDriverError::Protocol)?;
            let allowed_reply_fields = ["id", "sessionId", "result", "error"];
            let unexpected_reply_field = reply_fields
                .keys()
                .any(|field| !allowed_reply_fields.contains(&field.as_str()));
            let same_reply = response_id == id && matching_reply_session;
            if !same_reply || unexpected_reply_field {
                observation_error.get_or_insert(BrowserDriverError::Protocol);
                continue;
            }
            if message.get("error").is_some() {
                return Err(BrowserDriverError::Protocol);
            }
            let result = message
                .get("result")
                .filter(|result| result.is_object())
                .ok_or(BrowserDriverError::Protocol)?;
            // Void commands and target attachment have exact result shapes.
            // An extension field must not acknowledge a browser action.
            if !valid_cdp_command_result(method, result) {
                return Err(BrowserDriverError::Protocol);
            }
            if let Some(error) = observation_error {
                return Err(error);
            }
            return message
                .take_object_field("result")
                .ok_or(BrowserDriverError::Protocol);
        }
        Err(BrowserDriverError::Protocol)
    }

    fn allocate_id(&mut self) -> Result<u64, BrowserDriverError> {
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(BrowserDriverError::Protocol)?;
        Ok(id)
    }

    fn send_request(
        &mut self,
        id: u64,
        session: Option<&str>,
        method: &str,
        params: &Value,
    ) -> Result<(), BrowserDriverError> {
        if !allowed_mail_cdp_request(session, method, params) {
            return Err(BrowserDriverError::Protocol);
        }
        // jig-ignore-next-line: rustfmt CDP request ownership.
        let request = strict_json::SensitiveValue::from_owned(session.map_or_else(
            || json!({"id": id, "method": method, "params": params}),
            |session_id| {
                json!({
                    "id": id,
                    "method": method,
                    "params": params,
                    "sessionId": session_id
                })
            },
        ));
        let bytes = encode_cdp_request_frame(&request)?;
        self.writer
            .write_all(&bytes)
            .map_err(|_error| BrowserDriverError::PipeIo)?;
        self.writer
            .flush()
            .map_err(|_error| BrowserDriverError::PipeIo)
    }
}

#[expect(
    clippy::allow_attributes,
    reason = "Cross-toolchain Drop lint changes require an explicit exemption"
)]
#[allow(
    clippy::missing_trait_methods,
    reason = "Drop::pin_drop is unstable and conflicts with Drop::drop"
)]
impl Drop for ManagedBrowser {
    fn drop(&mut self) {
        let _ignored = self.child.kill();
        let _ignored = self.child.wait();
    }
}

/// Fail-closed managed-browser error without provider or message content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrowserDriverError {
    /// More than one Proton Account/Mail page is visible.
    AmbiguousProviderPages,
    /// Browser process could not be launched.
    BrowserLaunch,
    /// No Proton Account/Mail page is visible.
    MissingProviderPage,
    /// Mail-shell inspection was requested for a non-Mail provider page.
    MailOriginRequired,
    /// Required Mail-shell landmarks are missing or blocked by a dialog.
    MailShellNotReady,
    /// Mailbox-list DOM evidence is malformed or contradictory.
    MailboxListIncompatible,
    /// Visible mailbox location evidence is malformed or contradictory.
    MailboxModeIncompatible,
    /// Message-mode proof changed during a content snapshot.
    MailboxModeChanged,
    /// Current visible location does not prove individual-message mode.
    MailboxMessageModeRequired,
    /// Current visible message page exposes no verifiable enabled Next action.
    MailboxNextPageUnavailable,
    /// Pagination control or observed page changed unexpectedly.
    MailboxPaginationChanged,
    /// Pagination evidence lacks an explicit usable current page.
    MailboxPaginationIncompatible,
    /// Mail did not settle on the expected following page within the bound.
    MailboxPaginationTimeout,
    /// Visible sort menu state is missing, duplicated, or contradictory.
    MailboxSortIncompatible,
    /// Sort menu open/close transition did not settle before its deadline.
    MailboxSortTimeout,
    /// Visible mailbox content changed while the snapshot was being read.
    MailboxPageChanged,
    /// Visible mailbox row content is malformed or contradicts list evidence.
    MailboxPageIncompatible,
    /// Mailbox list is loading or lacks explicit settled-empty evidence.
    MailboxPageNotSettled,
    /// Immutable mailbox/label catalog paging failed closed.
    MailboxCatalogPage(MailboxCatalogPageError),
    /// Authenticated mailbox/label cursor framing or resume failed closed.
    MailboxCatalogCursor(WebCatalogCursorCodecError),
    /// Exact folder/label catalog Network lifecycle failed closed.
    MailboxCatalogNetwork(MailboxCatalogNetworkError),
    /// Folder/label catalog response failed bounded projection.
    MailboxCatalogResponse(MailboxCatalogResponseError),
    /// Required folder/label category responses did not arrive in time.
    MailboxCatalogUnavailable,
    /// Duplicate or residual exact catalog requests made capture ambiguous.
    MailboxCatalogAmbiguous,
    /// Exact conversation-list Network lifecycle failed closed.
    ConversationListNetwork(ConversationListNetworkError),
    /// Conversation-list response failed bounded fresh projection.
    ConversationListResponse(ConversationListResponseError),
    /// Requested passive conversation-list wait exceeds 30 seconds.
    ConversationListWaitTooLong,
    /// Multiple or residual conversation-list requests made capture ambiguous.
    ConversationListAmbiguous,
    /// Exact request page is absent or inconsistent with the visible page.
    ConversationListPageUnproven,
    /// A message-only route cannot use conversation IDs.
    ConversationListMessageMode,
    /// Provider list metadata does not match stable visible row IDs.
    ConversationListReconciliation(ConversationListReconciliationError),
    /// Exact conversation-detail Network lifecycle failed closed.
    ConversationDetailNetwork(ConversationDetailNetworkError),
    /// Conversation detail response failed bounded complete projection.
    ConversationDetailResponse(ConversationDetailResponseError),
    /// Requested passive conversation-detail wait exceeds 30 seconds.
    ConversationDetailWaitTooLong,
    // jig-ignore-next-line: canonical rustfmt line.
    /// Multiple or residual conversation-detail requests made capture ambiguous.
    ConversationDetailAmbiguous,
    /// Exact attachment-metadata Network lifecycle failed closed.
    AttachmentMetadataNetwork(AttachmentMetadataNetworkError),
    /// Attachment metadata response failed bounded parent-bound projection.
    AttachmentMetadataResponse(AttachmentMetadataResponseError),
    /// Requested passive attachment-metadata wait exceeds 30 seconds.
    AttachmentMetadataWaitTooLong,
    // jig-ignore-next-line: canonical rustfmt line.
    /// Multiple or residual attachment-metadata requests made capture ambiguous.
    AttachmentMetadataAmbiguous,
    /// Exact single-message detail Network lifecycle failed closed.
    MessageDetailNetwork(MessageDetailNetworkError),
    /// Single-message detail response failed bounded projection.
    MessageDetailResponse(MessageDetailResponseError),
    /// Requested passive message-detail wait exceeds 30 seconds.
    MessageDetailWaitTooLong,
    // jig-ignore-next-line: canonical rustfmt line.
    /// Multiple or residual exact message-detail requests made capture ambiguous.
    MessageDetailAmbiguous,
    /// Exact message-list Network lifecycle failed closed.
    MessageListNetwork(MessageListNetworkError),
    /// Exact legacy Mail event Network lifecycle failed closed.
    MailboxEventNetwork(MailboxEventNetworkError),
    /// Projected legacy Mail event response body failed validation.
    MailboxEventWatermark(MailboxEventWatermarkError),
    /// Exact legacy Mail event sequence violated resumability rules.
    MailboxEventSequence(MailboxEventSequenceError),
    /// Event cursor is invalid or can no longer resume exactly.
    EventCursorResume(EventCursorResumeFailure),
    /// Authenticated cursor encoding failed for a non-resume reason.
    EventCursorCodec(WebEventCursorCodecError),
    /// Requested passive Mail event wait exceeds the frozen 30-second bound.
    MailboxEventWaitTooLong,
    /// Cooperative cancellation interrupted a passive Mail event wait.
    MailboxEventCancelled,
    /// Bootstrap latest watermark disagreed with the first observed v5 request.
    MailboxEventBootstrapDrift,
    /// No required continuation event response arrived before the deadline.
    MailboxEventResponseUnavailable,
    /// More than one completed or residual event request made capture
    /// ambiguous.
    MailboxEventResponseAmbiguous,
    /// Exact message-list response body failed bounded projection.
    MessageListResponse(MessageListResponseError),
    /// Stable visible rows could not be reconciled to captured machine
    /// metadata.
    MessageListReconciliation(MessageListReconciliationError),
    /// No single completed exact message-list request arrived within the bound.
    MessageListResponseUnavailable,
    /// More than one completed exact message-list request was observed at once.
    MessageListResponseAmbiguous,
    // jig-ignore-next-line: canonical rustfmt line.
    /// Captured list batches do not match the proven `WebClients` batch sequence.
    MessageListBatchIncompatible,
    // jig-ignore-next-line: canonical rustfmt line.
    /// Captured zero-based request page disagrees with stable visible pagination.
    MessageListPageMismatch,
    /// Target metadata and live execution-context origin disagree.
    OriginDrift {
        /// Origin reported by browser target metadata.
        expected: PageOrigin,
        /// Origin observed inside the live page execution context.
        observed: PageOrigin,
    },
    /// `DevTools` pipe read/write failed or timed out.
    PipeIo,
    /// Private file-descriptor pipe setup failed.
    PipeSetup,
    /// Secure entropy was unavailable for the web-adapter generation token.
    GenerationEntropy,
    /// Dedicated profile ownership could not be acquired.
    ProfileLease(ProfileLeaseError),
    /// Managed browser process could not be controlled cleanly.
    ProcessControl,
    /// `DevTools` returned malformed, oversized, or contradictory data.
    Protocol,
}

impl fmt::Display for BrowserDriverError {
    #[expect(
        clippy::too_many_lines,
        reason = "central redacted formatting for the typed driver error enum"
    )]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // jig-ignore-next-line: canonical rustfmt line.
            Self::AmbiguousProviderPages => f.write_str("multiple provider pages are visible"),
            Self::BrowserLaunch => f.write_str("cannot launch managed browser"),
            // jig-ignore-next-line: canonical rustfmt line.
            Self::MissingProviderPage => f.write_str("provider page is missing"),
            // jig-ignore-next-line: canonical rustfmt line.
            Self::MailOriginRequired => f.write_str("Proton Mail origin is required"),
            // jig-ignore-next-line: canonical rustfmt line.
            Self::MailShellNotReady => f.write_str("Proton Mail shell is not ready"),
            Self::MailboxListIncompatible => {
                f.write_str("Proton Mail list evidence is incompatible")
            }
            Self::MailboxModeIncompatible => {
                f.write_str("Proton Mail mode evidence is incompatible")
            }
            Self::MailboxModeChanged => f.write_str("Proton Mail mode changed"),
            Self::MailboxMessageModeRequired => {
                f.write_str("Proton Mail message mode is not proven")
            }
            Self::MailboxNextPageUnavailable => f.write_str("next unavailable"),
            Self::MailboxPaginationChanged => f.write_str("pagination changed"),
            Self::MailboxPaginationIncompatible => {
                f.write_str("Proton Mail pagination is incompatible")
            }
            Self::MailboxPaginationTimeout => f.write_str("pagination timeout"),
            // jig-ignore-next-line: canonical rustfmt line.
            Self::MailboxSortIncompatible => f.write_str("mailbox sort state is incompatible"),
            // jig-ignore-next-line: canonical rustfmt line.
            Self::MailboxSortTimeout => f.write_str("mailbox sort transition timed out"),
            Self::MailboxPageChanged => f.write_str("Proton Mail list changed"),
            Self::MailboxPageIncompatible => {
                f.write_str("Proton Mail visible rows are incompatible")
            }
            // jig-ignore-next-line: canonical rustfmt line.
            Self::MailboxPageNotSettled => f.write_str("Proton Mail list is not settled"),
            // jig-ignore-next-line: canonical rustfmt line.
            Self::MailboxCatalogPage(_error) => f.write_str("mailbox catalog pagination failed"),
            // jig-ignore-next-line: canonical rustfmt line.
            Self::MailboxCatalogCursor(_error) => f.write_str("mailbox catalog cursor failed"),
            Self::MailboxCatalogNetwork(_error) => {
                f.write_str("mailbox catalog Network observation failed")
            }
            Self::MailboxCatalogResponse(_error) => {
                f.write_str("mailbox catalog response projection failed")
            }
            Self::MailboxCatalogUnavailable => {
                f.write_str("mailbox catalog responses were unavailable")
            }
            Self::MailboxCatalogAmbiguous => {
                f.write_str("mailbox catalog observation was ambiguous")
            }
            Self::ConversationListNetwork(_error) => {
                f.write_str("conversation-list Network observation failed")
            }
            Self::ConversationListResponse(_error) => {
                f.write_str("conversation-list response projection failed")
            }
            Self::ConversationListWaitTooLong => {
                f.write_str("conversation-list wait exceeds 30 seconds")
            }
            Self::ConversationListAmbiguous => {
                f.write_str("conversation-list observation was ambiguous")
            }
            Self::ConversationListPageUnproven => {
                f.write_str("conversation-list request page is unproven")
            }
            // jig-ignore-next-line: canonical rustfmt line.
            Self::ConversationListMessageMode => f.write_str("Mail is in message-only mode"),
            Self::ConversationListReconciliation(_error) => {
                f.write_str("visible conversation metadata did not reconcile")
            }
            Self::ConversationDetailNetwork(_error) => {
                f.write_str("conversation-detail Network observation failed")
            }
            Self::ConversationDetailResponse(_error) => {
                f.write_str("conversation-detail response projection failed")
            }
            Self::ConversationDetailWaitTooLong => {
                f.write_str("conversation-detail wait exceeds 30 seconds")
            }
            Self::ConversationDetailAmbiguous => {
                f.write_str("conversation-detail observation was ambiguous")
            }
            Self::AttachmentMetadataNetwork(_error) => {
                f.write_str("attachment-metadata Network observation failed")
            }
            Self::AttachmentMetadataResponse(_error) => {
                f.write_str("attachment-metadata response projection failed")
            }
            Self::AttachmentMetadataWaitTooLong => {
                f.write_str("attachment-metadata wait exceeds 30 seconds")
            }
            Self::AttachmentMetadataAmbiguous => {
                f.write_str("attachment-metadata observation was ambiguous")
            }
            Self::MessageDetailNetwork(_error) => {
                f.write_str("message-detail Network observation failed")
            }
            Self::MessageDetailResponse(_error) => {
                f.write_str("message-detail response projection failed")
            }
            // jig-ignore-next-line: canonical rustfmt line.
            Self::MessageDetailWaitTooLong => f.write_str("message-detail wait exceeds 30 seconds"),
            // jig-ignore-next-line: canonical rustfmt line.
            Self::MessageDetailAmbiguous => f.write_str("message-detail observation was ambiguous"),
            Self::MessageListNetwork(_error) => {
                f.write_str("message-list Network observation failed")
            }
            Self::MailboxEventNetwork(_error) => {
                f.write_str("mailbox-event Network observation failed")
            }
            Self::MailboxEventWatermark(_error) => {
                f.write_str("mailbox-event response projection failed")
            }
            Self::MailboxEventSequence(_error) => {
                f.write_str("mailbox-event sequence is not resumable")
            }
            Self::EventCursorResume(error) => match error {
                EventCursorResumeFailure::InvalidCursor => {
                    f.write_str("mailbox-event cursor is invalid")
                }
                EventCursorResumeFailure::CursorExpired => {
                    f.write_str("mailbox-event cursor expired")
                }
            },
            // jig-ignore-next-line: canonical rustfmt line.
            Self::EventCursorCodec(_error) => f.write_str("mailbox-event cursor encoding failed"),
            // jig-ignore-next-line: canonical rustfmt line.
            Self::MailboxEventWaitTooLong => f.write_str("mailbox-event wait exceeds 30 seconds"),
            // jig-ignore-next-line: canonical rustfmt line.
            Self::MailboxEventCancelled => f.write_str("mailbox-event wait was cancelled"),
            Self::MailboxEventBootstrapDrift => {
                f.write_str("mailbox-event bootstrap cursor drifted")
            }
            Self::MailboxEventResponseUnavailable => {
                f.write_str("mailbox-event continuation was unavailable")
            }
            Self::MailboxEventResponseAmbiguous => {
                f.write_str("mailbox-event observation was ambiguous")
            }
            Self::MessageListResponse(_error) => {
                f.write_str("message-list response projection failed")
            }
            Self::MessageListReconciliation(_error) => {
                f.write_str("message-list metadata reconciliation failed")
            }
            Self::MessageListResponseUnavailable => {
                f.write_str("message-list response was not observed")
            }
            Self::MessageListResponseAmbiguous => {
                // jig-ignore-next-line: canonical rustfmt line.
                f.write_str("multiple message-list responses completed together")
            }
            Self::MessageListBatchIncompatible => {
                f.write_str("message-list batch sequence is incompatible")
            }
            Self::MessageListPageMismatch => {
                // jig-ignore-next-line: canonical rustfmt line.
                f.write_str("message-list request page does not match visible page")
            }
            // jig-ignore-next-line: canonical rustfmt line.
            Self::OriginDrift { .. } => f.write_str("provider page origin changed"),
            Self::PipeIo => f.write_str("`DevTools` pipe I/O failed"),
            Self::PipeSetup => f.write_str("cannot create `DevTools` pipe"),
            // jig-ignore-next-line: canonical rustfmt line.
            Self::GenerationEntropy => f.write_str("cannot create web-adapter generation"),
            // jig-ignore-next-line: canonical rustfmt line.
            Self::ProfileLease(error) => write!(f, "profile unavailable: {error}"),
            Self::ProcessControl => f.write_str("managed browser did not exit"),
            Self::Protocol => f.write_str("invalid DevTools protocol state"),
        }
    }
}

fn fresh_web_adapter_tag() -> Result<String, BrowserDriverError> {
    let mut bytes = [0u8; WEB_ADAPTER_GENERATION_BYTES];
    // jig-ignore-next-line: canonical rustfmt line.
    getrandom::fill(&mut bytes).map_err(|_error| BrowserDriverError::GenerationEntropy)?;
    let capacity = WEB_ADAPTER_GENERATION_BYTES
        .checked_mul(2)
        .ok_or(BrowserDriverError::GenerationEntropy)?;
    let mut encoded = String::with_capacity(capacity);
    for byte in bytes {
        encoded.push(char::from(HEX_DIGITS[usize::from(byte >> 4u8)]));
        encoded.push(char::from(HEX_DIGITS[usize::from(byte & 0x0fu8)]));
    }
    Ok(encoded)
}

// jig-ignore-next-line: canonical rustfmt line.
const fn map_catalog_page_error(error: MailboxCatalogPageError) -> BrowserDriverError {
    match error {
        MailboxCatalogPageError::CursorExpired => {
            // jig-ignore-next-line: canonical rustfmt line.
            BrowserDriverError::MailboxCatalogCursor(WebCatalogCursorCodecError::CursorExpired)
        }
        error @ (MailboxCatalogPageError::InvalidPageSize
        | MailboxCatalogPageError::InvalidCursorState) => {
            BrowserDriverError::MailboxCatalogPage(error)
        }
    }
}

// jig-ignore-next-line: canonical rustfmt line.
fn map_event_cursor_codec_error(error: WebEventCursorCodecError) -> BrowserDriverError {
    error.resume_failure().map_or(
        BrowserDriverError::EventCursorCodec(error),
        BrowserDriverError::EventCursorResume,
    )
}

fn ensure_event_wait_not_cancelled(
    cancellation: Option<&MailboxEventCancellation>,
) -> Result<(), BrowserDriverError> {
    if cancellation.is_some_and(MailboxEventCancellation::is_cancelled) {
        return Err(BrowserDriverError::MailboxEventCancelled);
    }
    Ok(())
}

fn expected_message_list_batch_lengths(
    page: u32,
    limit: usize,
    total: u64,
) -> Result<(usize, usize), BrowserDriverError> {
    let limit_u64 =
        // jig-ignore-next-line: canonical rustfmt line.
        u64::try_from(limit).map_err(|_error| BrowserDriverError::MessageListBatchIncompatible)?;
    let offset = u64::from(page)
        .checked_mul(limit_u64)
        .ok_or(BrowserDriverError::MessageListBatchIncompatible)?;
    if total < offset {
        return Err(BrowserDriverError::MessageListBatchIncompatible);
    }
    let remaining = total
        .checked_sub(offset)
        .ok_or(BrowserDriverError::MessageListBatchIncompatible)?;
    let first = remaining.min(limit_u64);
    let second = remaining.saturating_sub(first).min(limit_u64);
    Ok((
        usize::try_from(first)
            // jig-ignore-next-line: canonical rustfmt line.
            .map_err(|_error| BrowserDriverError::MessageListBatchIncompatible)?,
        usize::try_from(second)
            // jig-ignore-next-line: canonical rustfmt line.
            .map_err(|_error| BrowserDriverError::MessageListBatchIncompatible)?,
    ))
}

fn response_matches_declared_time_order(
    request: &CompletedMessageListRequest,
    response: &ObservedMessageListResponse,
) -> bool {
    if request.sort_key != "Time" {
        return true;
    }
    response
        .messages()
        .windows(2)
        // jig-ignore-next-line: canonical rustfmt line.
        .all(|pair| metadata_pair_matches_time_order(&pair[0], &pair[1], request.descending))
}

fn batch_boundary_matches_time_order(
    request: &CompletedMessageListRequest,
    first: &ObservedMessageListResponse,
    second: &ObservedMessageListResponse,
) -> bool {
    if request.sort_key != "Time" {
        return true;
    }
    match (first.messages().last(), second.messages().first()) {
        (Some(left), Some(right)) => {
            metadata_pair_matches_time_order(left, right, request.descending)
        }
        _ => true,
    }
}

fn metadata_pair_matches_time_order(
    left: &ObservedMessageMetadata,
    right: &ObservedMessageMetadata,
    descending: bool,
) -> bool {
    let primary = left.time().cmp(&right.time());
    let tie = left.order().cmp(&right.order());
    // Equal Time+Order gives no stable order for distinct provider IDs.
    // Refuse that batch until an exact ID tie-break is independently proven.
    if descending {
        primary.is_gt() || (primary.is_eq() && tie.is_gt())
    } else {
        primary.is_lt() || (primary.is_eq() && tie.is_lt())
    }
}

fn ensure_message_list_page_matches(
    snapshot: &VisibleMessagePageSnapshot,
    initial_page: u32,
) -> Result<(), BrowserDriverError> {
    if let Some(visible_page) = snapshot.current_page() {
        let expected = initial_page
            .checked_add(1)
            .ok_or(BrowserDriverError::MessageListPageMismatch)?;
        if visible_page != expected {
            return Err(BrowserDriverError::MessageListPageMismatch);
        }
        return Ok(());
    }
    if initial_page == 0 && snapshot.next_page() == NextPageControl::Absent {
        return Ok(());
    }
    Err(BrowserDriverError::MessageListPageMismatch)
}

// A successfully selected network selector also has private String custody:
// guard it immediately before any fallible observation or parsing step.
fn guard_selected_request<T>(value: T) -> Zeroizing<T>
where
    T: zeroize::Zeroize,
{
    Zeroizing::new(value)
}

// A rejected multi-request batch still contains copied private request IDs.
// Guard the whole temporary vector before matching its cardinality; only a
// single accepted row may leave this scope for the existing typed caller.
fn take_exactly_one_finished<T>(
    finished: Vec<T>,
    ambiguous: BrowserDriverError,
) -> Result<Option<T>, BrowserDriverError>
where
    T: zeroize::Zeroize,
{
    let mut finished = Zeroizing::new(finished);
    match finished.len() {
        0 => Ok(None),
        1 => finished.pop().map(Some).ok_or(BrowserDriverError::Protocol),
        _ => Err(ambiguous),
    }
}

fn take_one_finished_latest_mailbox_event_request(
    capture: &mut LatestMailboxEventNetworkCapture,
) -> Result<Option<String>, BrowserDriverError> {
    take_exactly_one_finished(
        capture.take_finished_request_ids(),
        BrowserDriverError::MailboxEventResponseAmbiguous,
    )
}

fn take_one_finished_mailbox_event_request(
    capture: &mut MailboxEventNetworkCapture,
) -> Result<Option<(String, String)>, BrowserDriverError> {
    take_exactly_one_finished(
        capture.take_finished_requests(),
        BrowserDriverError::MailboxEventResponseAmbiguous,
    )
}

fn conversation_request_page_matches(
    visible: &MailboxListEvidence,
    requested_page: Option<u32>,
) -> bool {
    match (visible.current_page(), requested_page) {
        // jig-ignore-next-line: canonical rustfmt line.
        (Some(current), Some(requested)) => requested.checked_add(1) == Some(current),
        (None, Some(0)) => visible.next_page() == NextPageControl::Absent,
        _ => false,
    }
}

fn take_one_finished_conversation_list_request(
    capture: &mut ConversationListNetworkCapture,
) -> Result<Option<CapturedConversationListRequest>, BrowserDriverError> {
    take_exactly_one_finished(
        capture.take_finished_requests(),
        BrowserDriverError::ConversationListAmbiguous,
    )
}

fn take_one_finished_conversation_detail_request(
    capture: &mut ConversationDetailNetworkCapture,
) -> Result<Option<(String, String)>, BrowserDriverError> {
    take_exactly_one_finished(
        capture.take_finished_requests(),
        BrowserDriverError::ConversationDetailAmbiguous,
    )
}

fn take_one_finished_attachment_metadata_request(
    capture: &mut AttachmentMetadataNetworkCapture,
) -> Result<Option<(String, String)>, BrowserDriverError> {
    take_exactly_one_finished(
        capture.take_finished_requests(),
        BrowserDriverError::AttachmentMetadataAmbiguous,
    )
}

fn take_one_finished_message_detail_request(
    capture: &mut MessageDetailNetworkCapture,
) -> Result<Option<(String, String)>, BrowserDriverError> {
    take_exactly_one_finished(
        capture.take_finished_requests(),
        BrowserDriverError::MessageDetailAmbiguous,
    )
}

fn take_one_finished_request(
    capture: &mut MessageListNetworkCapture,
) -> Result<Option<CompletedMessageListRequest>, BrowserDriverError> {
    let completed = take_exactly_one_finished(
        capture.take_finished_requests(),
        BrowserDriverError::MessageListResponseAmbiguous,
    )?;
    let Some(completed) = completed else {
        return Ok(None);
    };
    // jig-ignore-next-line: canonical rustfmt line.
    let (request_id, continuation, limit, page, sort_key, descending, anchor, anchor_id) =
        completed;
    Ok(Some(CompletedMessageListRequest {
        request_id,
        continuation,
        limit,
        page,
        sort_key,
        descending,
        anchor,
        anchor_id,
    }))
}

const fn pagination_changed() -> BrowserDriverError {
    BrowserDriverError::MailboxPaginationChanged
}

fn executable_text_busy(error: &IoError) -> bool {
    error.raw_os_error().map(Errno::from_raw) == Some(Errno::ETXTBSY)
}

fn spawn_browser(
    plan: &ManagedBrowserPlan,
    child_read: UnixStream,
    child_write: UnixStream,
) -> Result<Child, BrowserDriverError> {
    let user_data = user_data_dir_argument(plan.profile.path());
    let read_fd: OwnedFd = child_read.into();
    let write_fd: OwnedFd = child_write.into();
    let mut command = Command::new(&plan.browser);
    command
        .arg(user_data)
        .arg("--remote-debugging-pipe")
        .args(PRIVATE_PROFILE_FLAGS)
        .arg(MAIL_URL)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
        .fd_mappings(vec![
            FdMapping {
                parent_fd: read_fd,
                child_fd: DEVTOOLS_READ_FD,
            },
            FdMapping {
                parent_fd: write_fd,
                child_fd: DEVTOOLS_WRITE_FD,
            },
        ])
        .map_err(|_error| BrowserDriverError::PipeSetup)?;
    // execve can return ETXTBSY when a just-replaced browser executable
    // is briefly held writable. No child was started in that case; retry
    // only this precise errno with a finite budget while keeping the lease.
    for attempt in 0u8..=MAX_TEXT_BUSY_RETRIES {
        let can_retry = attempt < MAX_TEXT_BUSY_RETRIES;
        match command.spawn() {
            Ok(child) => return Ok(child),
            Err(error) if can_retry && executable_text_busy(&error) => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_error) => return Err(BrowserDriverError::BrowserLaunch),
        }
    }
    Err(BrowserDriverError::BrowserLaunch)
}

// Treat one NUL-delimited frame as one bounded operation. A peer that keeps
// sending partial bytes just before every socket timeout must not extend the
// wall-clock budget indefinitely. Restore the caller's socket timeout even on
// a framing error, so later cleanup uses its original deadline.
type FrameReadResult<T> = Result<T, BrowserDriverError>;

fn with_frame_deadline<T>(
    reader: &mut SensitiveFrameReader,
    read: impl FnOnce(&mut SensitiveFrameReader, Instant) -> FrameReadResult<T>,
) -> FrameReadResult<T> {
    let previous = reader
        .get_ref()
        .read_timeout()
        .map_err(|_error| BrowserDriverError::PipeIo)?;
    let limit = previous.unwrap_or(PIPE_TIMEOUT);
    let deadline = Instant::now()
        .checked_add(limit)
        .ok_or(BrowserDriverError::PipeIo)?;
    let result = read(reader, deadline);
    reader
        .get_ref()
        .set_read_timeout(previous)
        .map_err(|_error| BrowserDriverError::PipeIo)?;
    result
}

fn arm_frame_deadline(
    reader: &SensitiveFrameReader,
    deadline: Instant,
) -> Result<(), BrowserDriverError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(BrowserDriverError::PipeIo);
    }
    reader
        .get_ref()
        .set_read_timeout(Some(remaining))
        .map_err(|_error| BrowserDriverError::PipeIo)
}

// Outbound request data can include scoped target/session IDs. Hold the
// serialized NUL-delimited frame in scrub-on-drop custody through write/flush
// errors as well as successful sends.
fn encode_cdp_request_frame(
    request: &strict_json::SensitiveValue,
) -> Result<Zeroizing<Vec<u8>>, BrowserDriverError> {
    // Serialize through scrub-on-grow storage. Ordinary Vec reallocation
    // would release earlier private command prefixes without erasing them.
    // Bound outbound commands to the same one-MiB JSON ceiling as inbound
    // frames, plus exactly one NUL delimiter. Reject during serialization.
    // jig-ignore-next-line: canonical bounded private CDP writer.
    let mut frame = strict_json::SensitiveJsonWriteBuffer::new_bounded(MAX_FRAME_BYTES + 1);
    // jig-ignore-next-line: canonical scrub-on-grow writer call.
    serde_json::to_writer(&mut frame, &**request).map_err(|_error| BrowserDriverError::Protocol)?;
    frame
        .append(&[0])
        .map_err(|_error| BrowserDriverError::Protocol)?;
    Ok(frame.into_guarded())
}

// Browser CDP notifications can contain cookies and bearer headers even
// when the read-only observer retains only metadata. Keep the fully decoded
// JSON graph scrub-on-drop, including failed validation and irrelevant events.
// jig-ignore-next-line: canonical strict sensitive decoder signature.
fn decode_cdp_frame(frame: &[u8]) -> Result<strict_json::SensitiveValue, BrowserDriverError> {
    let decoded = strict_json::from_sensitive_slice(frame);
    decoded.map_err(|_error| BrowserDriverError::Protocol)
}

fn read_frame_waiting(
    reader: &mut SensitiveFrameReader,
) -> Result<Option<Zeroizing<Vec<u8>>>, BrowserDriverError> {
    with_frame_deadline(reader, |reader, deadline| {
        // Raw CDP bytes can contain private browser and mailbox metadata.
        // Scrub every replaced allocation as frames span cache reads.
        let mut frame = strict_json::SensitiveJsonWriteBuffer::new();
        loop {
            if Instant::now() >= deadline {
                return if frame.is_empty() {
                    Ok(None)
                } else {
                    Err(BrowserDriverError::PipeIo)
                };
            }
            arm_frame_deadline(reader, deadline)?;
            let available = match reader.fill_buf() {
                Ok(available) => available,
                Err(error)
                    if frame.is_empty()
                        // jig-ignore-next-line: canonical rustfmt line.
                        && matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    return Ok(None);
                }
                Err(_error) => return Err(BrowserDriverError::PipeIo),
            };
            if available.is_empty() {
                return Err(BrowserDriverError::PipeIo);
            }
            let terminator = available.iter().position(|byte| *byte == 0);
            let payload = terminator.unwrap_or(available.len());
            let total = frame
                .len()
                .checked_add(payload)
                .ok_or(BrowserDriverError::Protocol)?;
            if total > MAX_FRAME_BYTES {
                return Err(BrowserDriverError::Protocol);
            }
            frame
                .append(&available[..payload])
                .map_err(|_error| BrowserDriverError::PipeIo)?;
            let consumed = if terminator.is_some() {
                payload.checked_add(1).ok_or(BrowserDriverError::Protocol)?
            } else {
                payload
            };
            reader.consume(consumed);
            if terminator.is_some() {
                return Ok(Some(frame.into_guarded()));
            }
        }
    })
}

// jig-ignore-next-line: rustfmt requires the flat private frame signature.
fn read_frame(reader: &mut SensitiveFrameReader) -> FrameReadResult<Zeroizing<Vec<u8>>> {
    with_frame_deadline(reader, |reader, deadline| {
        // Raw CDP bytes can contain private browser and mailbox metadata.
        // Scrub every replaced allocation as frames span cache reads.
        let mut frame = strict_json::SensitiveJsonWriteBuffer::new();
        loop {
            arm_frame_deadline(reader, deadline)?;
            let available = reader
                .fill_buf()
                .map_err(|_error| BrowserDriverError::PipeIo)?;
            if available.is_empty() {
                return Err(BrowserDriverError::PipeIo);
            }
            let terminator = available.iter().position(|byte| *byte == 0);
            let payload = terminator.unwrap_or(available.len());
            let total = frame
                .len()
                .checked_add(payload)
                .ok_or(BrowserDriverError::Protocol)?;
            if total > MAX_FRAME_BYTES {
                return Err(BrowserDriverError::Protocol);
            }
            frame
                .append(&available[..payload])
                .map_err(|_error| BrowserDriverError::PipeIo)?;
            let consumed = if terminator.is_some() {
                payload.checked_add(1).ok_or(BrowserDriverError::Protocol)?
            } else {
                payload
            };
            reader.consume(consumed);
            if terminator.is_some() {
                return Ok(frame.into_guarded());
            }
        }
    })
}

// Browser process commands and flattened target-session commands have
// disjoint authority. No CDP method outside the audited read-only browser
// boundary can be emitted, even if later code inadvertently requests it.
fn allowed_mail_cdp_method(session: Option<&str>, method: &str) -> bool {
    match session {
        None => matches!(
            method,
            "Browser.getVersion"
                | "Browser.close"
                | "Target.getTargets"
                | "Target.attachToTarget"
                | "Target.detachFromTarget"
        ),
        Some(_) => matches!(
            method,
            "Runtime.evaluate"
                | "DOM.getDocument"
                | "Accessibility.queryAXTree"
                | "Network.enable"
                | "Network.disable"
                | "Network.getResponseBody"
                | "Page.reload"
        ),
    }
}

// Validate complete command shape at the final pipe-write boundary, not only
// in the ordinary Runtime.evaluate helper. Future internal callers cannot
// bypass script authorization by calling send_request directly.
// jig-ignore-next-line: canonical rustfmt line.
fn allowed_mail_cdp_request(session: Option<&str>, method: &str, params: &Value) -> bool {
    if !allowed_mail_cdp_method(session, method)
        || session.is_some_and(|id| !safe_cdp_endpoint_id(id))
    {
        return false;
    }
    let Some(fields) = params.as_object() else {
        return false;
    };
    match method {
        "Runtime.evaluate" => {
            fields.len() == 2
                && fields
                    .get("expression")
                    .and_then(Value::as_str)
                    .is_some_and(allowed_mail_runtime_expression)
                // jig-ignore-next-line: canonical rustfmt line.
                && fields.get("returnByValue").and_then(Value::as_bool) == Some(true)
        }
        // jig-ignore-next-line: canonical rustfmt line.
        "Browser.getVersion" | "Browser.close" | "Target.getTargets" | "Network.disable" => {
            fields.is_empty()
        }
        "Target.attachToTarget" => {
            fields.len() == 2
                && fields.get("flatten").and_then(Value::as_bool) == Some(true)
                && fields
                    .get("targetId")
                    .and_then(Value::as_str)
                    .is_some_and(safe_cdp_endpoint_id)
        }
        "Target.detachFromTarget" => {
            fields.len() == 1
                && fields
                    .get("sessionId")
                    .and_then(Value::as_str)
                    .is_some_and(safe_cdp_endpoint_id)
        }
        "DOM.getDocument" => {
            fields.len() == 2
                && fields.get("depth").and_then(Value::as_i64) == Some(0)
                && fields.get("pierce").and_then(Value::as_bool) == Some(false)
        }
        "Accessibility.queryAXTree" => {
            fields.len() == 2
                && fields
                    .get("nodeId")
                    .and_then(Value::as_u64)
                    .is_some_and(|id| id > 0)
                && matches!(
                    fields.get("role").and_then(Value::as_str),
                    Some("navigation" | "search" | "dialog" | "alertdialog")
                )
        }
        "Network.enable" => {
            // jig-ignore-next-line: canonical rustfmt line.
            if fields.len() != 3 || fields.get("maxPostDataSize").and_then(Value::as_u64) != Some(0)
            {
                return false;
            }
            // jig-ignore-next-line: canonical rustfmt line.
            let Some(resource) = fields.get("maxResourceBufferSize").and_then(Value::as_u64) else {
                return false;
            };
            // jig-ignore-next-line: canonical rustfmt line.
            let Some(total) = fields.get("maxTotalBufferSize").and_then(Value::as_u64) else {
                return false;
            };
            resource > 0 && resource <= total && total <= 16_777_216
        }
        "Network.getResponseBody" => {
            fields.len() == 1
                && fields
                    .get("requestId")
                    .and_then(Value::as_str)
                    .is_some_and(safe_cdp_request_id)
        }
        "Page.reload" => {
            fields.is_empty()
                || (fields.len() == 1
                    // jig-ignore-next-line: canonical rustfmt line.
                    && fields.get("ignoreCache").and_then(Value::as_bool) == Some(false))
        }
        _ => false,
    }
}

// Validate method-specific result authority, separate from the CDP envelope.
// Requests that return no data cannot authorize follow-on work through an
// unfamiliar response shape. Attach supplies exactly one session handle.
fn valid_cdp_command_result(method: &str, result: &Value) -> bool {
    let Some(fields) = result.as_object() else {
        return false;
    };
    match method {
        // The discovery and by-value evaluation commands own specific
        // results; an unknown sibling cannot silently change what they prove.
        "Target.getTargets" => {
            let discovered = fields.get("targetInfos");
            fields.len() == 1 && discovered.is_some_and(Value::is_array)
        }
        "Runtime.evaluate" => {
            let field_count_ok = match fields.len() {
                1 => true,
                2 => fields.get("wasThrown") == Some(&Value::Bool(false)),
                _ => false,
            };
            field_count_ok && fields.get("result").is_some_and(Value::is_object)
        }
        "DOM.getDocument" => {
            let root = fields.get("root");
            fields.len() == 1 && root.is_some_and(Value::is_object)
        }
        "Accessibility.queryAXTree" => {
            let nodes = fields.get("nodes");
            fields.len() == 1 && nodes.is_some_and(Value::is_array)
        }
        "Target.attachToTarget" => {
            fields.len() == 1
                && fields
                    .get("sessionId")
                    .and_then(Value::as_str)
                    .is_some_and(safe_cdp_endpoint_id)
        }
        "Browser.close"
        | "Target.detachFromTarget"
        | "Network.enable"
        | "Network.disable"
        | "Page.reload" => fields.is_empty(),
        _ => true,
    }
}

// Browser-issued request IDs are not Mail path components. Require bounded
// printable ASCII to prevent control, spacing and invisible Unicode aliases
// from reaching Network.getResponseBody without narrowing ordinary CDP dots.
#[expect(
    clippy::redundant_pub_crate,
    reason = "sibling observers use CDP transport authority"
)]
pub(crate) fn safe_cdp_request_id(id: &str) -> bool {
    // jig-ignore-next-line: canonical rustfmt line.
    !id.is_empty() && id.len() <= 512 && id.bytes().all(|byte| byte.is_ascii_graphic())
}

// Runtime evaluations are limited to pre-audited, static UI observations and
// the existing checked page/sort controls. No user-controlled expression or
// dynamically assembled script can cross the CDP transport boundary.
fn allowed_mail_runtime_expression(expression: &str) -> bool {
    [
        LOCATION_EXPRESSION,
        MailboxModeEvidence::expression(),
        MailboxListEvidence::expression(),
        MailboxPageSnapshot::expression(),
        MailboxSortOrder::open_expression(),
        MailboxSortOrder::expression(),
        MailboxSortOrder::close_expression(),
        MailboxSortOrder::closed_expression(),
        NextPageActivation::expression(),
    ]
    .contains(&expression)
}

// Unsolicited CDP events use one Domain.method identifier. Empty domains,
// disguised extra dots, oversized names, or non-ASCII method bytes fail closed.
fn safe_cdp_notification_method(method: &str) -> bool {
    if method.len() > 128 {
        return false;
    }
    let Some((domain, event)) = method.split_once('.') else {
        return false;
    };
    !domain.is_empty()
        && !event.is_empty()
        && domain.bytes().all(|byte| byte.is_ascii_alphanumeric())
        && event.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

// Accept only a well-formed unsolicited notification. This shared check
// covers the command reader and every passive observer wait, even when an
// unrelated CDP method would otherwise be ignored by a specific classifier.
// jig-ignore-next-line: canonical rustfmt line.
fn validate_cdp_notification(message: &Value) -> Result<(), BrowserDriverError> {
    // Protocol notifications carry only method, optional params and session.
    // Reject extension fields before any Network observer can use the event.
    let allowed_fields = ["method", "params", "sessionId"];
    let invalid_fields = message.as_object().is_none_or(|notification| {
        notification
            .keys()
            .any(|field| !allowed_fields.contains(&field.as_str()))
    });
    if invalid_fields
        || message.get("id").is_some()
        || message.get("result").is_some()
        || message.get("error").is_some()
        || message
            .get("method")
            .and_then(Value::as_str)
            .is_none_or(|method| !safe_cdp_notification_method(method))
        || message
            .get("params")
            .is_some_and(|params| !params.is_object())
        || match message.get("sessionId") {
            None => false,
            Some(Value::String(session)) => !safe_cdp_endpoint_id(session),
            Some(_) => true,
        }
    {
        return Err(BrowserDriverError::Protocol);
    }
    Ok(())
}

// This catalog is only discovery metadata, not user inbox content.
const MAX_DISCOVERABLE_TARGETS: usize = 128;
const MAX_TARGET_URL_BYTES: usize = 16_384;

// CDP target and session IDs are browser-owned opaque ASCII identifiers.
// Refuse separators, hidden Unicode, empty IDs and oversized metadata before
// reusing an identifier in a subsequent privileged browser command.
fn safe_cdp_endpoint_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 512
        && id
            .bytes()
            // jig-ignore-next-line: canonical rustfmt line.
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

// jig-ignore-next-line: canonical rustfmt line.
fn provider_page_from_target(info: &Value) -> Result<Option<ProviderPage>, BrowserDriverError> {
    let target_type = info
        .get("type")
        .and_then(Value::as_str)
        .filter(|kind| !kind.is_empty() && kind.len() <= 64)
        .ok_or(BrowserDriverError::Protocol)?;
    if target_type != "page" {
        return Ok(None);
    }
    let target_id = info
        .get("targetId")
        .and_then(Value::as_str)
        .filter(|id| safe_cdp_endpoint_id(id))
        .ok_or(BrowserDriverError::Protocol)?;
    let raw_url = info
        .get("url")
        .and_then(Value::as_str)
        .ok_or(BrowserDriverError::Protocol)?;
    if raw_url.len() > MAX_TARGET_URL_BYTES {
        return Err(BrowserDriverError::Protocol);
    }
    let origin = trusted_origin(raw_url);
    if origin == PageOrigin::Other {
        return Ok(None);
    }
    // A page already attached to another debugger is not exclusively ours.
    // Missing `attached` remains compatible with older CDP implementations;
    // an explicitly present value must be false, not malformed or true.
    if info
        .get("attached")
        .is_some_and(|attached| attached.as_bool() != Some(false))
    {
        return Err(BrowserDriverError::Protocol);
    }
    // BrowserContextId is optional even for ordinary persistent profile tabs;
    // its presence alone cannot distinguish a private context. Do not infer
    // profile ownership from this field without getBrowserContexts evidence.
    if info.get("browserContextId").is_some_and(|value| {
        value
            .as_str()
            .is_none_or(|context| !safe_cdp_endpoint_id(context))
    }) {
        return Err(BrowserDriverError::Protocol);
    }
    Ok(Some(ProviderPage {
        origin,
        target_id: String::from(target_id),
    }))
}

fn trusted_origin(raw_url: &str) -> PageOrigin {
    if trusted_url(raw_url, "https://mail.proton.me") {
        return PageOrigin::ProtonMail;
    }
    if trusted_url(raw_url, "https://account.proton.me") {
        return PageOrigin::ProtonAccount;
    }
    PageOrigin::Other
}

fn trusted_url(raw_url: &str, origin: &str) -> bool {
    let Some(rest) = raw_url.strip_prefix(origin) else {
        return false;
    };
    // jig-ignore-next-line: canonical rustfmt line.
    rest.is_empty() || rest.starts_with('/') || rest.starts_with('?') || rest.starts_with('#')
}

#[cfg(test)]
#[path = "../../../../tests/mail/web/adapter-outbound/driver_authority.rs"]
mod cdp_authority_tests;
