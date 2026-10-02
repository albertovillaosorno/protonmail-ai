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

use std::fmt;
use std::io::{BufRead as _, BufReader, ErrorKind, Write as _};
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
use mail_capability_domain::EventCursorResumeFailure;
use mail_capability_domain::{EventCursorScope, ScopedEventCursor};
use serde_json::{Value, json};

use crate::lease::{AutomationProfileLease, ProfileLeaseError};
use crate::list_messages_readiness::ListMessagesReadiness;
use crate::mailbox_event_watermark::LatestMailboxEventNetworkCapture;
use crate::mailbox_event_watermark::MailboxEventNetworkCapture;
use crate::mailbox_event_watermark::MailboxEventNetworkError;
use crate::mailbox_event_watermark::MailboxEventSequenceError;
use crate::mailbox_event_watermark::MailboxEventWatermarkError;
use crate::mailbox_event_watermark::ObservedLatestMailboxEventWatermark;
use crate::mailbox_event_watermark::ObservedMailboxChangePage;
use crate::mailbox_event_watermark::ObservedMailboxEventSequence;
use crate::mailbox_event_watermark::ObservedMailboxEventWatermark;
use crate::mailbox_list::NextPageControl;
use crate::mailbox_list::{MailboxListEvidence, MailboxListState};
use crate::mailbox_mode::{MailboxModeEvidence, MailboxRenderMode};
use crate::mailbox_page::{MailboxPageSnapshot, VisibleMessagePageSnapshot};
use crate::mailbox_pagination::NextPageActivation;
use crate::mailbox_sort::MailboxSortOrder;
use crate::message_list_response::MessageListNetworkCapture;
use crate::message_list_response::MessageListNetworkError;
use crate::message_list_response::MessageListReconciliationError;
use crate::message_list_response::MessageListResponseError;
use crate::message_list_response::ObservedMessageListResponse;
use crate::message_list_response::ObservedMessageMetadata;
use crate::message_list_response::ReconciledVisibleMessageMetadata;
use crate::policy::PageOrigin;
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
const MAX_UNSOLICITED: u16 = 128;
const PIPE_TIMEOUT: Duration = Duration::from_secs(5);
const SHUTDOWN_DELAY: Duration = Duration::from_millis(20);
const SHUTDOWN_POLLS: u16 = 100;
const PAGE_ADVANCE_DELAY: Duration = Duration::from_millis(50);
const SORT_MENU_DELAY: Duration = Duration::from_millis(20);
const SORT_MENU_TIMEOUT: Duration = Duration::from_secs(2);
const PAGE_ADVANCE_TIMEOUT: Duration = Duration::from_secs(10);
const MESSAGE_LIST_CAPTURE_TIMEOUT: Duration = Duration::from_secs(10);
const MESSAGE_LIST_TOTAL_BUFFER_BYTES: usize = 1_048_576;
const MAILBOX_EVENT_MAX_WAIT: Duration = Duration::from_secs(30);
const MAILBOX_EVENT_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(10);
const MAILBOX_EVENT_CANCEL_POLL: Duration = Duration::from_millis(25);
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

struct CapturedMessageListResponses {
    responses: Vec<ObservedMessageListResponse>,
    initial_page: u32,
    initial_limit: usize,
    initial_sort_key: String,
    initial_descending: bool,
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

/// Immutable launch settings for one managed dedicated-profile browser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedBrowserPlan {
    browser: String,
    profile: DedicatedBrowserProfile,
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderPage {
    origin: PageOrigin,
    target_id: String,
}

impl ProviderPage {
    /// Returns the trusted provider origin classification.
    #[must_use]
    pub const fn origin(&self) -> PageOrigin {
        self.origin
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SortMenuActivation {
    AlreadyOpen,
    Opened,
}

impl SortMenuActivation {
    fn from_value(value: &Value) -> Result<Self, BrowserDriverError> {
        let already_open = value.get("alreadyOpen").and_then(Value::as_bool);
        let clicked = value.get("clicked").and_then(Value::as_bool);
        match (already_open, clicked) {
            (Some(true), Some(false)) => Ok(Self::AlreadyOpen),
            (Some(false), Some(true)) => Ok(Self::Opened),
            _ => Err(BrowserDriverError::MailboxSortIncompatible),
        }
    }
}

/// Managed Chromium process connected over private `DevTools` file descriptors.
#[derive(Debug)]
pub struct ManagedBrowser {
    child: Child,
    next_id: u64,
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    _lease: AutomationProfileLease,
}

trait CdpEventObserver {
    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_event(&mut self, event: &Value) -> Result<(), BrowserDriverError>;
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
            next_id: 1,
            reader: BufReader::new(reader),
            writer,
            _lease: lease,
        };
        browser.verify_handshake()?;
        Ok(browser)
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
    fn attach(&mut self, page: &ProviderPage) -> Result<String, BrowserDriverError> {
        let params = json!({"targetId": page.target_id, "flatten": true});
        let result = self.call("Target.attachToTarget", &params)?;
        result
            .get("sessionId")
            .and_then(Value::as_str)
            .map(String::from)
            .ok_or(BrowserDriverError::Protocol)
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn runtime_origin(&mut self, session: &str) -> Result<PageOrigin, BrowserDriverError> {
        let value = self.runtime_value(session, LOCATION_EXPRESSION)?;
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
        Ok(location_origin(protocol, hostname, port))
    }

    fn runtime_value(
        &mut self,
        session: &str,
        expression: &str,
    ) -> Result<Value, BrowserDriverError> {
        let params = json!({
            "expression": expression,
            "returnByValue": true
        });
        // jig-ignore-next-line: canonical rustfmt line.
        let result = self.call_in_session(session, "Runtime.evaluate", &params)?;
        result
            .get("result")
            .and_then(|remote| remote.get("value"))
            .cloned()
            .ok_or(BrowserDriverError::Protocol)
    }

    fn query_ax_role(
        &mut self,
        session: &str,
        node_id: u64,
        role: &str,
    ) -> Result<Value, BrowserDriverError> {
        self.call_in_session(
            session,
            "Accessibility.queryAXTree",
            &json!({"nodeId": node_id, "role": role}),
        )
    }

    fn detach(&mut self, session: &str) -> Result<(), BrowserDriverError> {
        self.call("Target.detachFromTarget", &json!({"sessionId": session}))?;
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
        // jig-ignore-next-line: canonical rustfmt line.
        self.call_in_session_observing(session, "Network.enable", &network_params, &mut capture)?;
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
            ensure_event_wait_not_cancelled(cancellation)?;
            let latest_body = self.call_in_session_observing(
                session,
                "Network.getResponseBody",
                &json!({"requestId": latest_request}),
                &mut capture,
            )?;
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
        // jig-ignore-next-line: canonical rustfmt line.
        self.call_in_session_observing(session, "Network.enable", &network_params, &mut capture)?;
        let deadline = Instant::now()
            .checked_add(MAILBOX_EVENT_BOOTSTRAP_TIMEOUT)
            .ok_or(BrowserDriverError::MailboxEventResponseUnavailable)?;
        let observed = (|| {
            // jig-ignore-next-line: canonical rustfmt line.
            self.call_in_session_observing(session, "Page.reload", &json!({}), &mut capture)?;
            // jig-ignore-next-line: canonical rustfmt line.
            let request_id = self.wait_for_latest_mailbox_event_request(&mut capture, deadline)?;
            let body = self.call_in_session_observing(
                session,
                "Network.getResponseBody",
                &json!({"requestId": request_id}),
                &mut capture,
            )?;
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
        // jig-ignore-next-line: canonical rustfmt line.
        self.call_in_session_observing(session, "Network.enable", &network_params, &mut capture)?;
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
        let body = self.call_in_session_observing(
            session,
            "Network.getResponseBody",
            &json!({"requestId": request.0.as_str()}),
            capture,
        )?;
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
            let message: Value =
                // jig-ignore-next-line: canonical rustfmt line.
                serde_json::from_slice(&frame).map_err(|_error| BrowserDriverError::Protocol)?;
            if message.get("id").is_some() {
                return Err(BrowserDriverError::Protocol);
            }
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
        let body = self.call_in_session_observing(
            session,
            "Network.getResponseBody",
            &json!({"requestId": request.0.as_str()}),
            capture,
        )?;
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
            let message: Value =
                // jig-ignore-next-line: canonical rustfmt line.
                serde_json::from_slice(&frame).map_err(|_error| BrowserDriverError::Protocol)?;
            if message.get("id").is_some() {
                return Err(BrowserDriverError::Protocol);
            }
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
            let message: Value =
                // jig-ignore-next-line: canonical rustfmt line.
                serde_json::from_slice(&frame).map_err(|_error| BrowserDriverError::Protocol)?;
            if message.get("id").is_some() {
                return Err(BrowserDriverError::Protocol);
            }
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
            let message: Value =
                // jig-ignore-next-line: canonical rustfmt line.
                serde_json::from_slice(&frame).map_err(|_error| BrowserDriverError::Protocol)?;
            if message.get("id").is_some() {
                return Err(BrowserDriverError::Protocol);
            }
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
        observed
            .responses
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
        self.call_in_session(session, "Network.enable", &network_params)?;
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
        if first.messages().len() < first_request.limit {
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
        if second.messages().len() != expected_second
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
        let body = self.call_in_session_observing(
            session,
            "Network.getResponseBody",
            &json!({"requestId": request.request_id.as_str()}),
            capture,
        )?;
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
            let message: Value =
                // jig-ignore-next-line: canonical rustfmt line.
                serde_json::from_slice(&frame).map_err(|_error| BrowserDriverError::Protocol)?;
            if message.get("id").is_some() {
                return Err(BrowserDriverError::Protocol);
            }
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
        let after = self.mailbox_list_in_session(session)?;
        self.ensure_page_origin(page, session)?;
        // jig-ignore-next-line: canonical rustfmt line.
        MailboxPageSnapshot::from_observations(&before, rows_value.as_ref(), &after)
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
        if result.get("product").and_then(Value::as_str).is_none() {
            return Err(BrowserDriverError::Protocol);
        }
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn call(&mut self, method: &str, params: &Value) -> Result<Value, BrowserDriverError> {
        self.call_with_session(None, method, params)
    }

    fn call_in_session(
        &mut self,
        session: &str,
        method: &str,
        params: &Value,
    ) -> Result<Value, BrowserDriverError> {
        self.call_with_session(Some(session), method, params)
    }

    fn call_with_session(
        &mut self,
        session: Option<&str>,
        method: &str,
        params: &Value,
    ) -> Result<Value, BrowserDriverError> {
        self.call_with_session_observer(session, method, params, None)
    }

    fn call_in_session_observing(
        &mut self,
        session: &str,
        method: &str,
        params: &Value,
        capture: &mut dyn CdpEventObserver,
    ) -> Result<Value, BrowserDriverError> {
        // jig-ignore-next-line: canonical rustfmt line.
        self.call_with_session_observer(Some(session), method, params, Some(capture))
    }

    fn call_with_session_observer(
        &mut self,
        session: Option<&str>,
        method: &str,
        params: &Value,
        mut capture: Option<&mut dyn CdpEventObserver>,
    ) -> Result<Value, BrowserDriverError> {
        let id = self.allocate_id()?;
        self.send_request(id, session, method, params)?;

        for _event in 0..MAX_UNSOLICITED {
            let frame = read_frame(&mut self.reader)?;
            let message: Value =
                // jig-ignore-next-line: canonical rustfmt line.
                serde_json::from_slice(&frame).map_err(|_error| BrowserDriverError::Protocol)?;
            // jig-ignore-next-line: canonical rustfmt line.
            let Some(response_id) = message.get("id").and_then(Value::as_u64) else {
                if let Some(observer) = capture.as_deref_mut() {
                    observer.observe_event(&message)?;
                }
                continue;
            };
            if response_id != id || message.get("error").is_some() {
                return Err(BrowserDriverError::Protocol);
            }
            return message
                .get("result")
                .cloned()
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
        let request = session.map_or_else(
            || json!({"id": id, "method": method, "params": params}),
            |session_id| {
                json!({
                    "id": id,
                    "method": method,
                    "params": params,
                    "sessionId": session_id
                })
            },
        );
        let mut bytes =
            // jig-ignore-next-line: canonical rustfmt line.
            serde_json::to_vec(&request).map_err(|_error| BrowserDriverError::Protocol)?;
        bytes.push(0);
        self.writer
            .write_all(&bytes)
            .map_err(|_error| BrowserDriverError::PipeIo)?;
        self.writer
            .flush()
            .map_err(|_error| BrowserDriverError::PipeIo)
    }
}

#[expect(
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
    /// Dedicated profile ownership could not be acquired.
    ProfileLease(ProfileLeaseError),
    /// Managed browser process could not be controlled cleanly.
    ProcessControl,
    /// `DevTools` returned malformed, oversized, or contradictory data.
    Protocol,
}

impl fmt::Display for BrowserDriverError {
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
            Self::ProfileLease(error) => write!(f, "profile unavailable: {error}"),
            Self::ProcessControl => f.write_str("managed browser did not exit"),
            Self::Protocol => f.write_str("invalid DevTools protocol state"),
        }
    }
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
    if descending {
        primary.is_gt() || (primary.is_eq() && !tie.is_lt())
    } else {
        primary.is_lt() || (primary.is_eq() && !tie.is_gt())
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

fn take_one_finished_latest_mailbox_event_request(
    capture: &mut LatestMailboxEventNetworkCapture,
) -> Result<Option<String>, BrowserDriverError> {
    let mut finished = capture.take_finished_request_ids();
    match finished.len() {
        0 => Ok(None),
        1 => finished.pop().map(Some).ok_or(BrowserDriverError::Protocol),
        _ => Err(BrowserDriverError::MailboxEventResponseAmbiguous),
    }
}

fn take_one_finished_mailbox_event_request(
    capture: &mut MailboxEventNetworkCapture,
) -> Result<Option<(String, String)>, BrowserDriverError> {
    let mut finished = capture.take_finished_requests();
    match finished.len() {
        0 => Ok(None),
        1 => finished.pop().map(Some).ok_or(BrowserDriverError::Protocol),
        _ => Err(BrowserDriverError::MailboxEventResponseAmbiguous),
    }
}

fn take_one_finished_request(
    capture: &mut MessageListNetworkCapture,
) -> Result<Option<CompletedMessageListRequest>, BrowserDriverError> {
    let mut finished = capture.take_finished_requests();
    match finished.len() {
        0 => Ok(None),
        1 => {
            // jig-ignore-next-line: canonical rustfmt line.
            let (request_id, continuation, limit, page, sort_key, descending, anchor, anchor_id) =
                finished.pop().ok_or(BrowserDriverError::Protocol)?;
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
        _ => Err(BrowserDriverError::MessageListResponseAmbiguous),
    }
}

const fn pagination_changed() -> BrowserDriverError {
    BrowserDriverError::MailboxPaginationChanged
}

fn spawn_browser(
    plan: &ManagedBrowserPlan,
    child_read: UnixStream,
    child_write: UnixStream,
) -> Result<Child, BrowserDriverError> {
    let profile = plan.profile.path().display();
    let user_data = format!("--user-data-dir={profile}");
    let read_fd: OwnedFd = child_read.into();
    let write_fd: OwnedFd = child_write.into();
    let mut command = Command::new(&plan.browser);
    command
        .arg(user_data)
        .arg("--remote-debugging-pipe")
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
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
    command
        .spawn()
        .map_err(|_error| BrowserDriverError::BrowserLaunch)
}

fn read_frame_waiting(
    reader: &mut BufReader<UnixStream>,
) -> Result<Option<Vec<u8>>, BrowserDriverError> {
    let mut frame = Vec::new();
    loop {
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
        frame.extend_from_slice(&available[..payload]);
        let consumed = if terminator.is_some() {
            payload.checked_add(1).ok_or(BrowserDriverError::Protocol)?
        } else {
            payload
        };
        reader.consume(consumed);
        if terminator.is_some() {
            return Ok(Some(frame));
        }
    }
}

// jig-ignore-next-line: canonical rustfmt line.
fn read_frame(reader: &mut BufReader<UnixStream>) -> Result<Vec<u8>, BrowserDriverError> {
    let mut frame = Vec::new();
    loop {
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
        frame.extend_from_slice(&available[..payload]);
        let consumed = if terminator.is_some() {
            payload.checked_add(1).ok_or(BrowserDriverError::Protocol)?
        } else {
            payload
        };
        reader.consume(consumed);
        if terminator.is_some() {
            return Ok(frame);
        }
    }
}

// jig-ignore-next-line: canonical rustfmt line.
fn provider_page_from_target(info: &Value) -> Result<Option<ProviderPage>, BrowserDriverError> {
    if info.get("type").and_then(Value::as_str) != Some("page") {
        return Ok(None);
    }
    if info.get("targetId").and_then(Value::as_str).is_none() {
        return Err(BrowserDriverError::Protocol);
    }
    let raw_url = info
        .get("url")
        .and_then(Value::as_str)
        .ok_or(BrowserDriverError::Protocol)?;
    let origin = trusted_origin(raw_url);
    if origin == PageOrigin::Other {
        return Ok(None);
    }
    Ok(Some(ProviderPage {
        origin,
        target_id: String::from(
            info.get("targetId")
                .and_then(Value::as_str)
                .ok_or(BrowserDriverError::Protocol)?,
        ),
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

fn location_origin(protocol: &str, hostname: &str, port: &str) -> PageOrigin {
    if !port.is_empty() && port != "443" {
        return PageOrigin::Other;
    }
    PageOrigin::from_location(protocol, hostname)
}
