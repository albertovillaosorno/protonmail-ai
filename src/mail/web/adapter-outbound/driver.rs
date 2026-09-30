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
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use command_fds::{CommandFdExt as _, FdMapping};
use serde_json::{Value, json};

use crate::lease::{AutomationProfileLease, ProfileLeaseError};
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

/// Managed Chromium process connected over private `DevTools` file descriptors.
#[derive(Debug)]
pub struct ManagedBrowser {
    child: Child,
    next_id: u64,
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    _lease: AutomationProfileLease,
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
        let params = json!({
            "expression": LOCATION_EXPRESSION,
            "returnByValue": true
        });
        // jig-ignore-next-line: canonical rustfmt line.
        let result = self.call_in_session(session, "Runtime.evaluate", &params)?;
        let value = result
            .get("result")
            .and_then(|remote| remote.get("value"))
            .ok_or(BrowserDriverError::Protocol)?;
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
        let id = self.allocate_id()?;
        self.send_request(id, session, method, params)?;

        for _event in 0..MAX_UNSOLICITED {
            let frame = read_frame(&mut self.reader)?;
            let message: Value =
                // jig-ignore-next-line: canonical rustfmt line.
                serde_json::from_slice(&frame).map_err(|_error| BrowserDriverError::Protocol)?;
            // jig-ignore-next-line: canonical rustfmt line.
            let Some(response_id) = message.get("id").and_then(Value::as_u64) else {
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
