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
//   - Dedicated local browser-profile path and visible Proton Mail launch.
// - Must-Not:
//   - Read personal browser profiles, automate authentication fields, or export
//     browser session state.
// - Allows:
//   - Create one project-owned browser profile and launch Chromium against it.
// - Split-When:
//   - Post-login page automation requires an independent adapter boundary.
// - Merge-When:
//   - Browser profile custody is owned by a dedicated outbound adapter crate.
// - Summary:
//   - Launches visible Proton Mail login in a project-owned browser profile.
// - Description:
//   - Resolves an XDG-scoped profile, rejects symlinks, and passes it through
//     Chromium's user-data-dir flag.
// - Usage:
//   - Used by the human `auth login` CLI command.
// - Defaults:
//   - No browser session data is read by the process.
//

//! Dedicated user-controlled Proton Mail browser profile launcher.

use std::env;
use std::ffi::OsString;
use std::fmt::{self, Formatter as Fmt};
use std::fs::{self, File};
use std::io::{Error as IoError, ErrorKind};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use nix::errno::Errno;
use nix::fcntl::{OFlag, open, openat};
use nix::sys::stat::{Mode, mkdirat};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::lease::AutomationProfileLease;

// Browser arguments are OS strings: display() would lossy-convert an XDG
// directory with non-UTF-8 bytes, launching a different unleased profile.
#[expect(
    clippy::redundant_pub_crate,
    reason = "shared OS argument helper belongs to sibling browser driver"
)]
pub(crate) fn user_data_dir_argument(profile: &Path) -> OsString {
    let mut argument = OsString::from("--user-data-dir=");
    argument.push(profile.as_os_str());
    argument
}

const MAIL_URL: &str = "https://mail.proton.me/";
const BROWSER_ENV: &str = "PROTONMAIL_AI_BROWSER";
const APP_DIR: &str = "protonmail-ai";
const PROFILE_DIR: &str = "browser-profile";
const BROWSER_CANDIDATES: [&str; 5] = [
    "google-chrome-stable",
    "google-chrome",
    "chromium",
    "chromium-browser",
    "microsoft-edge-stable",
];

/// Fixed project-owned browser profile used by visible login and automation.
#[derive(Clone, Eq, PartialEq)]
pub struct DedicatedBrowserProfile {
    path: PathBuf,
}

impl fmt::Debug for DedicatedBrowserProfile {
    fn fmt(&self, f: &mut Fmt<'_>) -> fmt::Result {
        f.debug_struct("DedicatedBrowserProfile")
            .field("path", &"<redacted>")
            .finish()
    }
}

impl DedicatedBrowserProfile {
    /// Resolves the dedicated profile from XDG/HOME process context.
    ///
    /// # Errors
    ///
    /// Returns an error when no absolute data home can be resolved.
    pub fn from_environment() -> Result<Self, WebLoginError> {
        Ok(Self {
            path: profile_dir_from_environment()?,
        })
    }

    /// Creates a dedicated profile beneath one absolute synthetic data home.
    ///
    /// This constructor still appends the fixed project/profile suffix; callers
    /// cannot supply a browser profile path directly.
    ///
    /// # Errors
    ///
    /// Returns an error when `data_home` is not absolute.
    pub fn under_data_home(data_home: &Path) -> Result<Self, WebLoginError> {
        if !data_home.is_absolute() {
            return Err(WebLoginError::MissingDataHome);
        }
        Ok(Self {
            path: data_home.join(APP_DIR).join(PROFILE_DIR),
        })
    }

    /// Returns the fixed project-owned profile path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn prepare(&self) -> Result<(), WebLoginError> {
        prepare_profile_dir(&self.path)
    }
}

/// Browser launch details that preserve a dedicated profile boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct WebLoginPlan {
    browser: String,
    profile: DedicatedBrowserProfile,
}

impl fmt::Debug for WebLoginPlan {
    fn fmt(&self, f: &mut Fmt<'_>) -> fmt::Result {
        f.debug_struct("WebLoginPlan")
            .field("browser", &"<redacted>")
            .field("profile", &self.profile)
            .finish()
    }
}

impl WebLoginPlan {
    /// Resolves browser and dedicated profile location from process context.
    ///
    /// # Errors
    ///
    /// Returns an error when no safe data home or browser candidate is present.
    pub fn from_environment() -> Result<Self, WebLoginError> {
        let profile = DedicatedBrowserProfile::from_environment()?;
        let browser = browser_from_environment()?;
        Ok(Self { browser, profile })
    }

    /// Returns the project-owned profile path used for this launch.
    #[must_use]
    pub fn profile_dir(&self) -> &Path {
        self.profile.path()
    }

    pub(crate) fn browser(&self) -> &str {
        &self.browser
    }

    pub(crate) const fn profile(&self) -> &DedicatedBrowserProfile {
        &self.profile
    }

    /// Creates the dedicated profile when needed and opens Proton Mail.
    ///
    /// # Errors
    ///
    /// Fails closed when the profile path is a symlink or not a directory, or
    /// when the browser process cannot be started.
    pub fn launch(&self) -> Result<(), WebLoginError> {
        self.profile.prepare()?;
        if AutomationProfileLease::is_active(&self.profile)? {
            return Err(WebLoginError::AutomationInUse);
        }
        let user_data = user_data_dir_argument(self.profile.path());
        Command::new(&self.browser)
            .arg(user_data)
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg(MAIL_URL)
            .spawn()
            .map_err(|error| browser_error(&self.browser, error))?;
        Ok(())
    }
}

/// Fail-closed visible-login setup error.
#[derive(Clone, Eq, PartialEq)]
pub enum WebLoginError {
    /// Neither XDG data home nor a usable home directory is available.
    MissingDataHome,
    /// No supported Chromium-family browser could be selected.
    BrowserUnavailable,
    /// The project profile path resolves to a symbolic link.
    ProfileLink(PathBuf),
    /// The project-owned profile parent resolves to a symbolic link.
    ProjectLink(PathBuf),
    /// The project profile path exists but is not a directory.
    ProfileIsNotDirectory(PathBuf),
    /// The project profile directory could not be created.
    ProfileCreate(PathBuf),
    /// Managed automation already owns the dedicated profile.
    AutomationInUse,
    /// The selected browser process could not be launched.
    BrowserLaunch(String),
    /// Automation lease state could not be inspected safely.
    LeaseInspect,
}

impl fmt::Debug for WebLoginError {
    fn fmt(&self, f: &mut Fmt<'_>) -> fmt::Result {
        match self {
            Self::MissingDataHome => f.write_str("MissingDataHome"),
            Self::BrowserUnavailable => f.write_str("BrowserUnavailable"),
            Self::ProfileLink(_) => f.write_str("ProfileLink(<redacted>)"),
            Self::ProjectLink(_) => f.write_str("ProjectLink(<redacted>)"),
            // jig-ignore-next-line: canonical rustfmt line.
            Self::ProfileIsNotDirectory(_) => f.write_str("ProfileIsNotDirectory(<redacted>)"),
            Self::ProfileCreate(_) => f.write_str("ProfileCreate(<redacted>)"),
            Self::AutomationInUse => f.write_str("AutomationInUse"),
            Self::BrowserLaunch(_) => f.write_str("BrowserLaunch(<redacted>)"),
            Self::LeaseInspect => f.write_str("LeaseInspect"),
        }
    }
}

impl fmt::Display for WebLoginError {
    fn fmt(&self, f: &mut Fmt<'_>) -> fmt::Result {
        match self {
            Self::MissingDataHome => f.write_str("browser data unavailable"),
            Self::BrowserUnavailable => f.write_str("Chromium unavailable"),
            // jig-ignore-next-line: canonical rustfmt line.
            Self::AutomationInUse => f.write_str("profile owned by managed automation"),
            Self::ProfileLink(_) => f.write_str("profile symlink"),
            Self::ProjectLink(_) => f.write_str("project symlink"),
            Self::ProfileIsNotDirectory(_) => {
                f.write_str("browser profile path is not a directory")
            }
            // jig-ignore-next-line: canonical rustfmt line.
            Self::ProfileCreate(_) => f.write_str("cannot create browser profile"),
            Self::BrowserLaunch(_) => f.write_str("cannot launch browser"),
            Self::LeaseInspect => f.write_str("cannot inspect profile lease"),
        }
    }
}

fn profile_dir_from_environment() -> Result<PathBuf, WebLoginError> {
    if let Some(data_home) = absolute_env("XDG_DATA_HOME") {
        return Ok(data_home.join(APP_DIR).join(PROFILE_DIR));
    }
    let home = absolute_env("HOME").ok_or(WebLoginError::MissingDataHome)?;
    Ok(home
        .join(".local")
        .join("share")
        .join(APP_DIR)
        .join(PROFILE_DIR))
}

fn absolute_env(key: &str) -> Option<PathBuf> {
    // Unix filesystem paths need not be UTF-8. Never silently fall back to a
    // different project profile just because XDG_DATA_HOME contains raw bytes.
    let value = env::var_os(key).filter(|value| !value.is_empty())?;
    let path = PathBuf::from(value);
    path.is_absolute().then_some(path)
}

fn browser_from_environment() -> Result<String, WebLoginError> {
    if let Some(browser) = non_empty_env(BROWSER_ENV) {
        return Ok(browser);
    }
    BROWSER_CANDIDATES
        .iter()
        .find(|candidate| executable_on_path(candidate))
        .map(|candidate| String::from(*candidate))
        .ok_or(WebLoginError::BrowserUnavailable)
}

fn non_empty_env(key: &str) -> Option<String> {
    env::var(key).ok().filter(|value| !value.is_empty())
}

fn executable_on_path(candidate: &str) -> bool {
    let Some(path) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path).any(|dir| is_executable(&dir.join(candidate)))
}

fn is_executable(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| {
        let mode = metadata.permissions().mode();
        metadata.is_file() && mode & 0o111 != 0
    })
}

fn prepare_profile_dir(path: &Path) -> Result<(), WebLoginError> {
    let project_path = path.parent().ok_or(WebLoginError::MissingDataHome)?;
    let project = prepare_project_dir(project_path)?;
    let _profile = open_private_child(
        &project,
        PROFILE_DIR,
        path,
        WebLoginError::ProfileLink(path.to_path_buf()),
        WebLoginError::ProfileIsNotDirectory(path.to_path_buf()),
    )?;
    Ok(())
}

fn prepare_project_dir(path: &Path) -> Result<File, WebLoginError> {
    let data_home = path.parent().ok_or(WebLoginError::MissingDataHome)?;
    // This is the caller-selected data home, not a project-owned component.
    fs::create_dir_all(data_home).map_err(|error| io_err(path, error))?;
    let root_flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC;
    let data_fd =
        // jig-ignore-next-line: canonical rustfmt line.
        open(data_home, root_flags, Mode::empty()).map_err(|_error| create_error(path))?;
    let data = File::from(data_fd);
    open_private_child(
        &data,
        APP_DIR,
        path,
        WebLoginError::ProjectLink(path.to_path_buf()),
        create_error(path),
    )
}

fn open_private_child(
    parent: &File,
    name: &str,
    path: &Path,
    link_error: WebLoginError,
    nondirectory_error: WebLoginError,
) -> Result<File, WebLoginError> {
    // Keep typed errors for preexisting unsafe components. The subsequent
    // openat is the authority: this preflight alone is not a race guard.
    match fs::symlink_metadata(path) {
        // jig-ignore-next-line: canonical rustfmt line.
        Ok(metadata) if metadata.file_type().is_symlink() => return Err(link_error),
        Ok(metadata) if !metadata.is_dir() => return Err(nondirectory_error),
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(_error) => return Err(create_error(path)),
    }
    // jig-ignore-next-line: canonical rustfmt line.
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let child = Path::new(name);
    let fd = match openat(parent, child, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::ENOENT) => {
            match mkdirat(parent, child, Mode::from_bits_truncate(0o700)) {
                Ok(()) | Err(Errno::EEXIST) => {}
                Err(_error) => return Err(create_error(path)),
            }
            // jig-ignore-next-line: canonical rustfmt line.
            openat(parent, child, flags, Mode::empty()).map_err(|_error| create_error(path))?
        }
        Err(_error) => return Err(create_error(path)),
    };
    let directory = File::from(fd);
    directory
        .set_permissions(fs::Permissions::from_mode(0o700))
        .map_err(|error| io_err(path, error))?;
    let held = directory.metadata().map_err(|error| io_err(path, error))?;
    // jig-ignore-next-line: canonical rustfmt line.
    let named = fs::symlink_metadata(path).map_err(|error| io_err(path, error))?;
    // jig-ignore-next-line: canonical rustfmt line.
    if !named.is_dir() || held.dev() != named.dev() || held.ino() != named.ino() {
        return Err(create_error(path));
    }
    Ok(directory)
}

fn create_error(path: &Path) -> WebLoginError {
    WebLoginError::ProfileCreate(path.to_path_buf())
}

fn io_err(path: &Path, _error: IoError) -> WebLoginError {
    create_error(path)
}

fn browser_error(browser: &str, _error: IoError) -> WebLoginError {
    WebLoginError::BrowserLaunch(String::from(browser))
}
