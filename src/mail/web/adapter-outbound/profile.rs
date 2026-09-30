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
use std::fmt::{self, Formatter as Fmt};
use std::fs;
use std::io::{Error as IoError, ErrorKind};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::lease::AutomationProfileLease;

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DedicatedBrowserProfile {
    path: PathBuf,
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebLoginPlan {
    browser: String,
    profile: DedicatedBrowserProfile,
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
        let profile = self.profile.path().display();
        let user_data = format!("--user-data-dir={profile}");
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
#[derive(Clone, Debug, Eq, PartialEq)]
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

impl fmt::Display for WebLoginError {
    fn fmt(&self, f: &mut Fmt<'_>) -> fmt::Result {
        match self {
            Self::MissingDataHome => f.write_str("browser data unavailable"),
            Self::BrowserUnavailable => f.write_str("Chromium unavailable"),
            // jig-ignore-next-line: canonical rustfmt line.
            Self::AutomationInUse => f.write_str("profile owned by managed automation"),
            Self::ProfileLink(path) => path_err(f, "profile symlink", path),
            Self::ProjectLink(path) => path_err(f, "project symlink", path),
            Self::ProfileIsNotDirectory(path) => {
                write!(
                    f,
                    "browser profile path is not a directory: {}",
                    path.display()
                )
            }
            Self::ProfileCreate(path) => {
                write!(f, "cannot create browser profile: {}", path.display())
            }
            Self::BrowserLaunch(browser) => {
                write!(f, "cannot launch browser: {browser}")
            }
            Self::LeaseInspect => f.write_str("cannot inspect profile lease"),
        }
    }
}

fn path_err(formatter: &mut Fmt<'_>, msg: &str, path: &Path) -> fmt::Result {
    write!(formatter, "{msg}: {}", path.display())
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
    let value = non_empty_env(key)?;
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
    let project_dir = path.parent().ok_or(WebLoginError::MissingDataHome)?;
    prepare_project_dir(project_dir)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(WebLoginError::ProfileLink(path.to_path_buf()));
        }
        Ok(metadata) if !metadata.is_dir() => {
            let owned = path.to_path_buf();
            return Err(WebLoginError::ProfileIsNotDirectory(owned));
        }
        Ok(_) => return restrict_permissions(path),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(_error) => return Err(create_error(path)),
    }
    create_private_dir(path)
}

fn prepare_project_dir(path: &Path) -> Result<(), WebLoginError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(WebLoginError::ProjectLink(path.to_path_buf()));
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(WebLoginError::ProfileCreate(path.to_path_buf()));
        }
        Ok(_) => return restrict_permissions(path),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(_error) => return Err(create_error(path)),
    }
    create_private_dir(path)
}

fn create_private_dir(path: &Path) -> Result<(), WebLoginError> {
    fs::create_dir_all(path).map_err(|error| io_err(path, error))?;
    restrict_permissions(path)
}

fn restrict_permissions(path: &Path) -> Result<(), WebLoginError> {
    let permissions = fs::Permissions::from_mode(0o700);
    fs::set_permissions(path, permissions).map_err(|error| io_err(path, error))
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
