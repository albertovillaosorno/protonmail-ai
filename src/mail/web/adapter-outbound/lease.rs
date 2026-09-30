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
//   - Exclusive local ownership of the dedicated profile during automation.
// - Must-Not:
//   - Read browser cookies, storage, credentials, or delete Chromium locks.
// - Allows:
//   - Detect Chromium profile use and serialize protonmail-ai automation.
// - Split-When:
//   - Cross-platform profile locking requires independent implementations.
// - Merge-When:
//   - Browser process lifecycle owns the same exclusive-profile guarantee.
// - Summary:
//   - Fails closed when the dedicated browser profile is already in use.
// - Description:
//   - Combines Chromium singleton detection with a recoverable local lease.
// - Usage:
//   - Acquire immediately before launching a managed persistent browser.
// - Defaults:
//   - No browser session material is opened or inspected.
//

//! Exclusive automation lease for the dedicated Proton Mail browser profile.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Error as IoError, ErrorKind, Write as _};
use std::os::unix::fs::FileTypeExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process;

use crate::profile::{DedicatedBrowserProfile as Profile, WebLoginError};

const AUTOMATION_LEASE: &str = ".automation-lease";
const CHROMIUM_SINGLETON_LOCK: &str = "SingletonLock";
const LEASE_VERSION: &str = "v1";
type LeaseResult<T> = Result<T, ProfileLeaseError>;
type LoginResult<T> = Result<T, WebLoginError>;

fn lease_io<T>(_error: T) -> ProfileLeaseError {
    ProfileLeaseError::LeaseIo
}

/// Exclusive ownership of one project browser profile for managed automation.
#[derive(Debug)]
pub struct AutomationProfileLease {
    _file: File,
    device: u64,
    inode: u64,
    path: PathBuf,
}

impl AutomationProfileLease {
    pub(crate) fn is_active(profile: &Profile) -> LoginResult<bool> {
        // jig-ignore-next-line: canonical rustfmt line.
        let path = automation_lease_path(profile).map_err(|_error| WebLoginError::LeaseInspect)?;
        match inspect_existing_lease(&path) {
            Ok(ExistingLease::Absent | ExistingLease::Stale(_)) => Ok(false),
            Ok(ExistingLease::Active) => Ok(true),
            Err(_error) => Err(WebLoginError::LeaseInspect),
        }
    }

    /// Acquires exclusive automation ownership for the dedicated profile.
    ///
    /// # Errors
    ///
    /// Fails when Chromium still owns the profile, another protonmail-ai
    /// process owns the automation lease, or lease state cannot be verified.
    pub fn acquire(profile: &Profile) -> LeaseResult<Self> {
        profile.prepare().map_err(ProfileLeaseError::ProfileSetup)?;
        if chromium_profile_busy(profile.path())? {
            return Err(ProfileLeaseError::BrowserInUse);
        }
        let lease_path = automation_lease_path(profile)?;
        let lease = acquire_local_lease(&lease_path)?;
        if chromium_profile_busy(profile.path())? {
            drop(lease);
            return Err(ProfileLeaseError::BrowserInUse);
        }
        Ok(lease)
    }
}

fn is_regular_file(file_type: fs::FileType) -> bool {
    !file_type.is_dir()
        && !file_type.is_symlink()
        && !file_type.is_block_device()
        && !file_type.is_char_device()
        && !file_type.is_fifo()
        && !file_type.is_socket()
}

#[expect(
    clippy::missing_trait_methods,
    reason = "Drop::pin_drop is unstable and conflicts with Drop::drop"
)]
impl Drop for AutomationProfileLease {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        let file_type = metadata.file_type();
        let same_file = is_regular_file(file_type)
            && metadata.dev() == self.device
            && metadata.ino() == self.inode;
        if same_file {
            let _ignored = fs::remove_file(&self.path);
        }
    }
}

/// Fail-closed profile ownership error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileLeaseError {
    /// Chromium has a process singleton for this user-data directory.
    BrowserInUse,
    /// Another live protonmail-ai process owns managed automation.
    AutomationInUse,
    /// Dedicated profile setup failed.
    ProfileSetup(WebLoginError),
    /// The local lease file is malformed and cannot be trusted.
    CorruptLease,
    /// The local lease path is a symlink or non-regular file.
    UnsafeLeasePath,
    /// Local lease state could not be read, created, or removed safely.
    LeaseIo,
}

impl fmt::Display for ProfileLeaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BrowserInUse => f.write_str("browser profile busy"),
            // jig-ignore-next-line: canonical rustfmt line.
            Self::AutomationInUse => f.write_str("managed automation owns profile"),
            Self::ProfileSetup(error) => {
                write!(f, "profile setup failed: {error}")
            }
            Self::CorruptLease => f.write_str("automation lease is malformed"),
            // jig-ignore-next-line: canonical rustfmt line.
            Self::UnsafeLeasePath => f.write_str("unsafe automation lease path"),
            Self::LeaseIo => f.write_str("automation lease I/O failed"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LeaseOwner {
    pid: u32,
    start_ticks: u64,
}

fn automation_lease_path(profile: &Profile) -> LeaseResult<PathBuf> {
    profile
        .path()
        .parent()
        .map(|parent| parent.join(AUTOMATION_LEASE))
        .ok_or(ProfileLeaseError::LeaseIo)
}

fn chromium_profile_busy(path: &Path) -> Result<bool, ProfileLeaseError> {
    let lock = path.join(CHROMIUM_SINGLETON_LOCK);
    let metadata = match fs::symlink_metadata(&lock) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(_error) => return Err(ProfileLeaseError::LeaseIo),
    };
    if !metadata.file_type().is_symlink() {
        return Ok(true);
    }
    let target = fs::read_link(lock).map_err(lease_io)?;
    let Some(target) = target.to_str() else {
        return Ok(true);
    };
    let Some((hostname, pid)) = target.rsplit_once('-') else {
        return Ok(true);
    };
    let Ok(pid) = pid.parse::<u32>() else {
        return Ok(true);
    };
    if hostname != local_hostname()?.as_str() {
        return Ok(true);
    }
    chrome_process_active(pid)
}

fn local_hostname() -> LeaseResult<String> {
    // jig-ignore-next-line: canonical rustfmt line.
    let value = fs::read_to_string("/proc/sys/kernel/hostname").map_err(lease_io)?;
    let hostname = value.trim();
    if hostname.is_empty() {
        return Err(ProfileLeaseError::LeaseIo);
    }
    Ok(String::from(hostname))
}

fn executable_name(path: &Path) -> Option<&str> {
    path.file_name().and_then(|name| name.to_str())
}

fn chrome_process_active(pid: u32) -> LeaseResult<bool> {
    let path = PathBuf::from(format!("/proc/{pid}/exe"));
    let executable = match fs::read_link(path) {
        Ok(executable) => executable,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(_error) => return Err(ProfileLeaseError::LeaseIo),
    };
    let Some(name) = executable_name(&executable) else {
        return Err(ProfileLeaseError::LeaseIo);
    };
    Ok(matches!(
        name,
        "chrome" | "chromium" | "msedge" | "chrome-headless-shell"
    ))
}

fn acquire_local_lease(path: &Path) -> LeaseResult<AutomationProfileLease> {
    match create_lease(path) {
        Ok(lease) => Ok(lease),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            reclaim_or_reject_existing(path)?;
            create_lease(path).map_err(|error| {
                if error.kind() == ErrorKind::AlreadyExists {
                    ProfileLeaseError::AutomationInUse
                } else {
                    ProfileLeaseError::LeaseIo
                }
            })
        }
        Err(_error) => Err(ProfileLeaseError::LeaseIo),
    }
}

fn create_lease(path: &Path) -> Result<AutomationProfileLease, IoError> {
    let owner = current_owner()?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    writeln!(file, "{LEASE_VERSION} {} {}", owner.pid, owner.start_ticks)?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    Ok(AutomationProfileLease {
        _file: file,
        device: metadata.dev(),
        inode: metadata.ino(),
        path: path.to_path_buf(),
    })
}

fn reclaim_or_reject_existing(path: &Path) -> LeaseResult<()> {
    match inspect_existing_lease(path)? {
        ExistingLease::Active => Err(ProfileLeaseError::AutomationInUse),
        ExistingLease::Absent => Ok(()),
        ExistingLease::Stale(identity) => remove_stale(path, identity),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExistingLease {
    Absent,
    Active,
    Stale(FileIdentity),
}

fn inspect_existing_lease(path: &Path) -> LeaseResult<ExistingLease> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Ok(ExistingLease::Absent);
        }
        Err(_error) => return Err(ProfileLeaseError::LeaseIo),
    };
    if !is_regular_file(metadata.file_type()) {
        return Err(ProfileLeaseError::UnsafeLeasePath);
    }
    let content = fs::read_to_string(path).map_err(lease_io)?;
    let owner = parse_owner(&content)?;
    if owner_is_active(owner)? {
        Ok(ExistingLease::Active)
    } else {
        Ok(ExistingLease::Stale(FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        }))
    }
}

fn remove_stale(path: &Path, expected: FileIdentity) -> LeaseResult<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(_error) => return Err(ProfileLeaseError::LeaseIo),
    };
    let current = FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    if !is_regular_file(metadata.file_type()) || current != expected {
        return Err(ProfileLeaseError::AutomationInUse);
    }
    fs::remove_file(path).map_err(lease_io)
}

fn parse_owner(content: &str) -> LeaseResult<LeaseOwner> {
    let mut fields = content.split_whitespace();
    if fields.next() != Some(LEASE_VERSION) {
        return Err(ProfileLeaseError::CorruptLease);
    }
    let pid = fields
        .next()
        .ok_or(ProfileLeaseError::CorruptLease)?
        .parse()
        .map_err(|_error| ProfileLeaseError::CorruptLease)?;
    let start_ticks = fields
        .next()
        .ok_or(ProfileLeaseError::CorruptLease)?
        .parse()
        .map_err(|_error| ProfileLeaseError::CorruptLease)?;
    if fields.next().is_some() {
        return Err(ProfileLeaseError::CorruptLease);
    }
    Ok(LeaseOwner { pid, start_ticks })
}

fn current_owner() -> Result<LeaseOwner, IoError> {
    let pid = process::id();
    let start_ticks =
// jig-ignore-next-line: canonical rustfmt line.
        process_start_ticks(pid)?.ok_or_else(|| IoError::from(ErrorKind::NotFound))?;
    Ok(LeaseOwner { pid, start_ticks })
}

fn owner_is_active(owner: LeaseOwner) -> LeaseResult<bool> {
    process_start_ticks(owner.pid)
        .map(|ticks| ticks == Some(owner.start_ticks))
        .map_err(lease_io)
}

fn process_start_ticks(pid: u32) -> Result<Option<u64>, IoError> {
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let (_prefix, tail) = content
        .rsplit_once(") ")
        .ok_or_else(|| IoError::from(ErrorKind::InvalidData))?;
    let mut fields = tail.split_whitespace();
    let start_ticks = fields
        .nth(19)
        // jig-ignore-next-line: canonical rustfmt line.
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "proc stat missing start time"))?;
    let parsed = start_ticks
        .parse()
        // jig-ignore-next-line: canonical rustfmt line.
        .map_err(|_error| IoError::new(ErrorKind::InvalidData, "invalid process start time"))?;
    Ok(Some(parsed))
}
