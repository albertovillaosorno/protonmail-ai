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
use std::fs::{self, File};
use std::io::{Error as IoError, ErrorKind, Read as _, Write as _};
use std::os::unix::fs::FileTypeExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process;

use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, open, openat};
use nix::sys::stat::{Mode, SFlag, fstatat};
use nix::unistd::{UnlinkatFlags, unlinkat};

use crate::profile::{DedicatedBrowserProfile as Profile, WebLoginError};

const AUTOMATION_LEASE: &str = ".automation-lease";
const CHROMIUM_SINGLETON_LOCK: &str = "SingletonLock";
const LEASE_VERSION: &str = "v1";
const MAX_LEASE_BYTES: u64 = 128;
type LeaseResult<T> = Result<T, ProfileLeaseError>;
type LoginResult<T> = Result<T, WebLoginError>;

fn lease_io<T>(_error: T) -> ProfileLeaseError {
    ProfileLeaseError::LeaseIo
}

/// Exclusive ownership of one project browser profile for managed automation.
pub struct AutomationProfileLease {
    _file: File,
    parent: File,
    device: u64,
    inode: u64,
    path: PathBuf,
}

impl fmt::Debug for AutomationProfileLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AutomationProfileLease")
            .field("path", &"<redacted>")
            .finish_non_exhaustive()
    }
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
    clippy::allow_attributes,
    reason = "Cross-toolchain Drop lint changes require an explicit exemption"
)]
#[allow(
    clippy::missing_trait_methods,
    reason = "Drop::pin_drop is unstable and conflicts with Drop::drop"
)]
impl Drop for AutomationProfileLease {
    fn drop(&mut self) {
        // The project name can change after acquisition. Never use it to
        // unlink: even a hardlink to our inode could then be removed outside
        // the dedicated directory through a substituted project symlink.
        let Some(project) = self.path.parent() else {
            return;
        };
        let (Ok(held_parent), Ok(named_parent)) =
            (self.parent.metadata(), fs::symlink_metadata(project))
        else {
            return;
        };
        if !named_parent.is_dir()
            || named_parent.dev() != held_parent.dev()
            || named_parent.ino() != held_parent.ino()
        {
            return;
        }
        let Ok(named) = fstatat(
            &self.parent,
            Path::new(AUTOMATION_LEASE),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        ) else {
            return;
        };
        // jig-ignore-next-line: canonical rustfmt line.
        let regular = SFlag::from_bits_truncate(named.st_mode) & SFlag::S_IFMT == SFlag::S_IFREG;
        // jig-ignore-next-line: canonical rustfmt line.
        if regular && named.st_dev == self.device && named.st_ino == self.inode {
            let _ignored = unlinkat(
                &self.parent,
                Path::new(AUTOMATION_LEASE),
                UnlinkatFlags::NoRemoveDir,
            );
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

// The fixed lease entry must be relative to a real dedicated project dir,
// never a directory that became an intermediate symlink after preparation.
fn open_lease_parent(path: &Path) -> Result<File, IoError> {
    let project = path.parent().ok_or(ErrorKind::NotFound)?;
    // jig-ignore-next-line: canonical rustfmt line.
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let fd = open(project, flags, Mode::empty()).map_err(IoError::from)?;
    let directory = File::from(fd);
    let held = directory.metadata()?;
    let named = fs::symlink_metadata(project)?;
    // jig-ignore-next-line: canonical rustfmt line.
    if !named.is_dir() || held.dev() != named.dev() || held.ino() != named.ino() {
        return Err(IoError::from(ErrorKind::PermissionDenied));
    }
    Ok(directory)
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
    let parent = open_lease_parent(path)?;
    let flags =
        // jig-ignore-next-line: canonical rustfmt line.
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let fd = openat(
        &parent,
        Path::new(AUTOMATION_LEASE),
        flags,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(IoError::from)?;
    let mut file = File::from(fd);
    writeln!(file, "{LEASE_VERSION} {} {}", owner.pid, owner.start_ticks)?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    let parent_held = parent.metadata()?;
    // jig-ignore-next-line: canonical rustfmt line.
    let parent_named = fs::symlink_metadata(path.parent().ok_or(ErrorKind::NotFound)?)?;
    let named = fs::symlink_metadata(path)?;
    if !parent_named.is_dir()
        || parent_named.dev() != parent_held.dev()
        || parent_named.ino() != parent_held.ino()
        || !is_regular_file(named.file_type())
        || named.dev() != metadata.dev()
        || named.ino() != metadata.ino()
    {
        return Err(IoError::from(ErrorKind::PermissionDenied));
    }
    Ok(AutomationProfileLease {
        _file: file,
        parent,
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
    // The pathname can be swapped between metadata inspection and reading.
    // Open the actual lease inode without following links, or waiting on a
    // substituted FIFO, then verify it is still the name we inspected.
    // jig-ignore-next-line: canonical rustfmt line.
    let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC;
    let parent = open_lease_parent(path).map_err(lease_io)?;
    let fd = openat(&parent, Path::new(AUTOMATION_LEASE), flags, Mode::empty())
        .map_err(|_error| ProfileLeaseError::UnsafeLeasePath)?;
    let file = File::from(fd);
    let held = file.metadata().map_err(lease_io)?;
    if !is_regular_file(held.file_type())
        || held.dev() != metadata.dev()
        || held.ino() != metadata.ino()
    {
        return Err(ProfileLeaseError::UnsafeLeasePath);
    }
    if held.len() > MAX_LEASE_BYTES {
        return Err(ProfileLeaseError::CorruptLease);
    }
    let mut content = String::new();
    file.take(MAX_LEASE_BYTES + 1)
        .read_to_string(&mut content)
        .map_err(lease_io)?;
    if u64::try_from(content.len()).unwrap_or(u64::MAX) > MAX_LEASE_BYTES {
        return Err(ProfileLeaseError::CorruptLease);
    }
    let named = fs::symlink_metadata(path).map_err(lease_io)?;
    // jig-ignore-next-line: canonical rustfmt line.
    if !is_regular_file(named.file_type()) || named.dev() != held.dev() || named.ino() != held.ino()
    {
        return Err(ProfileLeaseError::UnsafeLeasePath);
    }
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
    let parent = open_lease_parent(path).map_err(lease_io)?;
    let metadata = match fstatat(
        &parent,
        Path::new(AUTOMATION_LEASE),
        AtFlags::AT_SYMLINK_NOFOLLOW,
    ) {
        Ok(metadata) => metadata,
        Err(Errno::ENOENT) => return Ok(()),
        Err(_error) => return Err(ProfileLeaseError::LeaseIo),
    };
    // jig-ignore-next-line: canonical rustfmt line.
    let regular = SFlag::from_bits_truncate(metadata.st_mode) & SFlag::S_IFMT == SFlag::S_IFREG;
    // jig-ignore-next-line: canonical rustfmt line.
    if !regular || metadata.st_dev != expected.device || metadata.st_ino != expected.inode {
        return Err(ProfileLeaseError::AutomationInUse);
    }
    unlinkat(
        &parent,
        Path::new(AUTOMATION_LEASE),
        UnlinkatFlags::NoRemoveDir,
    )
    .map_err(lease_io)
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
