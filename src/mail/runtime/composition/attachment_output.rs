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
//   - Descriptor-relative attachment file output under one explicit root.
// - Must-Not:
//   - Follow symlinks, overwrite files, retain attachment bytes, or access
//     mail.
// - Allows:
//   - Write bounded plaintext bytes to a caller-validated relative destination.
// - Split-When:
//   - Streaming or configurable overwrite semantics gain independent policy.
// - Merge-When:
//   - A complete attachment workflow owns the same filesystem lifecycle.
// - Summary:
//   - Commits bounded attachment files without path traversal or symlink
//     escape.
// - Description:
//   - Uses directory file descriptors, no-follow opens, and atomic hard links.
// - Usage:
//   - Open an explicit root, then call `write_no_overwrite` with a safe path.
// - Defaults:
//   - Disabled until a root is explicitly opened; existing outputs are refused.
//

//! Race-resistant attachment file output under an explicit destination root.

use core::fmt::{Debug, Formatter, Result as FmtResult};
use std::ffi::OsString;
use std::fs::File;
use std::io::Write as _;
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

use mail_capability_domain::AttachmentRelativePath;
use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, open, openat};
use nix::sys::stat::Mode;
use nix::unistd::{UnlinkatFlags, dup, linkat, unlinkat};

const MAX_PARTIAL_NAME_ATTEMPTS: usize = 16;
static PARTIAL_NAME_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// An explicit allowlisted attachment output root held as an open directory FD.
pub struct AttachmentFileOutputRoot {
    directory: OwnedFd,
}

impl AttachmentFileOutputRoot {
    /// Opens an absolute output root without following any symlink component.
    ///
    /// # Errors
    ///
    /// Rejects relative roots, parent traversal, symlink components, and any
    /// component that cannot be opened as a directory.
    pub fn open(root: &Path) -> Result<Self, AttachmentFileOutputError> {
        if !root.is_absolute() {
            return Err(AttachmentFileOutputError::RootNotAbsolute);
        }
        // jig-ignore-next-line: canonical rustfmt line.
        let mut directory = open(Path::new("/"), directory_flags(), Mode::empty())
            .map_err(|_error| AttachmentFileOutputError::UnsafeRoot)?;
        for component in root.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(name) => {
                    directory = openat(
                        &directory,
                        Path::new(name),
                        directory_flags(),
                        Mode::empty(),
                    )
                    .map_err(|_error| AttachmentFileOutputError::UnsafeRoot)?;
                }
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(AttachmentFileOutputError::UnsafeRoot);
                }
            }
        }
        Ok(Self { directory })
    }

    /// Writes bounded bytes without overwriting an existing destination.
    ///
    /// The output is first written to a create-new `0600` partial inode inside
    /// the final directory. After the bytes are synchronized, an atomic hard
    /// link creates the final name only if no directory entry already exists.
    ///
    /// # Errors
    ///
    /// Rejects oversized data, unsafe destination directories, any existing
    /// final path, write/commit failure, or failure to remove a partial entry.
    pub fn write_no_overwrite(
        &self,
        destination: &AttachmentRelativePath,
        bytes: &[u8],
        max_bytes: u64,
    ) -> Result<AttachmentFileOutput, AttachmentFileOutputError> {
        let byte_length = u64::try_from(bytes.len())
            .map_err(|_error| AttachmentFileOutputError::OutputTooLarge)?;
        if byte_length > max_bytes {
            return Err(AttachmentFileOutputError::OutputTooLarge);
        }
        let (parent, final_name) = self.open_destination_parent(destination)?;
        let (partial_fd, partial_name) = create_partial(&parent)?;
        let mut partial = File::from(partial_fd);
        if partial.write_all(bytes).is_err() || partial.sync_all().is_err() {
            drop(partial);
            cleanup_partial(&parent, &partial_name)?;
            return Err(AttachmentFileOutputError::WriteFailed);
        }
        drop(partial);
        let final_path = Path::new(&final_name);
        let commit = linkat(
            &parent,
            Path::new(&partial_name),
            &parent,
            final_path,
            AtFlags::empty(),
        );
        if let Err(error) = commit {
            cleanup_partial(&parent, &partial_name)?;
            if error == Errno::EEXIST {
                return Err(AttachmentFileOutputError::DestinationExists);
            }
            return Err(AttachmentFileOutputError::CommitFailed);
        }
        if cleanup_partial(&parent, &partial_name).is_err() {
            return Err(AttachmentFileOutputError::PostCommitCleanupFailed);
        }
        Ok(AttachmentFileOutput {
            relative_path: destination.as_path().to_path_buf(),
            byte_length,
        })
    }

    fn open_destination_parent(
        &self,
        destination: &AttachmentRelativePath,
    ) -> Result<(OwnedFd, OsString), AttachmentFileOutputError> {
        let path = destination.as_path();
        let final_name = path
            .file_name()
            .ok_or(AttachmentFileOutputError::UnsafeDestination)?
            .to_os_string();
        let mut directory =
            // jig-ignore-next-line: canonical rustfmt line.
            dup(&self.directory).map_err(|_error| AttachmentFileOutputError::UnsafeDestination)?;
        if let Some(parent) = path.parent() {
            for component in parent.components() {
                match component {
                    Component::CurDir => {}
                    Component::Normal(name) => {
                        directory = openat(
                            &directory,
                            Path::new(name),
                            directory_flags(),
                            Mode::empty(),
                        )
                        // jig-ignore-next-line: canonical rustfmt line.
                        .map_err(|_error| AttachmentFileOutputError::UnsafeDestination)?;
                    }
                    // jig-ignore-next-line: canonical rustfmt line.
                    Component::RootDir | Component::ParentDir | Component::Prefix(_) => {
                        // jig-ignore-next-line: canonical rustfmt line.
                        return Err(AttachmentFileOutputError::UnsafeDestination);
                    }
                }
            }
        }
        Ok((directory, final_name))
    }
}

impl Debug for AttachmentFileOutputRoot {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("AttachmentFileOutputRoot")
            .field("directory", &"<redacted>")
            .finish()
    }
}

/// A successfully committed attachment file result.
#[derive(Clone, Eq, PartialEq)]
pub struct AttachmentFileOutput {
    relative_path: PathBuf,
    byte_length: u64,
}

impl AttachmentFileOutput {
    /// Returns the caller-validated relative output path.
    #[must_use]
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    /// Returns the exact number of plaintext bytes committed.
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }
}

impl Debug for AttachmentFileOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("AttachmentFileOutput")
            .field("relative_path", &"<redacted>")
            .field("byte_length", &"<redacted>")
            .finish()
    }
}

/// Why attachment file output failed before or during commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentFileOutputError {
    /// The configured destination root was not absolute.
    RootNotAbsolute,
    /// A root component was not a real no-follow directory.
    UnsafeRoot,
    /// A destination directory could not be walked without following symlinks.
    UnsafeDestination,
    /// Plaintext bytes exceed the configured file-output ceiling.
    OutputTooLarge,
    /// A bounded unique partial file could not be created.
    PartialCreateFailed,
    /// Writing or synchronizing the partial file failed.
    WriteFailed,
    /// A final destination entry already exists and overwrite is disabled.
    DestinationExists,
    /// The atomic no-overwrite commit failed for another reason.
    CommitFailed,
    /// A pre-commit partial entry could not be removed.
    CleanupFailed,
    /// The final path committed, but the partial hard link remained.
    PostCommitCleanupFailed,
}

fn directory_flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
}

fn partial_flags() -> OFlag {
    // jig-ignore-next-line: canonical rustfmt line.
    OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
}

// jig-ignore-next-line: canonical rustfmt line.
fn create_partial(parent: &OwnedFd) -> Result<(OwnedFd, String), AttachmentFileOutputError> {
    for _attempt in 0..MAX_PARTIAL_NAME_ATTEMPTS {
        let serial = PARTIAL_NAME_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!(
            ".protonmail-ai-attachment-partial-{}-{serial}",
            process::id()
        );
        match openat(
            parent,
            Path::new(&name),
            partial_flags(),
            Mode::from_bits_truncate(0o600),
        ) {
            Ok(fd) => return Ok((fd, name)),
            Err(Errno::EEXIST) => {}
            // jig-ignore-next-line: canonical rustfmt line.
            Err(_error) => return Err(AttachmentFileOutputError::PartialCreateFailed),
        }
    }
    Err(AttachmentFileOutputError::PartialCreateFailed)
}

// jig-ignore-next-line: canonical rustfmt line.
fn cleanup_partial(parent: &OwnedFd, partial_name: &str) -> Result<(), AttachmentFileOutputError> {
    unlinkat(parent, Path::new(partial_name), UnlinkatFlags::NoRemoveDir)
        .map_err(|_error| AttachmentFileOutputError::CleanupFailed)
}
