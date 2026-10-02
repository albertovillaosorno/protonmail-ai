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
//   - Synthetic filesystem evidence for bounded attachment file output.
// - Must-Not:
//   - Use live mailbox data, real attachments, or provider/browser access.
// - Allows:
//   - Exercise traversal, symlink, overwrite, byte, and cleanup invariants.
// - Split-When:
//   - Streaming output or platform-specific suites need separate ownership.
// - Merge-When:
//   - A full attachment workflow test owns the same filesystem guarantees.
// - Summary:
//   - Proves attachment files stay inside an explicit no-symlink root.
// - Description:
//   - Uses synthetic bytes and process-unique temporary directories only.
// - Usage:
//   - Run through the `mail_runtime` integration-test target.
// - Defaults:
//   - Local synthetic files only; no provider, browser, or account access.
//

//! Synthetic attachment file-output boundary tests.

use std::env;
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

use mail_capability_domain::AttachmentRelativePath;
use mail_runtime::{AttachmentFileOutputError, AttachmentFileOutputRoot};

static ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn test_root(label: &str) -> PathBuf {
    let serial = ROOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    env::temp_dir().join(format!(
        "protonmail-ai-attachment-output-{label}-{}-{serial}",
        process::id()
    ))
}

fn prepare_root(label: &str) -> PathBuf {
    let root = test_root(label);
    fs::create_dir_all(&root).expect("create synthetic output root");
    root
}

fn relative(value: &str) -> AttachmentRelativePath {
    AttachmentRelativePath::new(value).expect("valid synthetic relative path")
}

fn cleanup(root: &Path) {
    fs::remove_dir_all(root).expect("remove synthetic output root");
}

fn assert_no_partial_entries(root: &Path) {
    let entries = fs::read_dir(root).expect("read synthetic output root");
    for entry in entries {
        let name = entry
            .expect("read synthetic directory entry")
            .file_name()
            .to_string_lossy()
            .into_owned();
        assert!(!name.starts_with(".protonmail-ai-attachment-partial-"));
    }
}

#[test]
fn bounded_nested_output_commits_exact_bytes_with_private_mode() {
    let root = prepare_root("success");
    // jig-ignore-next-line: canonical rustfmt line.
    fs::create_dir_all(root.join("nested")).expect("create nested output directory");
    // jig-ignore-next-line: canonical rustfmt line.
    let output_root = AttachmentFileOutputRoot::open(&root).expect("open safe root");
    let destination = relative("nested/report.bin");
    let bytes = b"synthetic attachment bytes";
    let output = output_root
        .write_no_overwrite(&destination, bytes, 1_024)
        .expect("commit bounded attachment output");

    assert_eq!(output.relative_path(), Path::new("nested/report.bin"));
    assert_eq!(output.byte_length(), 26);
    assert_eq!(
        fs::read(root.join("nested/report.bin")).expect("read output"),
        bytes
    );
    // jig-ignore-next-line: canonical rustfmt line.
    let metadata = fs::metadata(root.join("nested/report.bin")).expect("stat output");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert!(!format!("{output:?}").contains("report.bin"));
    assert_no_partial_entries(&root.join("nested"));
    cleanup(&root);
}

#[test]
fn opened_root_fd_ignores_later_path_replacement_with_symlink() {
    let root = prepare_root("root-race");
    let moved = test_root("root-race-moved");
    let outside = test_root("root-race-outside");
    fs::create_dir_all(&outside).expect("create outside directory");
    // jig-ignore-next-line: canonical rustfmt line.
    let output_root = AttachmentFileOutputRoot::open(&root).expect("open safe root");

    fs::rename(&root, &moved).expect("rename already-open output root");
    symlink(&outside, &root).expect("replace old root pathname with symlink");
    let destination = relative("after-rename.bin");
    output_root
        .write_no_overwrite(&destination, b"safe-fd-target", 100)
        .expect("write through held root descriptor");

    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        fs::read(moved.join("after-rename.bin")).expect("read descriptor target"),
        b"safe-fd-target"
    );
    assert!(!outside.join("after-rename.bin").exists());
    fs::remove_file(&root).expect("remove replacement root symlink");
    cleanup(&moved);
    cleanup(&outside);
}

#[test]
fn missing_destination_parent_fails_without_creating_partial() {
    let root = prepare_root("missing-parent");
    // jig-ignore-next-line: canonical rustfmt line.
    let output_root = AttachmentFileOutputRoot::open(&root).expect("open safe root");
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        output_root.write_no_overwrite(&relative("missing/file.bin"), b"blocked", 100),
        Err(AttachmentFileOutputError::UnsafeDestination)
    );
    assert_no_partial_entries(&root);
    cleanup(&root);
}

#[test]
fn root_and_destination_symlinks_fail_without_touching_targets() {
    let root = prepare_root("symlinks");
    let outside = test_root("outside");
    fs::create_dir_all(&outside).expect("create outside directory");
    let alias = test_root("alias");
    symlink(&root, &alias).expect("create root symlink");
    assert_eq!(
        AttachmentFileOutputRoot::open(&alias).expect_err("root symlink fails"),
        AttachmentFileOutputError::UnsafeRoot
    );
    fs::remove_file(&alias).expect("remove synthetic root symlink");

    // jig-ignore-next-line: canonical rustfmt line.
    symlink(&outside, root.join("escape")).expect("create nested directory symlink");
    // jig-ignore-next-line: canonical rustfmt line.
    let output_root = AttachmentFileOutputRoot::open(&root).expect("open safe real root");
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        output_root.write_no_overwrite(&relative("escape/file.bin"), b"blocked", 100),
        Err(AttachmentFileOutputError::UnsafeDestination)
    );
    assert!(!outside.join("file.bin").exists());
    cleanup(&root);
    cleanup(&outside);
}

#[test]
fn existing_file_or_symlink_is_never_overwritten_and_partial_is_cleaned() {
    let root = prepare_root("existing");
    let outside = test_root("outside-file");
    fs::write(&outside, b"outside-original").expect("create outside file");
    // jig-ignore-next-line: canonical rustfmt line.
    fs::write(root.join("existing.bin"), b"existing-original").expect("create output");
    symlink(&outside, root.join("linked.bin")).expect("create final symlink");
    // jig-ignore-next-line: canonical rustfmt line.
    let output_root = AttachmentFileOutputRoot::open(&root).expect("open safe root");

    for destination in ["existing.bin", "linked.bin"] {
        assert_eq!(
            // jig-ignore-next-line: canonical rustfmt line.
            output_root.write_no_overwrite(&relative(destination), b"replacement", 100),
            Err(AttachmentFileOutputError::DestinationExists)
        );
        assert_no_partial_entries(&root);
    }
    assert_eq!(
        fs::read(root.join("existing.bin")).expect("read existing output"),
        b"existing-original"
    );
    assert_eq!(
        fs::read(&outside).expect("read outside target"),
        b"outside-original"
    );
    cleanup(&root);
    fs::remove_file(&outside).expect("remove outside file");
}

#[test]
fn oversized_output_fails_before_any_file_is_created() {
    let root = prepare_root("oversized");
    // jig-ignore-next-line: canonical rustfmt line.
    let output_root = AttachmentFileOutputRoot::open(&root).expect("open safe root");
    assert_eq!(
        output_root.write_no_overwrite(&relative("too-large.bin"), b"12345", 4),
        Err(AttachmentFileOutputError::OutputTooLarge)
    );
    assert!(!root.join("too-large.bin").exists());
    assert_no_partial_entries(&root);
    cleanup(&root);
}

#[test]
fn relative_or_regular_file_root_is_rejected() {
    assert_eq!(
        AttachmentFileOutputRoot::open(Path::new("relative-root"))
            .expect_err("relative root fails"),
        AttachmentFileOutputError::RootNotAbsolute
    );
    let file = test_root("regular-file-root");
    // jig-ignore-next-line: canonical rustfmt line.
    fs::write(&file, b"not a directory").expect("create synthetic regular file");
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        AttachmentFileOutputRoot::open(&file).expect_err("regular file root fails"),
        AttachmentFileOutputError::UnsafeRoot
    );
    fs::remove_file(file).expect("remove synthetic regular file");
}

#[test]
fn output_root_diagnostics_redact_filesystem_identity() {
    let root = prepare_root("redaction");
    // jig-ignore-next-line: canonical rustfmt line.
    let output_root = AttachmentFileOutputRoot::open(&root).expect("open safe root");
    let debug = format!("{output_root:?}");
    assert_eq!(
        debug,
        "AttachmentFileOutputRoot { directory: \"<redacted>\" }"
    );
    assert!(!debug.contains(root.to_string_lossy().as_ref()));
    cleanup(&root);
}
