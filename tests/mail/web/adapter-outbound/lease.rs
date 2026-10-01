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
//   - Synthetic evidence for exclusive dedicated-profile automation ownership.
// - Must-Not:
//   - Launch a browser, access a live account, or inspect browser session data.
// - Allows:
//   - Exercise Chromium singleton and local lease edge cases on temp paths.
// - Split-When:
//   - Cross-platform profile locking gains distinct acceptance suites.
// - Merge-When:
//   - Browser-driver lifecycle tests own the same exclusive-profile invariants.
// - Summary:
//   - Proves managed automation cannot share the dedicated profile.
// - Description:
//   - Covers active, stale, corrupt, symlink, and replacement lease states.
// - Usage:
//   - Run through the `mail_web_adapter` integration-test target.
// - Defaults:
//   - Synthetic local filesystem state only.
//

//! Dedicated browser-profile automation lease tests.

use std::env;
use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{self, Child, Command};

use mail_web_adapter::AutomationProfileLease as Lease;
use mail_web_adapter::DedicatedBrowserProfile as Profile;
use mail_web_adapter::ProfileLeaseError as LeaseError;
use mail_web_adapter::WebLoginError as LoginError;

fn test_root(label: &str) -> PathBuf {
    let name = format!("protonmail-ai-lease-{label}-{}", process::id());
    env::temp_dir().join(name)
}

fn profile(root: &Path) -> Profile {
    // jig-ignore-next-line: canonical rustfmt line.
    Profile::under_data_home(&root.join("data")).expect("absolute synthetic data home")
}

fn project_dir(profile: &Profile) -> &Path {
    profile.path().parent().expect("profile project parent")
}

fn singleton_path(profile: &Profile) -> PathBuf {
    profile.path().join("SingletonLock")
}

fn lease_path(profile: &Profile) -> PathBuf {
    profile
        .path()
        .parent()
        .expect("profile must have project parent")
        .join(".automation-lease")
}

fn acquire(profile: &Profile) -> Result<Lease, LeaseError> {
    Lease::acquire(profile)
}

fn cleanup(root: &Path) {
    fs::remove_dir_all(root).expect("remove synthetic lease tree");
}

#[test]
fn relative_data_home_is_not_a_profile_constructor() {
    let result = Profile::under_data_home(Path::new("relative"));
    assert_eq!(result, Err(LoginError::MissingDataHome));
}

#[test]
fn lease_is_private_and_removed_on_drop() {
    let root = test_root("drop");
    let profile = profile(&root);
    let lease = acquire(&profile).expect("acquire lease");
    let path = lease_path(&profile);
    let metadata = fs::metadata(&path).expect("lease file must exist");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    drop(lease);
    assert!(!path.exists());
    cleanup(&root);
}

#[test]
fn second_live_automation_owner_is_rejected() {
    let root = test_root("double");
    let profile = profile(&root);
    let first = acquire(&profile).expect("first lease");
    let second = acquire(&profile).expect_err("reject second owner");
    assert_eq!(second, LeaseError::AutomationInUse);

    drop(first);
    let replacement = acquire(&profile).expect("reacquire after drop");
    drop(replacement);
    cleanup(&root);
}

fn local_hostname() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .expect("read synthetic-test host name")
        .trim()
        .to_owned()
}

fn fake_chrome_process(root: &Path) -> Child {
    let source = Path::new("/bin/sleep");
    let chrome = root.join("chrome");
    fs::copy(source, &chrome).expect("copy synthetic chrome executable");
    let permissions = fs::Permissions::from_mode(0o700);
    fs::set_permissions(&chrome, permissions).expect("chmod synthetic chrome");
    Command::new(chrome)
        .arg("30")
        .spawn()
        .expect("spawn synthetic chrome")
}

#[test]
fn live_local_chromium_singleton_blocks_managed_automation() {
    let root = test_root("chromium-live");
    fs::create_dir_all(&root).expect("create synthetic root");
    let profile = profile(&root);
    fs::create_dir_all(profile.path()).expect("create synthetic profile");
    let mut chrome = fake_chrome_process(&root);
    let target = format!("{}-{}", local_hostname(), chrome.id());
    symlink(target, singleton_path(&profile)).expect("create Chromium lock");

    let result = acquire(&profile).expect_err("live Chromium must block");
    assert_eq!(result, LeaseError::BrowserInUse);
    assert!(!lease_path(&profile).exists());
    chrome.kill().expect("kill synthetic chrome");
    chrome.wait().expect("reap synthetic chrome");
    cleanup(&root);
}

#[test]
fn stale_local_chromium_lock_does_not_block_managed_launch() {
    let root = test_root("chromium-stale");
    let profile = profile(&root);
    fs::create_dir_all(profile.path()).expect("create synthetic profile");
    let target = format!("{}-4294967295", local_hostname());
    // jig-ignore-next-line: canonical rustfmt line.
    symlink(target, singleton_path(&profile)).expect("create stale Chrome lock");

    let lease = acquire(&profile).expect("stale local lock may proceed");
    // jig-ignore-next-line: canonical rustfmt line.
    assert!(singleton_path(&profile).exists() || singleton_path(&profile).is_symlink());
    drop(lease);
    cleanup(&root);
}

#[test]
fn remote_or_malformed_chromium_lock_fails_closed() {
    for (label, target) in [
        ("chromium-remote", "definitely-other-host-4294967295"),
        ("chromium-malformed", "not-a-valid-chromium-lock"),
    ] {
        let root = test_root(label);
        let profile = profile(&root);
        fs::create_dir_all(profile.path()).expect("create synthetic profile");
        // jig-ignore-next-line: canonical rustfmt line.
        symlink(target, singleton_path(&profile)).expect("create unsafe Chrome lock");
        let result = acquire(&profile).expect_err("unsafe Chrome lock fails");
        assert_eq!(result, LeaseError::BrowserInUse);
        cleanup(&root);
    }
}

#[test]
fn stale_automation_owner_is_reclaimed() {
    let root = test_root("stale");
    let profile = profile(&root);
    let path = lease_path(&profile);
    fs::create_dir_all(project_dir(&profile)).expect("create project dir");
    fs::write(&path, "v1 4294967295 1\n").expect("write stale lease");

    let lease = acquire(&profile).expect("reclaim stale lease");
    let current = fs::read_to_string(&path).expect("read current lease");
    assert_ne!(current, "v1 4294967295 1\n");
    drop(lease);
    cleanup(&root);
}

#[test]
fn malformed_lease_fails_closed() {
    let root = test_root("malformed");
    let profile = profile(&root);
    let path = lease_path(&profile);
    fs::create_dir_all(project_dir(&profile)).expect("create project dir");
    fs::write(&path, "not-a-valid-lease\n").expect("write malformed lease");

    let result = acquire(&profile).expect_err("malformed lease fails");
    assert_eq!(result, LeaseError::CorruptLease);
    cleanup(&root);
}

#[test]
fn symlinked_lease_path_fails_closed() {
    let root = test_root("symlink");
    let profile = profile(&root);
    let path = lease_path(&profile);
    let outside = root.join("outside-lock");
    fs::create_dir_all(project_dir(&profile)).expect("create project dir");
    fs::write(&outside, "outside").expect("create outside target");
    symlink(&outside, &path).expect("create lease symlink");

    let result = acquire(&profile).expect_err("symlink lease fails");
    assert_eq!(result, LeaseError::UnsafeLeasePath);
    assert_eq!(
        fs::read_to_string(outside).expect("read outside"),
        "outside"
    );
    cleanup(&root);
}

#[test]
fn drop_does_not_delete_replaced_lease_file() {
    let root = test_root("replace");
    let profile = profile(&root);
    let lease = acquire(&profile).expect("acquire lease");
    let path = lease_path(&profile);

    fs::remove_file(&path).expect("unlink owned lease");
    fs::write(&path, "replacement\n").expect("write replacement lease");
    drop(lease);

    assert_eq!(
        fs::read_to_string(&path).expect("replacement must survive"),
        "replacement\n"
    );
    cleanup(&root);
}
