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
use std::io::ErrorKind;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{self, Child, Command};
use std::thread;
use std::time::Duration;

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
    let debug = format!("{lease:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains(&root.display().to_string()));
    assert!(!debug.contains(&path.display().to_string()));

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
    let prepared = root.join("chrome-prepared");
    // Avoid writing an executable path that a previous failed fixture may
    // still be executing. Publish a fully written inode by rename instead.
    fs::copy(source, &prepared).expect("prepare synthetic Chrome binary");
    let permissions = fs::Permissions::from_mode(0o700);
    // jig-ignore-next-line: canonical rustfmt line.
    fs::set_permissions(&prepared, permissions).expect("chmod synthetic Chrome");
    fs::rename(prepared, &chrome).expect("publish synthetic Chrome binary");
    // Some Linux filesystems briefly return ETXTBSY after a newly published
    // executable inode. Retry only that transient fixture setup condition.
    let mut attempt = 0u8;
    loop {
        match Command::new(&chrome).arg("30").spawn() {
            Ok(child) => return child,
            // jig-ignore-next-line: canonical rustfmt guard line.
            Err(error) if error.kind() == ErrorKind::ExecutableFileBusy && attempt < 4 => {
                attempt = attempt.saturating_add(1);
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("spawn synthetic chrome: {error}"),
        }
    }
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
fn stale_recovery_refuses_a_competing_project_directory_lock() {
    use nix::fcntl::{Flock, FlockArg};

    let root = test_root("stale-directory-lock");
    let profile = profile(&root);
    let project = project_dir(&profile);
    fs::create_dir_all(project).expect("prepare project directory");
    let lease_path = lease_path(&profile);
    let stale = "v1 4294967295 1\n";
    fs::write(&lease_path, stale).expect("install stale lease");
    let parent = fs::File::open(project).expect("open held project directory");
    let lock = Flock::lock(parent, FlockArg::LockExclusiveNonblock)
        .expect("lock project directory for competing owner");

    let attempt = acquire(&profile);
    let blocked = matches!(attempt, Err(LeaseError::AutomationInUse));
    drop(attempt);
    let preserved = fs::read_to_string(&lease_path).ok();
    drop(lock);
    cleanup(&root);
    assert!(blocked, "recovery cannot race a held directory lease lock");
    assert_eq!(preserved.as_deref(), Some(stale));
}

#[test]
fn lease_directory_lock_is_held_until_owned_lease_is_dropped() {
    use nix::errno::Errno;
    use nix::fcntl::{Flock, FlockArg};

    let root = test_root("lifetime-directory-lock");
    let profile = profile(&root);
    let lease = acquire(&profile).expect("acquire lease");
    let parent = fs::File::open(project_dir(&profile)).expect("open project");
    let blocked = matches!(
        Flock::lock(parent, FlockArg::LockExclusiveNonblock),
        Err((_file, Errno::EWOULDBLOCK))
    );
    let named_lease = lease_path(&profile);
    let held = named_lease.is_file();
    drop(lease);
    let removed_after_drop = !named_lease.exists();
    let project = project_dir(&profile);
    let parent = fs::File::open(project).expect("open after drop");
    let result = Flock::lock(parent, FlockArg::LockExclusiveNonblock);
    let reacquired = result.expect("drop releases directory lock");
    drop(reacquired);
    cleanup(&root);
    assert!(blocked && held, "live owner must hold the directory lock");
    assert!(removed_after_drop, "drop must remove its own lease");
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

#[test]
fn oversized_automation_lease_is_rejected_without_reading_unbounded_payloads() {
    let root = test_root("oversized-existing");
    let profile = profile(&root);
    let path = lease_path(&profile);
    // jig-ignore-next-line: canonical rustfmt line.
    fs::create_dir_all(project_dir(&profile)).expect("create synthetic project");
    // jig-ignore-next-line: canonical rustfmt line.
    fs::write(&path, "Z".repeat(129)).expect("create oversized synthetic lease");
    assert_eq!(
        acquire(&profile).expect_err("oversized lease must not be reclaimed"),
        LeaseError::CorruptLease
    );
    assert_eq!(
        fs::metadata(&path).expect("lease remains intact").len(),
        129
    );
    cleanup(&root);
}

#[test]
fn named_pipe_at_automation_lease_path_fails_without_blocking() {
    use nix::sys::stat::Mode;
    use nix::unistd::mkfifo;

    let root = test_root("unsafe-fifo");
    let profile = profile(&root);
    let path = lease_path(&profile);
    // jig-ignore-next-line: canonical rustfmt line.
    fs::create_dir_all(project_dir(&profile)).expect("create synthetic project");
    // jig-ignore-next-line: canonical rustfmt line.
    mkfifo(&path, Mode::from_bits_truncate(0o600)).expect("create non-regular synthetic lease");
    assert_eq!(
        acquire(&profile).expect_err("FIFO cannot hold a lease"),
        LeaseError::UnsafeLeasePath
    );
    cleanup(&root);
}

#[test]
fn lease_at_exact_read_ceiling_still_rejects_unrecognized_version() {
    let root = test_root("bounded-unknown-lease");
    let profile = profile(&root);
    let path = lease_path(&profile);
    // jig-ignore-next-line: canonical rustfmt line.
    fs::create_dir_all(project_dir(&profile)).expect("create synthetic project");
    fs::write(&path, "X".repeat(128)).expect("create bounded invalid lease");
    assert_eq!(
        acquire(&profile).expect_err("invalid bounded lease has no owner"),
        LeaseError::CorruptLease
    );
    cleanup(&root);
}

#[test]
fn swapped_project_symlink_cannot_redirect_lease_acquisition() {
    let root = test_root("project-swap");
    let profile = profile(&root);
    let project = project_dir(&profile);
    let moved = root.join("moved-project");
    fs::create_dir_all(project).expect("create project");
    // jig-ignore-next-line: canonical rustfmt line.
    fs::write(lease_path(&profile), "v1 4294967295 1\n").expect("create stale lease");
    fs::rename(project, &moved).expect("move project");
    symlink(&moved, project).expect("replace project with symlink");

    assert!(matches!(
        acquire(&profile),
        Err(LeaseError::ProfileSetup(LoginError::ProjectLink(_)))
    ));
    assert_eq!(
        // jig-ignore-next-line: canonical rustfmt line.
        fs::read_to_string(moved.join(".automation-lease")).expect("original lease is untouched"),
        "v1 4294967295 1\n"
    );
    cleanup(&root);
}

#[test]
fn symlinked_caller_selected_data_home_is_allowed() {
    let root = test_root("selected-home-symlink");
    let physical = root.join("physical");
    let selected = root.join("selected");
    fs::create_dir_all(&physical).expect("create physical data home");
    symlink(&physical, &selected).expect("symlink selected data home");
    // jig-ignore-next-line: canonical rustfmt line.
    let profile = Profile::under_data_home(&selected).expect("absolute data home");

    // jig-ignore-next-line: canonical rustfmt line.
    let lease = acquire(&profile).expect("acquire in real project under selected home");
    assert!(lease_path(&profile).is_file());
    drop(lease);
    assert!(!lease_path(&profile).exists());
    cleanup(&root);
}

#[test]
fn drop_cannot_unlink_a_hardlinked_lease_through_a_replaced_project_path() {
    let root = test_root("hardlinked-swapped-parent");
    let profile = profile(&root);
    let lease = acquire(&profile).expect("acquire original lease");
    let original = lease_path(&profile);
    let moved_project = root.join("moved-project");
    let outside = root.join("outside");
    fs::create_dir_all(&outside).expect("create outside directory");
    let outside_lease = outside.join(".automation-lease");
    // jig-ignore-next-line: canonical rustfmt line.
    fs::hard_link(&original, &outside_lease).expect("alias owned inode outside");
    fs::rename(project_dir(&profile), &moved_project).expect("move project");
    // jig-ignore-next-line: canonical rustfmt line.
    symlink(&outside, project_dir(&profile)).expect("redirect project pathname");

    drop(lease);
    assert!(
        outside_lease.is_file(),
        "dropping a lease must not unlink through a replaced parent"
    );
    assert!(moved_project.join(".automation-lease").is_file());
    cleanup(&root);
}

#[test]
fn stale_lease_recovery_keeps_external_hardlinks_intact() {
    let root = test_root("stale-hardlink");
    let profile = profile(&root);
    let path = lease_path(&profile);
    fs::create_dir_all(project_dir(&profile)).expect("create project");
    fs::write(&path, "v1 4294967295 1\n").expect("create stale lease");
    let outside = root.join("outside-lease");
    fs::hard_link(&path, &outside).expect("link stale lease to outside");

    let lease = acquire(&profile).expect("reclaim only the project lease name");
    assert_eq!(
        fs::read_to_string(&outside).expect("outside hardlink is intact"),
        "v1 4294967295 1\n"
    );
    assert_ne!(
        fs::metadata(&outside).expect("external inode").ino(),
        fs::metadata(&path).expect("new lease inode").ino()
    );
    drop(lease);
    assert!(outside.is_file());
    cleanup(&root);
}

#[test]
fn deleted_but_running_chromium_executable_keeps_profile_locked() {
    let root = test_root("chromium-executable-deleted");
    fs::create_dir_all(&root).expect("create synthetic root");
    let profile = profile(&root);
    fs::create_dir_all(profile.path()).expect("create synthetic profile");
    let mut chrome = fake_chrome_process(&root);
    // jig-ignore-next-line: canonical rustfmt line.
    fs::remove_file(root.join("chrome")).expect("simulate a browser binary update");
    let target = format!("{}-{}", local_hostname(), chrome.id());
    symlink(target, singleton_path(&profile)).expect("create Chromium lock");

    let result = acquire(&profile);
    chrome.kill().expect("kill synthetic Chrome");
    chrome.wait().expect("reap synthetic Chrome");
    cleanup(&root);
    assert_eq!(
        result.expect_err("unlinked but live Chrome must hold profile"),
        LeaseError::BrowserInUse
    );
}

#[test]
fn unknown_live_process_at_singleton_pid_cannot_be_assumed_stale() {
    let root = test_root("singleton-live-unknown-process");
    fs::create_dir_all(&root).expect("create synthetic root");
    let profile = profile(&root);
    fs::create_dir_all(profile.path()).expect("create profile");
    let mut process = Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .expect("start synthetic unrelated process");
    let target = format!("{}-{}", local_hostname(), process.id());
    symlink(target, singleton_path(&profile)).expect("create singleton lock");

    let result = acquire(&profile);
    process.kill().expect("terminate synthetic process");
    process.wait().expect("reap synthetic process");
    assert_eq!(
        result.expect_err("a live PID must not authorize a profile takeover"),
        LeaseError::BrowserInUse
    );
    assert!(!lease_path(&profile).exists());
    cleanup(&root);
}

#[test]
fn zero_pid_chromium_singleton_fails_closed() {
    let root = test_root("chromium-zero-pid");
    let profile = profile(&root);
    fs::create_dir_all(profile.path()).expect("create profile");
    let target = format!("{}-0", local_hostname());
    symlink(target, singleton_path(&profile)).expect("create malformed lock");
    assert_eq!(
        acquire(&profile).expect_err("PID zero is not a valid browser owner"),
        LeaseError::BrowserInUse
    );
    assert!(!lease_path(&profile).exists());
    cleanup(&root);
}

#[test]
fn invalid_zero_lease_owner_values_cannot_be_reclaimed() {
    for (label, contents) in [
        ("zero-pid", "v1 0 1\n"),
        ("zero-start", "v1 1 0\n"),
        ("both-zero", "v1 0 0\n"),
    ] {
        let root = test_root(label);
        let profile = profile(&root);
        let path = lease_path(&profile);
        fs::create_dir_all(project_dir(&profile)).expect("create project");
        fs::write(&path, contents).expect("write invalid lease");
        assert_eq!(
            acquire(&profile).expect_err("zero fields must fail closed"),
            LeaseError::CorruptLease
        );
        assert_eq!(
            fs::read_to_string(&path).expect("invalid lease remains"),
            contents
        );
        cleanup(&root);
    }
}

#[test]
fn unix_socket_cannot_masquerade_as_an_automation_lease() {
    use std::os::unix::net::UnixListener;

    let root = test_root("unsafe-socket");
    let profile = profile(&root);
    let path = lease_path(&profile);
    fs::create_dir_all(project_dir(&profile)).expect("create project");
    let socket = UnixListener::bind(&path).expect("bind synthetic socket");
    assert_eq!(
        acquire(&profile).expect_err("socket must not be parsed as a lease"),
        LeaseError::UnsafeLeasePath
    );
    drop(socket);
    cleanup(&root);
}

#[test]
fn noncanonical_singleton_pid_cannot_be_treated_as_stale() {
    for (label, suffix) in [
        ("leading-zero", "00004294967295"),
        ("plus-sign", "+4294967295"),
        ("leading-zero-live", "00"),
    ] {
        let root = test_root(label);
        let profile = profile(&root);
        fs::create_dir_all(profile.path()).expect("create isolated profile");
        let target = format!("{}-{suffix}", local_hostname());
        symlink(target, singleton_path(&profile)).expect("create lock fixture");
        assert_eq!(
            acquire(&profile).expect_err("malformed browser owner must block"),
            LeaseError::BrowserInUse
        );
        assert!(!lease_path(&profile).exists());
        cleanup(&root);
    }
}

#[test]
fn malformed_numeric_lease_owner_cannot_be_reclaimed() {
    for (label, content) in [
        ("pid-leading-zero", "v1 04294967295 1\n"),
        ("pid-plus", "v1 +4294967295 1\n"),
        ("ticks-leading-zero", "v1 4294967295 0001\n"),
        ("ticks-plus", "v1 4294967295 +1\n"),
    ] {
        let root = test_root(label);
        let profile = profile(&root);
        let path = lease_path(&profile);
        fs::create_dir_all(project_dir(&profile)).expect("create project");
        fs::write(&path, content).expect("write synthetic malformed lease");
        assert_eq!(
            acquire(&profile).expect_err("malformed numeric owner fails"),
            LeaseError::CorruptLease
        );
        assert_eq!(fs::read_to_string(&path).expect("preserve entry"), content);
        cleanup(&root);
    }
}

#[test]
fn unreaped_process_pid_keeps_chromium_singleton_busy() {
    use std::thread;
    use std::time::{Duration, Instant};

    let root = test_root("singleton-unreaped-pid");
    let profile = profile(&root);
    fs::create_dir_all(profile.path()).expect("create private profile");
    let mut child = Command::new("/bin/true")
        .spawn()
        .expect("spawn short-lived synthetic process");
    let pid = child.id();
    let status_path = format!("/proc/{pid}/status");
    let mut unreaped = false;
    // A busy workspace scheduler can delay even /bin/true beyond 100ms.
    // Wait for the kernel's zombie evidence with one bounded wall-clock limit.
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        // jig-ignore-next-line: canonical rustfmt line.
        if fs::read_to_string(&status_path).is_ok_and(|status| status.contains("State:\tZ")) {
            unreaped = true;
            break;
        }
        thread::sleep(Duration::from_millis(2));
    }
    if !unreaped {
        child.wait().expect("reap failed synthetic zombie fixture");
        cleanup(&root);
    }
    assert!(unreaped, "synthetic process must exit without being reaped");
    assert!(fs::read_link(format!("/proc/{pid}/exe")).is_err());
    let target = format!("{}-{pid}", local_hostname());
    symlink(target, singleton_path(&profile)).expect("install synthetic lock");

    let result = acquire(&profile);
    child
        .wait()
        .expect("reap synthetic process after lock inspection");
    assert_eq!(
        result.expect_err("existing PID without an exe is not proven dead"),
        LeaseError::BrowserInUse
    );
    assert!(!lease_path(&profile).exists());
    cleanup(&root);
}

#[test]
fn malformed_lease_record_layout_is_not_reclaimed() {
    for (label, record) in [
        ("missing-newline", "v1 4294967295 1"),
        ("leading-space", " v1 4294967295 1\n"),
        ("tabs", "v1\t4294967295\t1\n"),
        ("extra-newline", "v1 4294967295 1\n\n"),
        ("windows-newline", "v1 4294967295 1\r\n"),
        ("double-space", "v1  4294967295 1\n"),
    ] {
        let root = test_root(label);
        let profile = profile(&root);
        let path = lease_path(&profile);
        fs::create_dir_all(project_dir(&profile)).expect("create project");
        fs::write(&path, record).expect("write synthetic owner record");
        assert_eq!(
            acquire(&profile).expect_err("noncanonical record must fail"),
            LeaseError::CorruptLease
        );
        assert_eq!(fs::read_to_string(&path).expect("read record"), record);
        cleanup(&root);
    }
}

#[test]
fn a_distinct_live_process_keeps_a_written_lease_busy() {
    let root = test_root("external-live-owner");
    fs::create_dir_all(&root).expect("create isolated root");
    let profile = profile(&root);
    let path = lease_path(&profile);
    fs::create_dir_all(project_dir(&profile)).expect("create project");
    let mut other = fake_chrome_process(&root);
    let stat = fs::read_to_string(format!("/proc/{}/stat", other.id()))
        .expect("read synthetic owner start ticks");
    let (_, tail) = stat.rsplit_once(") ").expect("split /proc/stat");
    let ticks = tail.split_whitespace().nth(19).expect("start tick field");
    let record = format!("v1 {} {ticks}\n", other.id());
    fs::write(&path, &record).expect("write external owner record");

    let busy = acquire(&profile);
    assert_eq!(
        busy.expect_err("external process owns lease"),
        LeaseError::AutomationInUse
    );
    assert_eq!(fs::read_to_string(&path).expect("preserve owner"), record);
    other.kill().expect("terminate isolated owner");
    other.wait().expect("reap isolated owner");
    let reclaimed = acquire(&profile).expect("reclaim stopped external owner");
    drop(reclaimed);
    cleanup(&root);
}
