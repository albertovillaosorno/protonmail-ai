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
//   - Process-level evidence for dedicated visible web login.
// - Must-Not:
//   - Launch a real browser or use live Proton account data.
// - Allows:
//   - Launch a synthetic browser executable with isolated environment paths.
// - Split-When:
//   - Browser-adapter acceptance requires live opt-in coverage.
// - Merge-When:
//   - A broader runtime acceptance suite owns profile lifecycle behavior.
// - Summary:
//   - Proves auth login uses only a project-owned browser profile.
// - Description:
//   - Verifies launch flags, profile location, permissions, and fail-closed
//     paths.
// - Usage:
//   - Run through the `mail_runtime` integration-test target.
// - Defaults:
//   - Synthetic local files and fake browser only.
//

//! Dedicated browser-profile login regression tests.

use std::env;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Output, Stdio};
use std::thread;
use std::time::Duration;

use mail_web_adapter::AutomationProfileLease as Lease;
use mail_web_adapter::DedicatedBrowserProfile as Profile;

const LOGIN_ARGS_FILE: &str = "PROTONMAIL_AI_TEST_ARGS";

fn test_root(label: &str) -> PathBuf {
    let name = format!("protonmail-ai-web-{label}-{}", process::id());
    env::temp_dir().join(name)
}

fn fake_browser(root: &Path) -> PathBuf {
    let script = root.join("fake-browser");
    let body = concat!(
        "#!/bin/sh\n",
        "printf '%s\\n' \"$@\" > \"$PROTONMAIL_AI_TEST_ARGS\"\n"
    );
    fs::write(&script, body).expect("write fake browser");
    let permissions = fs::Permissions::from_mode(0o700);
    fs::set_permissions(&script, permissions).expect("chmod fake browser");
    script
}

fn login(root: &Path, browser: &Path, xdg: Option<&Path>) -> Output {
    let args_file = root.join("browser-args.txt");
    let mut command = Command::new(env!("CARGO_BIN_EXE_protonmail-ai"));
    command
        .args(["auth", "login"])
        .env("PROTONMAIL_AI_BROWSER", browser)
        .env(LOGIN_ARGS_FILE, &args_file)
        .env("HOME", root.join("home"));
    match xdg {
        Some(path) => {
            command.env("XDG_DATA_HOME", path);
        }
        None => {
            command.env_remove("XDG_DATA_HOME");
        }
    }
    command.output().expect("execute auth login")
}

fn login_without_override(root: &Path, path_env: &Path, xdg: &Path) -> Output {
    let args_file = root.join("browser-args.txt");
    Command::new(env!("CARGO_BIN_EXE_protonmail-ai"))
        .args(["auth", "login"])
        .env_remove("PROTONMAIL_AI_BROWSER")
        .env(LOGIN_ARGS_FILE, &args_file)
        .env("PATH", path_env)
        .env("HOME", root.join("home"))
        .env("XDG_DATA_HOME", xdg)
        .output()
        .expect("execute auth login")
}

fn wait_for_args_bytes(root: &Path) -> Vec<u8> {
    let path = root.join("browser-args.txt");
    for _attempt in 0..100u8 {
        if let Ok(value) = fs::read(&path) {
            // The CLI returns before the visible child finishes writing.
            // Do not mistake an opened but partially flushed file for argv.
            const LAST_ARG: &[u8] = b"https://mail.proton.me/\n";
            if value.ends_with(LAST_ARG) {
                return value;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("fake browser did not record arguments");
}

fn wait_for_args(root: &Path) -> String {
    let bytes = wait_for_args_bytes(root);
    String::from_utf8(bytes).expect("UTF-8 browser arguments")
}

fn profile_under(data_home: &Path) -> PathBuf {
    data_home.join("protonmail-ai").join("browser-profile")
}

fn local_test_hostname() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .expect("read hostname")
        .trim()
        .to_owned()
}

fn cleanup(root: &Path) {
    fs::remove_dir_all(root).expect("remove synthetic web profile tree");
}

#[test]
fn visible_login_refuses_existing_chromium_profile_owner() {
    let root = test_root("visible-existing-chromium");
    fs::create_dir_all(&root).expect("create synthetic root");
    let browser = fake_browser(&root);
    let data_home = root.join("xdg-data");
    let profile = profile_under(&data_home);
    fs::create_dir_all(&profile).expect("create dedicated profile");
    let host = local_test_hostname();
    let owner = format!("{}-{}", host, process::id());
    symlink(owner, profile.join("SingletonLock")).expect("install lock");
    let output = login(&root, &browser, Some(&data_home));
    assert!(
        !output.status.success(),
        "occupied profile cannot be reused"
    );
    assert!(!root.join("browser-args.txt").exists());
    assert!(
        String::from_utf8(output.stderr)
            .expect("redacted browser error")
            .contains("browser profile busy")
    );
    cleanup(&root);
}

#[test]
fn visible_login_refuses_unprovable_chromium_owners() {
    for (label, owner) in [
        ("visible-foreign-browser", "foreign-host-1234"),
        ("visible-malformed-browser", "invalid-singleton-lock"),
    ] {
        let root = test_root(label);
        fs::create_dir_all(&root).expect("create synthetic root");
        let browser = fake_browser(&root);
        let data_home = root.join("xdg-data");
        let profile = profile_under(&data_home);
        fs::create_dir_all(&profile).expect("create dedicated profile");
        symlink(owner, profile.join("SingletonLock")).expect("install lock");
        let output = login(&root, &browser, Some(&data_home));
        assert!(!output.status.success());
        assert!(!root.join("browser-args.txt").exists());
        assert!(
            String::from_utf8(output.stderr)
                .expect("redacted browser error")
                .contains("browser profile busy")
        );
        cleanup(&root);
    }
}

#[test]
fn visible_login_allows_proven_stale_local_chromium_owner() {
    let root = test_root("visible-stale-chromium");
    fs::create_dir_all(&root).expect("create synthetic root");
    let browser = fake_browser(&root);
    let data_home = root.join("xdg-data");
    let profile = profile_under(&data_home);
    fs::create_dir_all(&profile).expect("create dedicated profile");
    let host = local_test_hostname();
    let owner = format!("{host}-4294967295");
    symlink(owner, profile.join("SingletonLock")).expect("install lock");
    let output = login(&root, &browser, Some(&data_home));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    wait_for_args(&root);
    cleanup(&root);
}

#[test]
fn visible_login_rechecks_chromium_owner_during_busy_executable_retry() {
    let root = test_root("chromium-owner-during-retry");
    fs::create_dir_all(&root).expect("create synthetic root");
    let browser = fake_browser(&root);
    let data_home = root.join("xdg-data");
    let writer = fs::OpenOptions::new()
        .write(true)
        .open(&browser)
        .expect("hold executable writable");
    let run_root = root.clone();
    let runner = thread::spawn(move || {
        let xdg = run_root.join("xdg-data");
        login(&run_root, &browser, Some(&xdg))
    });
    let profile = profile_under(&data_home);
    for _attempt in 0..100u8 {
        if profile.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(profile.exists(), "visible login must prepare profile");
    thread::sleep(Duration::from_millis(60));
    let host = local_test_hostname();
    let owner = format!("{}-{}", host, process::id());
    symlink(owner, profile.join("SingletonLock")).expect("install lock");
    let output = runner.join().expect("reap visible-login CLI");
    drop(writer);
    assert!(!output.status.success());
    assert!(!root.join("browser-args.txt").exists());
    assert!(
        String::from_utf8(output.stderr)
            .expect("redacted browser error")
            .contains("browser profile busy")
    );
    cleanup(&root);
}

#[test]
fn visible_login_retries_only_transient_busy_executable() {
    let root = test_root("busy-visible-browser");
    fs::create_dir_all(&root).expect("create synthetic root");
    let browser = fake_browser(&root);
    // A just-written browser executable can temporarily fail execve with
    // ETXTBSY while another process retains an open writable descriptor.
    let writer = fs::OpenOptions::new()
        .write(true)
        .open(&browser)
        .expect("hold executable writable");
    let release = thread::spawn(move || {
        thread::sleep(Duration::from_millis(180));
        drop(writer);
    });
    let output = login(&root, &browser, Some(&root.join("xdg-data")));
    release.join().expect("release executable writer");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    wait_for_args(&root);
    cleanup(&root);
}

#[test]
fn visible_login_rechecks_automation_lease_during_busy_executable_retry() {
    let root = test_root("lease-acquired-during-retry");
    fs::create_dir_all(&root).expect("create synthetic root");
    let browser = fake_browser(&root);
    let data_home = root.join("xdg-data");
    let writer = fs::OpenOptions::new()
        .write(true)
        .open(&browser)
        .expect("hold executable writable");
    let run_root = root.clone();
    let runner = thread::spawn(move || {
        let xdg = run_root.join("xdg-data");
        login(&run_root, &browser, Some(&xdg))
    });
    // Once the CLI has prepared its private profile, it will spin through
    // ETXTBSY retries until this test releases the executable writer.
    let target = profile_under(&data_home);
    for _attempt in 0..100u8 {
        if target.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(target.exists(), "visible login must prepare profile");
    thread::sleep(Duration::from_millis(60));
    let profile_result = Profile::under_data_home(&data_home);
    let profile = profile_result.expect("synthetic profile");
    let lease_result = Lease::acquire(&profile);
    let lease = lease_result.expect("automation takes profile lease");
    // Keep ETXTBSY in force until the runner exits. Releasing the writer
    // while a launch attempt sits between its lease check and execve would
    // let the fake browser start, making the race test itself flaky.
    let output = runner.join().expect("reap visible-login CLI");
    drop(writer);
    assert!(
        !output.status.success(),
        "lease must block the delayed launch"
    );
    assert!(!root.join("browser-args.txt").exists());
    let diagnostic = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(diagnostic.contains("owned by managed automation"));
    drop(lease);
    cleanup(&root);
}

#[test]
fn xdg_login_uses_dedicated_private_profile() {
    let root = test_root("xdg");
    fs::create_dir_all(&root).expect("create synthetic root");
    let browser = fake_browser(&root);
    let data_home = root.join("xdg-data");
    let output = login(&root, &browser, Some(&data_home));
    assert!(output.status.success());

    let profile = profile_under(&data_home);
    let metadata = fs::metadata(&profile).expect("profile must exist");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);

    let args = wait_for_args(&root);
    let expected = format!("--user-data-dir={}", profile.display());
    assert!(args.lines().any(|line| line == expected));
    assert!(args.lines().any(|line| line == "https://mail.proton.me/"));
    assert!(args.lines().any(|line| line == "--disable-extensions"));
    assert!(args.lines().any(|line| line == "--disable-sync"));
    assert!(!args.contains("remote-debugging"));
    assert!(!args.contains("password"));
    assert!(!args.contains("captcha"));
    assert!(!args.contains("cookie"));
    cleanup(&root);
}

#[test]
fn visible_browser_cannot_read_cli_stdin_or_write_cli_output_channels() {
    let root = test_root("browser-stdio");
    fs::create_dir_all(&root).expect("create synthetic root");
    let browser = fake_browser(&root);
    fs::write(
        &browser,
        concat!(
            "#!/bin/sh\n",
            "printf '%s\\n' \"$@\" > \"$PROTONMAIL_AI_TEST_ARGS\"\n",
            "IFS= read -r line || :\n",
            "printf '%s' \"$line\" > \"$PROTONMAIL_AI_TEST_STDIN\"\n",
            "printf 'browser-stdout-private-marker\\n'\n",
            "printf 'browser-stderr-private-marker\\n' >&2\n",
        ),
    )
    .expect("replace synthetic browser script");
    let stdin_capture = root.join("browser-stdin.txt");
    let mut child = Command::new(env!("CARGO_BIN_EXE_protonmail-ai"))
        .args(["auth", "login"])
        .env("PROTONMAIL_AI_BROWSER", &browser)
        .env(LOGIN_ARGS_FILE, root.join("browser-args.txt"))
        .env("PROTONMAIL_AI_TEST_STDIN", &stdin_capture)
        .env("HOME", root.join("home"))
        .env("XDG_DATA_HOME", root.join("xdg-data"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn synthetic login CLI");
    child
        .stdin
        .take()
        .expect("CLI stdin pipe")
        .write_all(b"browser-stdin-private-marker\n")
        .expect("send synthetic CLI input");
    let output = child.wait_with_output().expect("collect CLI output");
    assert!(output.status.success());
    wait_for_args(&root);
    let mut captured = None;
    for _attempt in 0..100u8 {
        if let Ok(text) = fs::read_to_string(&stdin_capture) {
            captured = Some(text);
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(captured.as_deref(), Some(""), "browser must receive EOF");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 CLI stdout");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 CLI stderr");
    assert!(!stdout.contains("browser-stdout-private-marker"));
    assert!(!stderr.contains("browser-stderr-private-marker"));
    cleanup(&root);
}

#[test]
fn shared_writable_data_home_cannot_hold_private_browser_profile() {
    for mode in [0o770u32, 0o777u32] {
        let root = test_root(&format!("shared-data-{mode}"));
        let data_home = root.join("data");
        fs::create_dir_all(&data_home).expect("create shared data home");
        fs::set_permissions(&data_home, fs::Permissions::from_mode(mode))
            .expect("set shared data home mode");
        let browser = fake_browser(&root);
        let output = login(&root, &browser, Some(&data_home));
        assert!(!output.status.success());
        assert!(!root.join("browser-args.txt").exists());
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 error");
        assert!(stderr.contains("browser data home is shared-writable"));
        let mode_after = fs::metadata(&data_home)
            .expect("data home remains")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode_after, mode, "never chmod user-selected data home");
        cleanup(&root);
    }
}

#[test]
fn rejected_missing_data_home_is_not_created_under_untrusted_parent() {
    for mode in [0o770u32, 0o777u32] {
        let root = test_root(&format!("missing-shared-data-{mode}"));
        let shared = root.join("shared");
        let data_home = shared.join("nested").join("private-data");
        fs::create_dir_all(&shared).expect("create synthetic shared parent");
        fs::set_permissions(&shared, fs::Permissions::from_mode(mode))
            .expect("make parent unsafe before login");
        let browser = fake_browser(&root);
        let output = login(&root, &browser, Some(&data_home));
        assert!(!output.status.success());
        assert!(!data_home.exists());
        assert!(!shared.join("nested").exists());
        assert!(!root.join("browser-args.txt").exists());
        cleanup(&root);
    }
}

#[test]
fn missing_data_home_is_not_created_through_untrusted_parent_alias() {
    let root = test_root("missing-shared-alias");
    let shared = root.join("shared");
    let alias = root.join("shared-alias");
    let data_home = alias.join("private-data");
    fs::create_dir_all(&shared).expect("create shared target");
    symlink(&shared, &alias).expect("create caller-owned directory alias");
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777))
        .expect("make resolved target unsafe");
    let browser = fake_browser(&root);
    let output = login(&root, &browser, Some(&data_home));
    assert!(!output.status.success());
    assert!(!shared.join("private-data").exists());
    assert!(!root.join("browser-args.txt").exists());
    cleanup(&root);
}

#[test]
fn missing_data_home_can_be_created_under_trusted_sticky_parent() {
    let root = test_root("missing-sticky-parent");
    let sticky = root.join("sticky");
    let data_home = sticky.join("private-data");
    fs::create_dir_all(&sticky).expect("create synthetic sticky parent");
    fs::set_permissions(&sticky, fs::Permissions::from_mode(0o1777))
        .expect("make parent sticky before login");
    let browser = fake_browser(&root);
    let output = login(&root, &browser, Some(&data_home));
    assert!(output.status.success());
    wait_for_args(&root);
    assert!(profile_under(&data_home).is_dir());
    cleanup(&root);
}

#[test]
fn shared_writable_parent_cannot_replace_private_data_home() {
    for mode in [0o770u32, 0o777u32] {
        let root = test_root(&format!("shared-data-parent-{mode}"));
        let shared = root.join("shared");
        let data_home = shared.join("private-data");
        fs::create_dir_all(&data_home).expect("create private data home");
        fs::set_permissions(&data_home, fs::Permissions::from_mode(0o700))
            .expect("set private home permissions");
        fs::set_permissions(&shared, fs::Permissions::from_mode(mode))
            .expect("make selected parent shared writable");
        let browser = fake_browser(&root);
        let output = login(&root, &browser, Some(&data_home));
        assert!(!output.status.success());
        assert!(!root.join("browser-args.txt").exists());
        assert!(
            String::from_utf8(output.stderr)
                .expect("UTF-8 refusal")
                .contains("browser data home ancestor is unsafe")
        );
        assert_eq!(
            fs::metadata(&shared)
                .expect("shared parent remains")
                .permissions()
                .mode()
                & 0o777,
            mode,
            "unsafe parent permissions must not be silently changed"
        );
        assert_eq!(
            fs::metadata(&data_home)
                .expect("private data home remains")
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "private data home must not be chmodded after refusal"
        );
        cleanup(&root);
    }
}

#[test]
fn symlinked_data_home_cannot_hide_shared_writable_target_ancestor() {
    let root = test_root("alias-shared-ancestor");
    let shared = root.join("shared");
    let actual_data_home = shared.join("private-data");
    let chosen = root.join("xdg-alias");
    fs::create_dir_all(&actual_data_home).expect("create private data home");
    fs::set_permissions(&actual_data_home, fs::Permissions::from_mode(0o700))
        .expect("set private alias target permissions");
    symlink(&actual_data_home, &chosen).expect("create selected XDG alias");
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777))
        .expect("make target ancestor shared writable");
    let browser = fake_browser(&root);
    let output = login(&root, &browser, Some(&chosen));
    assert!(!output.status.success());
    assert!(!root.join("browser-args.txt").exists());
    assert!(!actual_data_home.join("protonmail-ai").exists());
    cleanup(&root);
}

#[test]
fn trusted_sticky_parent_allows_private_data_home() {
    let root = test_root("sticky-ancestor");
    let sticky = root.join("sticky");
    let data_home = sticky.join("private-data");
    fs::create_dir_all(&data_home).expect("create private data home");
    fs::set_permissions(&data_home, fs::Permissions::from_mode(0o700))
        .expect("set private home permissions");
    fs::set_permissions(&sticky, fs::Permissions::from_mode(0o1777))
        .expect("set sticky directory permissions");
    let browser = fake_browser(&root);
    assert!(login(&root, &browser, Some(&data_home)).status.success());
    let expected = profile_under(&data_home);
    assert!(expected.is_dir());
    cleanup(&root);
}

#[test]
fn home_fallback_remains_project_scoped() {
    let root = test_root("home");
    fs::create_dir_all(&root).expect("create synthetic root");
    let browser = fake_browser(&root);
    let output = login(&root, &browser, None);
    assert!(output.status.success());

    let home = root.join("home");
    let data_home = home.join(".local").join("share");
    let profile = profile_under(&data_home);
    assert!(profile.is_dir());
    let args = wait_for_args(&root);
    let expected = format!("--user-data-dir={}", profile.display());
    assert!(args.lines().any(|line| line == expected));
    cleanup(&root);
}

#[test]
fn symlink_profile_fails_before_browser_launch() {
    let root = test_root("symlink");
    let data_home = root.join("xdg-data");
    let app_dir = data_home.join("protonmail-ai");
    let outside = root.join("outside-profile");
    fs::create_dir_all(&app_dir).expect("create app dir");
    fs::create_dir_all(&outside).expect("create outside dir");
    symlink(&outside, app_dir.join("browser-profile")).expect("create symlink");
    let browser = fake_browser(&root);

    let output = login(&root, &browser, Some(&data_home));
    assert!(!output.status.success());
    assert!(!root.join("browser-args.txt").exists());
    cleanup(&root);
}

#[test]
fn file_profile_fails_before_browser_launch() {
    let root = test_root("file");
    let data_home = root.join("xdg-data");
    let app_dir = data_home.join("protonmail-ai");
    fs::create_dir_all(&app_dir).expect("create app dir");
    fs::write(app_dir.join("browser-profile"), "not a directory")
        .expect("create profile-shaped file");
    let browser = fake_browser(&root);

    let output = login(&root, &browser, Some(&data_home));
    assert!(!output.status.success());
    assert!(!root.join("browser-args.txt").exists());
    cleanup(&root);
}

#[test]
fn absent_browser_fails_closed() {
    let root = test_root("missing-browser");
    fs::create_dir_all(&root).expect("create synthetic root");
    let output = Command::new(env!("CARGO_BIN_EXE_protonmail-ai"))
        .args(["auth", "login"])
        .env_remove("PROTONMAIL_AI_BROWSER")
        .env("PATH", root.join("empty-path"))
        .env("HOME", root.join("home"))
        .env("XDG_DATA_HOME", root.join("xdg-data"))
        .output()
        .expect("execute auth login");
    assert!(!output.status.success());
    cleanup(&root);
}

#[test]
fn relative_xdg_data_home_is_ignored() {
    let root = test_root("relative-xdg");
    fs::create_dir_all(&root).expect("create synthetic root");
    let browser = fake_browser(&root);
    let relative = Path::new("relative-data-home");
    let output = login(&root, &browser, Some(relative));
    assert!(output.status.success());

    let home_data = root.join("home/.local/share");
    let profile = profile_under(&home_data);
    assert!(profile.is_dir());
    let args = wait_for_args(&root);
    let expected = format!("--user-data-dir={}", profile.display());
    assert!(args.lines().any(|line| line == expected));
    cleanup(&root);
}

#[test]
fn project_directory_symlink_fails_before_browser_launch() {
    let root = test_root("project-link");
    let data_home = root.join("xdg-data");
    let outside = root.join("outside-project");
    fs::create_dir_all(&data_home).expect("create data home");
    fs::create_dir_all(&outside).expect("create outside dir");
    let project_path = data_home.join("protonmail-ai");
    symlink(&outside, project_path).expect("create project symlink");
    let browser = fake_browser(&root);

    let output = login(&root, &browser, Some(&data_home));
    assert!(!output.status.success());
    assert!(!root.join("browser-args.txt").exists());
    cleanup(&root);
}

#[test]
fn executable_browser_is_discovered_from_path() {
    let root = test_root("path-browser");
    let bin_dir = root.join("bin");
    fs::create_dir_all(&bin_dir).expect("create synthetic bin");
    let generic = fake_browser(&root);
    let browser = bin_dir.join("google-chrome-stable");
    fs::rename(generic, &browser).expect("install fake chrome");
    let data_home = root.join("xdg-data");

    let output = login_without_override(&root, &bin_dir, &data_home);
    assert!(output.status.success());
    let args = wait_for_args(&root);
    assert!(args.contains("https://mail.proton.me/"));
    cleanup(&root);
}

#[test]
fn non_executable_browser_candidate_is_ignored() {
    let root = test_root("nonexec-browser");
    let bin_dir = root.join("bin");
    fs::create_dir_all(&bin_dir).expect("create synthetic bin");
    let browser = bin_dir.join("google-chrome-stable");
    fs::write(&browser, "not executable").expect("write fake candidate");
    let permissions = fs::Permissions::from_mode(0o600);
    fs::set_permissions(&browser, permissions).expect("chmod candidate");
    let data_home = root.join("xdg-data");

    let output = login_without_override(&root, &bin_dir, &data_home);
    assert!(!output.status.success());
    assert!(!root.join("browser-args.txt").exists());
    cleanup(&root);
}

#[test]
fn arbitrary_profile_cli_option_is_rejected_before_browser_launch() {
    let root = test_root("profile-override");
    fs::create_dir_all(&root).expect("create synthetic root");
    let browser = fake_browser(&root);
    let args_file = root.join("browser-args.txt");
    let personal = root.join("personal-browser-profile");

    let output = Command::new(env!("CARGO_BIN_EXE_protonmail-ai"))
        .args([
            "auth",
            "login",
            "--profile",
            personal.to_str().expect("synthetic path must be UTF-8"),
        ])
        .env("PROTONMAIL_AI_BROWSER", browser)
        .env(LOGIN_ARGS_FILE, &args_file)
        .env("HOME", root.join("home"))
        .env("XDG_DATA_HOME", root.join("xdg-data"))
        .output()
        .expect("execute rejected auth login");

    assert!(!output.status.success());
    assert!(!args_file.exists());
    assert!(!personal.exists());
    cleanup(&root);
}

#[test]
fn active_automation_lease_blocks_visible_login_launch() {
    let root = test_root("automation-owned");
    fs::create_dir_all(&root).expect("create synthetic root");
    let data_home = root.join("xdg-data");
    // jig-ignore-next-line: canonical rustfmt line.
    let profile = Profile::under_data_home(&data_home).expect("create profile descriptor");
    let lease = Lease::acquire(&profile).expect("acquire lease");
    let browser = fake_browser(&root);

    let output = login(&root, &browser, Some(&data_home));
    assert!(!output.status.success());
    assert!(!root.join("browser-args.txt").exists());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(stderr.contains("owned by managed automation"));

    drop(lease);
    cleanup(&root);
}

#[test]
fn dedicated_profile_debug_does_not_reveal_absolute_data_home() {
    let root = test_root("private-profile-debug");
    let profile = Profile::under_data_home(&root)
        .expect("isolated absolute data home creates a fixed profile path");
    let debug = format!("{profile:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains(&root.display().to_string()));
}

#[test]
fn login_error_diagnostics_redact_local_paths_and_browser_executables() {
    use mail_web_adapter::WebLoginError;

    // jig-ignore-next-line: canonical rustfmt line.
    let secret_path = PathBuf::from("/test-only/private-home/audit-credential-marker");
    // jig-ignore-next-line: canonical rustfmt line.
    let secret_browser = String::from("/test-only/browser/audit-credential-marker");
    let sensitive = [
        WebLoginError::ProfileLink(secret_path.clone()),
        WebLoginError::ProjectLink(secret_path.clone()),
        WebLoginError::ProfileIsNotDirectory(secret_path.clone()),
        WebLoginError::ProfileCreate(secret_path),
        WebLoginError::BrowserLaunch(secret_browser),
    ];
    for error in sensitive {
        let debug = format!("{error:?}");
        let display = error.to_string();
        assert!(!debug.contains("audit-credential-marker"));
        assert!(!display.contains("audit-credential-marker"));
        assert!(debug.contains("<redacted>"));
        assert_ne!(display, "");
    }
}

#[test]
fn symlinked_project_or_profile_cannot_change_external_directory_permissions() {
    // jig-ignore-next-line: canonical rustfmt line.
    for (case, project_link) in [("external-project", true), ("external-profile", false)] {
        let root = test_root(case);
        let data_home = root.join("data");
        let outside = root.join("outside-private-data");
        fs::create_dir_all(&data_home).expect("create isolated test data home");
        fs::create_dir_all(&outside).expect("create external marker directory");
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o751))
            .expect("set distinguishable outside mode");
        let project = data_home.join("protonmail-ai");
        if project_link {
            // jig-ignore-next-line: canonical rustfmt line.
            symlink(&outside, &project).expect("link project directory to outside");
        } else {
            fs::create_dir_all(&project).expect("create owned project");
            symlink(&outside, project.join("browser-profile"))
                .expect("link profile directory to outside");
        }
        let browser = fake_browser(&root);
        let output = login(&root, &browser, Some(&data_home));
        assert!(!output.status.success());
        assert!(!root.join("browser-args.txt").exists());
        let mode = fs::metadata(&outside)
            .expect("external directory remains present")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o751,
            "outside mode must not be hardened through a link"
        );
        cleanup(&root);
    }
}

#[test]
fn existing_dedicated_directories_are_private_after_login() {
    let root = test_root("existing-private-directories");
    let data_home = root.join("data");
    let project = data_home.join("protonmail-ai");
    let profile = project.join("browser-profile");
    fs::create_dir_all(&profile).expect("create isolated existing profile");
    for directory in [&project, &profile] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o751))
            .expect("set distinguishable old permissions");
    }
    let browser = fake_browser(&root);
    assert!(login(&root, &browser, Some(&data_home)).status.success());
    for directory in [&project, &profile] {
        assert_eq!(
            fs::metadata(directory)
                .expect("existing directory still present")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    // The CLI detaches its synthetic browser. Wait for its final argument
    // write before removing the fake profile tree, otherwise a late child
    // creation can race remove_dir_all and make this test intermittent.
    let _arguments = wait_for_args(&root);
    cleanup(&root);
}

#[test]
fn dangling_project_and_profile_links_fail_without_creating_outside_paths() {
    // jig-ignore-next-line: canonical rustfmt line.
    for (case, project_link) in [("dangling-project", true), ("dangling-profile", false)] {
        let root = test_root(case);
        let data_home = root.join("data");
        let project = data_home.join("protonmail-ai");
        let absent = root.join("must-not-be-created");
        fs::create_dir_all(&data_home).expect("create isolated data home");
        if project_link {
            symlink(&absent, &project).expect("create dangling project link");
        } else {
            fs::create_dir_all(&project).expect("create dedicated project");
            symlink(&absent, project.join("browser-profile"))
                .expect("create dangling profile link");
        }
        let browser = fake_browser(&root);
        assert!(!login(&root, &browser, Some(&data_home)).status.success());
        assert!(!absent.exists());
        assert!(!root.join("browser-args.txt").exists());
        cleanup(&root);
    }
}

#[test]
fn explicitly_chosen_symlinked_data_home_still_isolates_project_components() {
    let root = test_root("symlinked-data-home");
    let actual_home = root.join("actual-data-home");
    let aliased_home = root.join("xdg-data-home-alias");
    fs::create_dir_all(&actual_home).expect("create isolated data-home target");
    symlink(&actual_home, &aliased_home).expect("create synthetic XDG alias");
    let browser = fake_browser(&root);
    assert!(login(&root, &browser, Some(&aliased_home)).status.success());
    let expected = actual_home.join("protonmail-ai/browser-profile");
    assert!(expected.is_dir());
    let args = wait_for_args(&root);
    assert!(args.contains("--user-data-dir="));
    let alias_profile = aliased_home.join("protonmail-ai/browser-profile");
    // jig-ignore-next-line: canonical rustfmt line.
    assert!(args.contains(alias_profile.to_str().expect("synthetic UTF-8 path")));
    cleanup(&root);
}

#[test]
fn corrupt_automation_owner_blocks_visible_login() {
    let root = test_root("corrupt-owner");
    fs::create_dir_all(&root).expect("create synthetic root");
    let data_home = root.join("xdg-data");
    let dir = data_home.join("protonmail-ai");
    fs::create_dir_all(&dir).expect("create project");
    let lease = dir.join(".automation-lease");
    fs::write(&lease, "v1 4294967295 1\n\n").expect("write fixture");
    let browser = fake_browser(&root);
    let output = login(&root, &browser, Some(&data_home));
    assert!(!output.status.success());
    assert!(!root.join("browser-args.txt").exists());
    assert_eq!(
        fs::read_to_string(&lease).expect("read"),
        "v1 4294967295 1\n\n"
    );
    cleanup(&root);
}

#[test]
fn non_utf8_data_home_preserves_exact_browser_argument() {
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};

    let root = test_root("non-utf8-home");
    fs::create_dir_all(&root).expect("create isolated test root");
    let browser = fake_browser(&root);
    let data_home = root.join(OsString::from_vec(b"data-\xff".to_vec()));
    let output = login(&root, &browser, Some(&data_home));
    assert!(output.status.success());
    let profile = profile_under(&data_home);
    assert!(profile.is_dir());
    let mut expected = b"--user-data-dir=".to_vec();
    expected.extend_from_slice(profile.as_os_str().as_bytes());
    let args = wait_for_args_bytes(&root);
    assert!(
        args.split(|byte| *byte == b'\n')
            .any(|line| line == expected.as_slice())
    );
    cleanup(&root);
}

#[test]
fn non_utf8_browser_override_cannot_silently_select_a_fallback() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;

    let root = test_root("non-utf8-browser-override");
    let bin = root.join("bin");
    fs::create_dir_all(&bin).expect("create synthetic PATH");
    let fallback = fake_browser(&root);
    fs::rename(fallback, bin.join("google-chrome-stable"))
        .expect("install synthetic fallback browser");
    let args = root.join("browser-args.txt");
    let output = Command::new(env!("CARGO_BIN_EXE_protonmail-ai"))
        .args(["auth", "login"])
        .env("PROTONMAIL_AI_BROWSER", OsString::from_vec(vec![b'x', 255]))
        .env(LOGIN_ARGS_FILE, &args)
        .env("PATH", bin)
        .env("HOME", root.join("home"))
        .env("XDG_DATA_HOME", root.join("xdg-data"))
        .output()
        .expect("invoke synthetic login");
    assert!(!output.status.success());
    assert!(!args.exists());
    cleanup(&root);
}

#[test]
fn non_utf8_home_fallback_keeps_exact_profile_bytes() {
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};

    let root = test_root("raw-home-fallback");
    fs::create_dir_all(&root).expect("create isolated root");
    let browser = fake_browser(&root);
    let home = root.join(OsString::from_vec(b"home-\xff".to_vec()));
    let args_file = root.join("browser-args.txt");
    let output = Command::new(env!("CARGO_BIN_EXE_protonmail-ai"))
        .args(["auth", "login"])
        .env("PROTONMAIL_AI_BROWSER", browser)
        .env(LOGIN_ARGS_FILE, &args_file)
        .env_remove("XDG_DATA_HOME")
        .env("HOME", &home)
        .output()
        .expect("run synthetic login");
    assert!(output.status.success());
    let profile = profile_under(&home.join(".local/share"));
    assert!(profile.is_dir());
    let mut expected = b"--user-data-dir=".to_vec();
    expected.extend_from_slice(profile.as_os_str().as_bytes());
    let args = wait_for_args_bytes(&root);
    assert!(
        args.split(|byte| *byte == b'\n')
            .any(|line| line == expected.as_slice())
    );
    cleanup(&root);
}
