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
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Output};
use std::thread;
use std::time::Duration;

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

fn wait_for_args(root: &Path) -> String {
    let path = root.join("browser-args.txt");
    for _attempt in 0..100u8 {
        if let Ok(value) = fs::read_to_string(&path) {
            return value;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("fake browser did not record arguments");
}

fn profile_under(data_home: &Path) -> PathBuf {
    data_home.join("protonmail-ai").join("browser-profile")
}

fn cleanup(root: &Path) {
    fs::remove_dir_all(root).expect("remove synthetic web profile tree");
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
    assert!(!args.contains("remote-debugging"));
    assert!(!args.contains("password"));
    assert!(!args.contains("captcha"));
    assert!(!args.contains("cookie"));
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
