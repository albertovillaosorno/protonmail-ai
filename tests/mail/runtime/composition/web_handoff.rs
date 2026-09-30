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
//   - Executable evidence for the web-composer handoff CLI.
// - Must-Not:
//   - Open a browser, send mail, or use live account data.
// - Allows:
//   - Execute the built binary with synthetic composition input.
// - Split-When:
//   - CLI process testing grows beyond handoff behavior.
// - Merge-When:
//   - A broader CLI acceptance suite owns these cases.
// - Summary:
//   - Verifies encoded Proton Mail compose URLs and fail-closed parsing.
// - Description:
//   - Exercises aliases, Unicode, line breaks, and invalid CLI input.
// - Usage:
//   - Run through the `mail_runtime` integration-test target.
// - Defaults:
//   - Synthetic `.test` recipients only; no network side effects.
//

//! Web-composer handoff CLI regression tests.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{self, Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_protonmail-ai"))
        .args(args)
        .output()
        .expect("protonmail-ai binary must execute")
}

fn body_path(label: &str) -> PathBuf {
    let name = format!("protonmail-ai-{label}-{}.txt", process::id());
    env::temp_dir().join(name)
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout must be UTF-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr must be UTF-8")
}

#[test]
fn compose_url_preserves_alias_unicode_and_line_breaks() {
    let output = run(&[
        "mail",
        "compose-url",
        "--to",
        "candidate+jobs@example.test",
        "--cc",
        "team@example.test",
        "--bcc",
        "audit@example.test",
        "--subject",
        "Entrevista \u{2013} seguimiento",
        "--body",
        "Hola,\nGracias \u{2615}",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));

    let url = stdout(&output);
    assert!(url.starts_with("https://mail.proton.me/inbox/#mailto=mailto%3A"));
    assert!(url.contains("candidate%252Bjobs%2540example.test"));
    assert!(url.contains("%3Fsubject%3DEntrevista%2520%25E2%2580%2593"));
    assert!(url.contains("%26cc%3Dteam%2540example.test"));
    assert!(url.contains("%26bcc%3Daudit%2540example.test"));
    assert!(url.contains("%26body%3DHola%252C%250A"));
    assert!(url.contains("Gracias%2520%25E2%2598%2595"));
}

#[test]
fn missing_primary_recipient_fails_closed() {
    let output = run(&["mail", "compose-url", "--subject", "Synthetic"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("--to is required"));
}

#[test]
fn duplicate_single_value_flag_is_rejected() {
    let output = run(&[
        "mail",
        "compose-url",
        "--to",
        "one@example.test",
        "--to",
        "two@example.test",
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("duplicate compose flag: --to"));
}

#[test]
fn subject_line_break_is_rejected() {
    let output = run(&[
        "mail",
        "compose-url",
        "--to",
        "person@example.test",
        "--subject",
        "line one\nline two",
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("subject contains control"));
}

#[test]
fn body_file_is_encoded_without_putting_body_in_cli_arguments() {
    let path = body_path("body");
    fs::write(&path, "Hello\nFrom file \u{2615}").expect("write body");
    let path_text = path.to_str().expect("temporary path must be UTF-8");
    let output = run(&[
        "mail",
        "compose-url",
        "--to",
        "file@example.test",
        "--body-file",
        path_text,
    ]);
    fs::remove_file(&path).expect("remove synthetic body");

    assert!(output.status.success(), "{}", stderr(&output));
    let url = stdout(&output);
    assert!(url.contains("%3Fbody%3DHello%250AFrom%2520file%2520"));
    assert!(url.contains("%25E2%2598%2595"));
}

#[test]
fn missing_body_file_fails_closed() {
    let path = body_path("missing");
    if path.exists() {
        fs::remove_file(&path).expect("remove stale body");
    }
    let path_text = path.to_str().expect("temporary path must be UTF-8");
    let output = run(&[
        "mail",
        "compose-url",
        "--to",
        "file@example.test",
        "--body-file",
        path_text,
    ]);

    assert!(!output.status.success());
    assert!(stderr(&output).contains("cannot read body file"));
}

#[test]
fn inline_body_and_body_file_are_mutually_exclusive() {
    let path = body_path("conflict");
    fs::write(&path, "file body").expect("write body");
    let path_text = path.to_str().expect("temporary path must be UTF-8");
    let output = run(&[
        "mail",
        "compose-url",
        "--to",
        "file@example.test",
        "--body",
        "inline body",
        "--body-file",
        path_text,
    ]);
    fs::remove_file(&path).expect("remove synthetic body");

    assert!(!output.status.success());
    assert!(stderr(&output).contains("duplicate compose flag"));
}

#[test]
fn oversized_inline_body_is_rejected() {
    let body = "x".repeat(16_385);
    let output = run(&[
        "mail",
        "compose-url",
        "--to",
        "size@example.test",
        "--body",
        &body,
    ]);

    assert!(!output.status.success());
    assert!(stderr(&output).contains("body exceeds 16384 bytes"));
}

#[test]
fn oversized_body_file_is_rejected_before_encoding() {
    let path = body_path("oversized");
    fs::write(&path, "x".repeat(16_385)).expect("write oversized body");
    let path_text = path.to_str().expect("temporary path must be UTF-8");
    let output = run(&[
        "mail",
        "compose-url",
        "--to",
        "size@example.test",
        "--body-file",
        path_text,
    ]);
    fs::remove_file(&path).expect("remove oversized body");

    assert!(!output.status.success());
    assert!(stderr(&output).contains("body exceeds 16384 bytes"));
}
