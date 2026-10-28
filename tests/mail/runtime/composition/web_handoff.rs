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
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt as _;
use std::path::PathBuf;
use std::process::{self, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::stat::Mode;
use nix::unistd::mkfifo;

#[path = "../../../../src/mail/runtime/composition/web_handoff.rs"]
pub mod web_handoff;

use web_handoff::{ComposeInput, ComposeInputError};

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

#[test]
fn compose_input_and_error_debug_redact_mail_and_path_content() {
    let input = ComposeInput::parse(&[
        "--to".into(),
        "secret-recipient@example.test".into(),
        "--subject".into(),
        "secret-subject-marker".into(),
        "--body".into(),
        "secret-body-marker".into(),
    ])
    .expect("synthetic compose input");
    let debug = format!("{input:?}");
    assert!(input.web_url().starts_with("https://mail.proton.me/inbox/"));
    for secret in ["secret-recipient", "secret-subject", "secret-body"] {
        assert!(
            !debug.contains(secret),
            "Debug must not expose mail content"
        );
    }
    let errors = [
        ComposeInputError::BodyFileRead(String::from("secret-path-marker")),
        ComposeInputError::UnknownFlag(String::from("--secret-flag-marker")),
    ];
    for error in errors {
        let debug = format!("{error:?}");
        let display = error.to_string();
        assert!(!debug.contains("secret"), "Debug must redact CLI input");
        assert!(!display.contains("secret"), "Display must redact CLI input");
    }
}

#[test]
fn compose_errors_never_echo_unknown_flags_or_private_file_paths() {
    let unrecognized = run(&[
        "mail",
        "compose-url",
        "--to",
        "candidate@example.test",
        "--secret-flag-marker",
        "synthetic-value",
    ]);
    assert!(!unrecognized.status.success());
    assert!(!stderr(&unrecognized).contains("secret-flag-marker"));
    assert!(stderr(&unrecognized).contains("unknown compose flag"));

    let missing = run(&[
        "mail",
        "compose-url",
        "--to",
        "candidate@example.test",
        "--body-file",
        "/private/secret-file-marker.txt",
    ]);
    assert!(!missing.status.success());
    assert!(stderr(&missing).contains("cannot read body file"));
    assert!(!stderr(&missing).contains("secret-file-marker"));
}

#[test]
fn non_utf8_cli_args_fail_without_panic_or_leak() {
    let raw = b"private-recipient-\xff@example.test".to_vec();
    let input = OsString::from_vec(raw);
    let output = Command::new(env!("CARGO_BIN_EXE_protonmail-ai"))
        .args(["mail", "compose-url", "--to"])
        .arg(input)
        .output()
        .expect("run CLI with non-UTF-8 user input");
    assert_eq!(output.status.code(), Some(1i32));
    assert!(output.stdout.is_empty());
    let diagnostic = stderr(&output);
    assert!(diagnostic.contains("invalid command arguments"));
    assert!(!diagnostic.contains("private-recipient"));
    assert!(!diagnostic.contains("panicked"));
}

#[test]
fn nonregular_body_file_refuses_fifo_without_waiting_for_writer() {
    let path = body_path("fifo");
    if path.exists() {
        fs::remove_file(&path).expect("remove stale fixture");
    }
    let private_mode = Mode::from_bits_truncate(0o600);
    mkfifo(&path, private_mode).expect("create FIFO fixture");
    let mut child = Command::new(env!("CARGO_BIN_EXE_protonmail-ai"))
        .args(["mail", "compose-url", "--to", "person@example.test"])
        .arg("--body-file")
        .arg(&path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start CLI without a FIFO writer");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if child.try_wait().expect("poll synthetic CLI").is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().expect("stop blocked CLI");
            child.wait().expect("reap stopped CLI");
            fs::remove_file(&path).expect("remove FIFO fixture");
            panic!("body-file FIFO blocked without a writer");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().expect("collect CLI output");
    fs::remove_file(&path).expect("remove FIFO fixture");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(stderr(&output).contains("cannot read body file"));
}
