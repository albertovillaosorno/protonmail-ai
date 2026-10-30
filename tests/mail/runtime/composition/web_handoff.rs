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
use std::os::unix::fs::symlink;
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
fn rejected_compose_args_do_not_open_body_files() {
    // /dev/null is not a regular body file. An earlier argument error must
    // prevail instead of touching a file the rejected command cannot use.
    for (args, expected) in [
        (
            vec!["--body-file", "/dev/null"],
            ComposeInputError::MissingTo,
        ),
        (
            vec!["--to", "bad address", "--body-file", "/dev/null"],
            ComposeInputError::InvalidRecipient,
        ),
        (
            vec![
                "--to",
                "one@example.test",
                "--body-file",
                "/dev/null",
                "--subject",
                "first\nsecond",
            ],
            ComposeInputError::InvalidSubject,
        ),
        (
            vec![
                "--to",
                "one@example.test",
                "--body-file",
                "/dev/null",
                "--subject",
                "first",
                "--subject",
                "second",
            ],
            ComposeInputError::DuplicateFlag("--subject"),
        ),
    ] {
        let args = args.into_iter().map(String::from).collect::<Vec<_>>();
        assert_eq!(ComposeInput::parse(&args), Err(expected));
    }

    let output = run(&["mail", "compose-url", "--body-file", "/dev/null"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("--to is required"));
    assert!(!stderr(&output).contains("cannot read body file"));
    assert!(output.stdout.is_empty());
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
fn body_file_does_not_follow_symlink_into_unrelated_content() {
    let target = body_path("symlink-target");
    let alias = body_path("symlink-alias");
    if alias.exists() {
        fs::remove_file(&alias).expect("remove stale link");
    }
    let private_body = "unrelated-private-body-marker";
    fs::write(&target, private_body).expect("write private fixture");
    symlink(&target, &alias).expect("link to unrelated content");
    let alias_text = alias.to_str().expect("UTF-8 fixture link");
    let output = run(&[
        "mail",
        "compose-url",
        "--to",
        "person@example.test",
        "--body-file",
        alias_text,
    ]);
    fs::remove_file(&alias).expect("remove synthetic link");
    fs::remove_file(&target).expect("remove synthetic target");

    assert!(!output.status.success(), "symlink body must be refused");
    assert!(output.stdout.is_empty(), "do not encode unrelated bytes");
    assert!(stderr(&output).contains("cannot read body file"));
    assert!(!stderr(&output).contains("symlink-alias"));
    assert!(!stderr(&output).contains("unrelated-private-body-marker"));
}

#[test]
fn body_file_rejects_symlinked_parent_directory() {
    let name = format!("protonmail-ai-body-parent-link-{}", process::id());
    let root = env::temp_dir().join(name);
    if root.exists() {
        fs::remove_dir_all(&root).expect("clear synthetic fixture");
    }
    let directory = root.join("real");
    let alias = root.join("alias");
    fs::create_dir_all(&directory).expect("create ordinary nested source");
    let content = directory.join("body.txt");
    fs::write(&content, "private-symlink-parent-body").expect("synthetic body");
    symlink(&directory, &alias).expect("alias source directory");

    let aliased = alias.join("body.txt");
    let output = run(&[
        "mail",
        "compose-url",
        "--to",
        "person@example.test",
        "--body-file",
        aliased.to_str().expect("fixture UTF-8"),
    ]);
    assert!(!output.status.success(), "must refuse parent alias");
    assert!(output.stdout.is_empty());
    assert!(stderr(&output).contains("cannot read body file"));
    assert!(!stderr(&output).contains("private-symlink-parent-body"));

    // The same regular file remains usable through an ordinary directory.
    let ordinary = run(&[
        "mail",
        "compose-url",
        "--to",
        "person@example.test",
        "--body-file",
        content.to_str().expect("fixture UTF-8"),
    ]);
    assert!(ordinary.status.success(), "ordinary nested path must work");
    assert!(stdout(&ordinary).contains("private-symlink-parent-body"));
    fs::remove_dir_all(&root).expect("clean synthetic fixture");
}

#[test]
fn body_file_accepts_explicit_relative_parent_component() {
    let name = format!("protonmail-ai-body-relative-{}", process::id());
    let root = env::temp_dir().join(name);
    if root.exists() {
        fs::remove_dir_all(&root).expect("clear synthetic fixture");
    }
    let nested = root.join("nested");
    fs::create_dir_all(&nested).expect("create relative working directory");
    fs::write(root.join("body.txt"), "ordinary-relative-body")
        .expect("write ordinary relative body");
    let output = Command::new(env!("CARGO_BIN_EXE_protonmail-ai"))
        .current_dir(&nested)
        .args([
            "mail",
            "compose-url",
            "--to",
            "person@example.test",
            "--body-file",
            "../body.txt",
        ])
        .output()
        .expect("run helper with explicit relative path");
    assert!(output.status.success());
    assert!(stdout(&output).contains("ordinary-relative-body"));
    fs::remove_dir_all(&root).expect("clean synthetic fixture");
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

#[test]
fn composer_single_line_fields_reject_unicode_line_controls() {
    for marker in ['\u{0085}', '\u{2028}', '\u{2029}'] {
        let recipient = format!("local{marker}@example.test");
        let to = run(&["mail", "compose-url", "--to", &recipient]);
        assert!(
            !to.status.success(),
            "recipient Unicode line control passed"
        );
        assert!(stderr(&to).contains("recipient contains control"));
        assert!(to.stdout.is_empty());

        for flag in ["--cc", "--bcc"] {
            let copy = run(&[
                "mail",
                "compose-url",
                "--to",
                "person@example.test",
                flag,
                &recipient,
            ]);
            assert!(!copy.status.success(), "copy address control passed");
            assert!(stderr(&copy).contains("recipient contains control"));
            assert!(copy.stdout.is_empty());
        }

        let subject = format!("invoice{marker}extra");
        let title = run(&[
            "mail",
            "compose-url",
            "--to",
            "person@example.test",
            "--subject",
            &subject,
        ]);
        assert!(
            !title.status.success(),
            "subject Unicode line control passed"
        );
        assert!(stderr(&title).contains("subject contains control"));
        assert!(title.stdout.is_empty());
    }
}

#[test]
fn composer_header_fields_reject_invisible_formatting_characters() {
    // These are not directional overrides or line breaks, but invisible
    // selectors can conceal the actual destination or change a shown subject.
    for mark in [
        '\u{00ad}',
        '\u{034f}',
        '\u{0600}',
        '\u{0605}',
        '\u{06dd}',
        '\u{070f}',
        '\u{0890}',
        '\u{0891}',
        '\u{08e2}',
        '\u{17b4}',
        '\u{17b5}',
        '\u{1bca0}',
        '\u{1bca3}',
        '\u{180e}',
        '\u{200b}',
        '\u{200c}',
        '\u{200d}',
        '\u{2060}',
        '\u{2800}',
        '\u{3164}',
        '\u{ffa0}',
        '\u{fe0f}',
        '\u{feff}',
        '\u{fff9}',
        '\u{fffb}',
        '\u{110bd}',
        '\u{110cd}',
        '\u{13430}',
        '\u{1343f}',
        '\u{1d173}',
        '\u{1d17a}',
        '\u{e0001}',
        '\u{e0100}',
    ] {
        let recipient = format!("support{mark}@example.test");
        for flag in ["--to", "--cc", "--bcc"] {
            let args = if flag == "--to" {
                vec!["mail", "compose-url", "--to", &recipient]
            } else {
                vec![
                    "mail",
                    "compose-url",
                    "--to",
                    "valid@example.test",
                    flag,
                    &recipient,
                ]
            };
            let result = run(&args);
            assert!(!result.status.success(), "invisible {flag} must fail");
            assert!(result.stdout.is_empty());
            assert!(stderr(&result).contains("recipient contains control"));
            assert!(!stderr(&result).contains(&recipient));
        }
        // Joiners and variation selectors have valid linguistic/emoji uses in
        // subject prose, but never in bare email recipient addresses.
        if matches!(
            mark,
            '\u{180b}'..='\u{180d}' | '\u{200c}'..='\u{200d}'
                | '\u{fe00}'..='\u{fe0f}' | '\u{e0100}'..='\u{e01ef}'
        ) {
            continue;
        }
        let subject = format!("invoice{mark}approved");
        let result = run(&[
            "mail",
            "compose-url",
            "--to",
            "valid@example.test",
            "--subject",
            &subject,
        ]);
        assert!(!result.status.success(), "invisible subject must fail");
        assert!(result.stdout.is_empty());
        assert!(stderr(&result).contains("subject contains control"));
        assert!(!stderr(&result).contains(&subject));
    }
}

#[test]
fn composer_literal_recipients_refuse_replacement_character() {
    let address = "alice\u{fffd}@example.test";
    for flag in ["--to", "--cc", "--bcc"] {
        let args = if flag == "--to" {
            vec!["mail", "compose-url", "--to", address]
        } else {
            vec![
                "mail",
                "compose-url",
                "--to",
                "valid@example.test",
                flag,
                address,
            ]
        };
        let output = run(&args);
        assert!(!output.status.success(), "lossy {flag} address must fail");
        assert!(output.stdout.is_empty());
        assert!(stderr(&output).contains("recipient contains control"));
        assert!(!stderr(&output).contains(address));
    }
    let subject = run(&[
        "mail",
        "compose-url",
        "--to",
        "alice@example.test",
        "--subject",
        "Quoted \u{fffd} replacement glyph",
    ]);
    assert!(subject.status.success(), "subject text is not a mailbox ID");
}

#[test]
fn composer_literal_recipients_refuse_address_list_delimiters() {
    for address in [
        "alice@example.test,bob@example.test",
        "alice@example.test;bob@example.test",
        "alice@example.test:Bcc:other@example.test",
        "<alice@example.test>",
    ] {
        for flag in ["--to", "--cc", "--bcc"] {
            let args = if flag == "--to" {
                vec!["mail", "compose-url", "--to", address]
            } else {
                vec![
                    "mail",
                    "compose-url",
                    "--to",
                    "valid@example.test",
                    flag,
                    address,
                ]
            };
            let result = run(&args);
            assert!(!result.status.success(), "one {flag} cannot hide a list");
            assert!(result.stdout.is_empty());
            assert!(stderr(&result).contains("recipient contains control"));
            assert!(!stderr(&result).contains(address));
        }
    }
    let valid = run(&[
        "mail",
        "compose-url",
        "--to",
        "alice+tag@example.test",
        "--subject",
        "Hello, Alice: see attachments; thanks",
    ]);
    assert!(
        valid.status.success(),
        "subject prose and plus-tags remain valid"
    );
}

#[test]
fn composer_literal_recipients_refuse_embedded_whitespace() {
    for address in [
        "person@example.test Bcc:other@example.test",
        "person @example.test",
        "person\u{00a0}@example.test",
        "person\u{1680}@example.test",
        "person\u{2007}@example.test",
        "person\u{202f}@example.test",
        "person\u{3000}@example.test",
    ] {
        for flag in ["--to", "--cc", "--bcc"] {
            let args = if flag == "--to" {
                vec!["mail", "compose-url", "--to", address]
            } else {
                vec![
                    "mail",
                    "compose-url",
                    "--to",
                    "valid@example.test",
                    flag,
                    address,
                ]
            };
            let result = run(&args);
            assert!(!result.status.success(), "ambiguous {flag} must fail");
            assert!(result.stdout.is_empty());
            assert!(stderr(&result).contains("recipient contains control"));
            assert!(!stderr(&result).contains(address));
        }
    }
    let valid = run(&[
        "mail",
        "compose-url",
        "--to",
        "alice+tag@example.test",
        "--subject",
        "Meeting notes with spaces",
    ]);
    assert!(
        valid.status.success(),
        "ordinary subject and address remain valid"
    );
}

#[test]
fn subject_accepts_emoji_variation_and_language_joiners() {
    let subject = concat!(
        "Heart \u{2764}\u{fe0f}, coder \u{1f469}\u{200d}\u{1f4bb}",
        ", Name\u{200c}part"
    );
    let output = run(&[
        "mail",
        "compose-url",
        "--to",
        "person@example.test",
        "--subject",
        subject,
    ]);
    assert!(
        output.status.success(),
        "ordinary subject graphemes must work"
    );
    let url = stdout(&output);
    assert!(url.starts_with("https://mail.proton.me/inbox/#mailto="));
    assert!(
        url.contains("%25E2%259D%25A4"),
        "Unicode subject encoded twice"
    );
}

#[test]
fn composer_address_and_subject_refuse_invisible_direction_overrides() {
    // Bidi controls can make the displayed destination or subject differ from
    // the encoded text even though no newline is present.
    for mark in [
        // jig-ignore-next-line: rustfmt canonical bidi control fixture.
        '\u{061c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}',
        // jig-ignore-next-line: rustfmt canonical bidi control fixture.
        '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{206e}', '\u{206f}',
    ] {
        let recipient = format!("candidate{mark}@example.test");
        for flag in ["--to", "--cc", "--bcc"] {
            let args = if flag == "--to" {
                vec!["mail", "compose-url", "--to", &recipient]
            } else {
                vec![
                    "mail",
                    "compose-url",
                    "--to",
                    "valid@example.test",
                    flag,
                    &recipient,
                ]
            };
            let result = run(&args);
            assert!(!result.status.success(), "bidi address must fail");
            assert!(result.stdout.is_empty());
            assert!(stderr(&result).contains("recipient contains control"));
            assert!(!stderr(&result).contains(&recipient));
        }
        let subject = format!("invoice{mark}2026");
        let result = run(&[
            "mail",
            "compose-url",
            "--to",
            "valid@example.test",
            "--subject",
            &subject,
        ]);
        assert!(!result.status.success(), "bidi subject must fail");
        assert!(result.stdout.is_empty());
        assert!(stderr(&result).contains("subject contains control"));
        assert!(!stderr(&result).contains(&subject));
    }
}

#[test]
fn composer_rejects_oversized_header_fields_before_encoding() {
    for flag in ["--to", "--cc", "--bcc"] {
        let oversized = "x".repeat(8_193);
        let args = if flag == "--to" {
            vec!["mail", "compose-url", "--to", oversized.as_str()]
        } else {
            vec![
                "mail",
                "compose-url",
                "--to",
                "person@example.test",
                flag,
                oversized.as_str(),
            ]
        };
        let output = run(&args);
        assert!(!output.status.success(), "oversized recipients must fail");
        assert!(output.stdout.is_empty());
        assert!(stderr(&output).contains("recipient exceeds 8192 bytes"));
        assert!(!stderr(&output).contains(&oversized));
    }
    let subject = "\u{e9}".repeat(1_025);
    let output = run(&[
        "mail",
        "compose-url",
        "--to",
        "person@example.test",
        "--subject",
        &subject,
    ]);
    assert!(!output.status.success(), "oversized subject must fail");
    assert!(output.stdout.is_empty());
    assert!(stderr(&output).contains("subject exceeds 2048 bytes"));
    assert!(!stderr(&output).contains(&subject));
}

#[test]
fn composer_header_byte_ceiling_is_inclusive() {
    let to = "x".repeat(8_192);
    let subject = "\u{e9}".repeat(1_024);
    let args = ["mail", "compose-url", "--to", &to, "--subject", &subject];
    let output = run(&args);
    assert!(output.status.success());
    assert!(stderr(&output).is_empty());
    assert!(
        String::from_utf8(output.stdout)
            .expect("UTF-8 URL")
            .starts_with("https://mail.proton.me/inbox/#mailto=")
    );
}
