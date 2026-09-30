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
//   - Process startup and explicit CLI, MCP, authentication, and server wiring.
// - Must-Not:
//   - Own provider semantics, credential material, or mail business rules.
// - Allows:
//   - Compose accepted ports and adapters behind one installed executable.
// - Split-When:
//   - A runtime mode requires an independently deployed product boundary.
// - Merge-When:
//   - Process startup no longer has an independent composition concern.
// - Summary:
//   - Composes the installable mail automation runtime.
// - Description:
//   - Selects explicit local CLI, MCP, login, or remote service operation.
// - Usage:
//   - Install and invoke the `protonmail-ai` executable.
// - Defaults:
//   - No provider access, listener, authentication, or mailbox mutation.
//

//! Composition root for CLI, local MCP, and remote-server modes.

#![forbid(unsafe_code)]

pub mod web_handoff;

use std::env;
use std::process::ExitCode;

use mail_capability_domain::planned_capabilities;
use mail_web_adapter::WebLoginPlan;
use web_handoff::ComposeInput;

fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [mode, command] if is_auth_login(mode, command) => web_login(),
        [mode, command, rest @ ..] if is_mail(mode, command) => emit_url(rest),
        [] => {
            print_status();
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{}", usage());
            ExitCode::FAILURE
        }
    }
}

fn is_auth_login(mode: &str, command: &str) -> bool {
    mode == "auth" && command == "login"
}

fn web_login() -> ExitCode {
    match WebLoginPlan::from_environment().and_then(|plan| plan.launch()) {
        Ok(()) => {
            println!("protonmail-ai: opened dedicated Proton Mail profile");
            println!("finish sign-in visibly; the CLI reads no credentials");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("cannot start web login: {error}");
            ExitCode::FAILURE
        }
    }
}

fn is_mail(mode: &str, command: &str) -> bool {
    mode == "mail" && command == "compose-url"
}

fn emit_url(args: &[String]) -> ExitCode {
    match ComposeInput::parse(args) {
        Ok(input) => {
            println!("{}", input.web_url());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("invalid compose request: {error}");
            eprintln!("{}", compose_usage());
            ExitCode::FAILURE
        }
    }
}

const fn usage() -> &'static str {
    concat!(
        "usage: protonmail-ai auth login\n",
        "       protonmail-ai mail compose-url --to RECIPIENT ..."
    )
}

const fn compose_usage() -> &'static str {
    concat!(
        "usage: protonmail-ai mail compose-url --to RECIPIENT ",
        "[--cc RECIPIENTS] [--bcc RECIPIENTS] ",
        "[--subject TEXT] [--body TEXT | --body-file PATH]"
    )
}

fn print_status() {
    let capability_count = planned_capabilities().len();
    println!("protonmail-ai: no mailbox was accessed");
    println!("planned capabilities: {capability_count}");
    println!("available now: auth login | mail compose-url");
    println!("planned modes: cli | mcp | serve");
}
