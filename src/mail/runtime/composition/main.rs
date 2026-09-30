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

use mail_capability_domain::planned_capabilities;

fn main() {
    let capability_count = planned_capabilities().len();

    println!(
        "{}",
        concat!(
            "protonmail-ai is an implementation scaffold; ",
            "no mailbox was accessed."
        )
    );
    println!("planned capabilities: {capability_count}");
    println!("planned modes: cli | mcp | serve | auth");
    println!("see TODO.md before enabling an adapter");
}
