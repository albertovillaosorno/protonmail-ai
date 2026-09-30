// SPDX-License-Identifier: GPL-3.0-only

//! Non-operational bootstrap binary for `protonmail-ai`.

#![forbid(unsafe_code)]

use protonmail_ai_core::planned_capabilities;

fn main() {
    println!(
        "{}",
        concat!(
            "protonmail-ai is an implementation scaffold; ",
            "no mailbox was accessed."
        )
    );
    println!("planned capabilities: {}", planned_capabilities().len());
    println!("see TODO.md before implementing or enabling an adapter");
}
