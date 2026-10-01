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
//   - Synthetic evidence for content-free mailbox-mode reduction.
// - Must-Not:
//   - Read URL text, account state, localized text, rows, or provider stores.
// - Allows:
//   - Verify provider booleans reduce conservatively to message/unknown mode.
// - Split-When:
//   - Conversation-mode evidence gains a separate externally stable source.
// - Merge-When:
//   - Mailbox page workflow tests own all mode-reduction invariants.
// - Summary:
//   - Proves mode evidence never guesses conversation/message semantics.
// - Description:
//   - Covers forced-route/search flags, unknown state, and malformed evidence.
// - Usage:
//   - Run through the `mail_web_adapter` integration-test target.
// - Defaults:
//   - Missing or non-boolean fields fail closed.
//

//! Content-free mailbox-mode evidence regression tests.

use mail_web_adapter::{MailboxModeEvidence, MailboxRenderMode};

// jig-ignore-next-line: rustfmt keeps the include_str invocation intact.
const MODE_SOURCE: &str = include_str!("../../../../src/mail/web/adapter-outbound/mailbox_mode.rs");

#[test]
fn source_contains_provider_forced_message_rules_without_content_return() {
    let source = MODE_SOURCE;
    for route in ["drafts", "all-drafts", "sent", "all-sent", "deleted"] {
        assert!(source.contains(route));
    }
    for key in [
        "address", "from", "keyword", "to", "begin", "end", "wildcard",
    ] {
        assert!(source.contains(key));
    }
    assert!(source.contains("forcedMessageRoute"));
    assert!(source.contains("activeSearch"));
    assert!(!source.contains("return {pathname"));
    assert!(!source.contains("return {hash"));
}

#[test]
fn forced_route_or_search_proves_messages() {
    for (forced, search) in [(true, false), (false, true), (true, true)] {
        let evidence = MailboxModeEvidence::from_signals(forced, search);
        assert_eq!(evidence.mode(), MailboxRenderMode::Messages);
    }
}

#[test]
fn no_forced_signal_remains_unknown() {
    let evidence = MailboxModeEvidence::from_signals(false, false);
    assert_eq!(evidence.mode(), MailboxRenderMode::Unknown);
}
