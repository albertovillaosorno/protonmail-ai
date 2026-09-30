# protonmail-ai

Local-first Rust infrastructure for giving AI clients auditable, least-privilege
access to Proton Mail through the Model Context Protocol (MCP).

> [!IMPORTANT]
> This repository is an early scaffold. It does not authenticate to Proton,
> expose an MCP server, or modify mail yet. Follow [`TODO.md`](TODO.md) for the
> implementation plan and acceptance criteria.

## Intended outcome

The finished project should offer a Gmail-like tool surface for Proton Mail:

- search and read messages and threads;
- inspect headers and download attachments safely;
- create and revise drafts;
- send, reply, reply-all, and forward with explicit side-effect controls;
- archive, move, label, mark, trash, and restore messages;
- wait for mailbox changes without polling aggressively.

The first supported route is expected to be a local Proton Mail Bridge adapter
using IMAP and SMTP. Direct Proton API support is a separate experimental track
that must not ship until its authentication, compatibility, provenance, and
maintenance boundaries are documented.

## Safety model

- Local stdio transport is the default; no network listener is enabled by
  default.
- Read-only tools come first.
- Draft creation is separated from sending.
- Sending and destructive actions require explicit policy and clear MCP tool
  annotations.
- Account passwords, Bridge passwords, session material, message bodies, and
  attachments must never appear in logs or repository fixtures.
- Secrets belong in an operating-system credential store or an explicitly
  approved runtime secret source, never in repository configuration.

## Workspace

```text
crates/
  protonmail-ai-core/  Provider-neutral capability and safety contracts.
  protonmail-ai-mcp/   Future MCP process; currently a non-operational stub.
docs/todo/open/        Typed work records for delegated implementation.
```

The large `reference/` corpus is deliberately local-only and ignored by Git.
It is research material, not vendored product source. See
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features
cargo test --workspace
jig check --root .
```

No live-account test may run unless it is explicitly opted into and isolated
from ordinary unit and integration tests.

## Independence

This is an independent community project. It is not affiliated with, endorsed
by, or sponsored by Proton AG. Proton and Proton Mail are trademarks of their
respective owners.

## License

`protonmail-ai` is licensed under GPL-3.0-only. Third-party material retains its
original license and attribution.
