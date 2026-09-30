# protonmail-ai

Local-first Rust infrastructure for using Proton Mail through a CLI, the Model
Context Protocol (MCP), or an explicitly configured remote service.

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

The intended primary login route is an interactive, visible browser session:
`protonmail-ai auth login` opens Proton's normal login flow and stores the
resulting revocable local session through an approved operating-system secret
store. Supplying credentials through environment variables is a secondary,
less-recommended deployment route and must require explicit configuration.

The implementation may also use Proton Mail Bridge where it provides a more
stable capability. Browser, Bridge, and any direct Proton API integration remain
outbound adapters behind the same provider-neutral mail contract.

## Intended command surface

The completed binary has one installation and several explicit modes:

```text
protonmail-ai auth login       Interactive browser authentication
protonmail-ai mail ...         Human-facing CLI operations
protonmail-ai mcp --stdio      Local MCP server
protonmail-ai serve ...        Explicit remote/cloud service
```

The remote mode is never enabled implicitly and must define authentication,
transport security, tenancy, secret storage, and network binding.

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
src/
  mail/capability/domain/  Provider-neutral capability and safety contracts.
  mail/runtime/composition/  One binary for CLI, MCP, auth, and server modes.
docs/todo/open/        Typed work records for delegated implementation.
tests/                 Product tests outside implementation directories.
```

The large `reference/` corpus is deliberately local-only and ignored by Git.
It is research material, not vendored product source. See
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## Development

```sh
CARGO_TARGET_DIR=.cache/cargo-target cargo fmt --all --check
CARGO_TARGET_DIR=.cache/cargo-target cargo clippy --workspace \
  --all-targets --all-features
CARGO_TARGET_DIR=.cache/cargo-target cargo test --workspace
jig check --root .
```

No live-account test may run unless it is explicitly opted into and isolated
from ordinary unit and integration tests.

## Independence

This is an independent community project. It is not affiliated with, endorsed
by, or sponsored by Proton AG. Proton and Proton Mail are trademarks of their
respective owners.

## License

`protonmail-ai` is currently licensed under GPL-3.0-only out of legal necessity
due to incorporating material from Proton's `WebClients` repository.

This choice is purely regulatory, not ideological. Like Linux, this project is
built to be executed and used: for end users, the license changes nothing and
usage remains entirely free. Code reuse is restricted under GPL terms, but
the source code itself is secondary to the functional tool.

Rather than pretending to perform a clean-room implementation, `WebClients` code
was retained for now. If future development proves that dependency completely
unnecessary, the project will be re-licensed under MIT.

Third-party material retains its original license and attribution.
