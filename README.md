# protonmail-ai

**Proton Mail automation for AI agents, designed as a security boundary rather
than a credential shortcut.**

`protonmail-ai` is a local-first Rust project for using Proton Mail through a
CLI, the Model Context Protocol (MCP), or an explicitly configured remote
service. The premise is simple: an AI client should never need your Proton
password, and *send mail* should never look like *read mail*.

> [!IMPORTANT]
> This repository is an early scaffold. It does not authenticate to Proton,
> expose an MCP server, or modify mail yet. Follow [`TODO.md`](TODO.md) for the
> implementation plan and acceptance criteria.

## Why this exists

Most mail automation gets easy by collapsing trust boundaries. This project
chooses the opposite direction: visible authentication, local session custody,
provider-neutral tools, explicit side-effect classes, and evidence that can be
audited before a capability is advertised.

The target is not merely "an MCP wrapper around Proton." It is one installable
binary with a narrow, inspectable authority model:

- **local-first by default** — stdio first, no surprise network listener;
- **human-controlled authentication** — Proton-owned login surfaces retain
  passwords, 2FA, CAPTCHA, security-key, and recovery challenges;
- **least privilege by construction** — read, reversible mutation, send, and
  destructive authority stay separate;
- **provider-neutral behavior** — the direct Proton adapter must prove the same
  public contract instead of leaking provider quirks;
- **auditable failure modes** — opaque IDs, bounded retries, redacted secrets,
  deterministic fixtures, and explicit ambiguous outcomes.

## Design already frozen

The codebase is still pre-provider, but the dangerous decisions are not being
left for the end:

- [`connectivity.mdc`](docs/architecture/connectivity.mdc) selects Proton's
  direct session-fork login with the third-party `Other` identity and rejects
  credential replay, Bridge, and browser automation;
- [`threat-model.mdc`](docs/security/threat-model.mdc) separates observation,
  reversible mutation, external side effects, and disabled destructive access;
- [`tool-contract-v1.mdc`](docs/contract/tool-contract-v1.mdc) freezes a
  29-operation provider-neutral surface with opaque IDs, cursor semantics,
  stable errors, bounded batches, and explicit ambiguous-send behavior;
- the repository gate rejects untracked provenance, member-local dependency
  versions, vague dependency ranges, and automated dependency-update bots.

That means implementation work has to conform to an accepted security and wire
contract instead of inventing authority rules while handling a live mailbox.

## Intended outcome

The finished project should offer a Gmail-like tool surface for Proton Mail:

- search and read messages and threads;
- inspect headers and download attachments safely;
- create and revise drafts;
- send, reply, reply-all, and forward with explicit side-effect controls;
- archive, move, label, mark, trash, and restore messages;
- wait for mailbox changes without polling aggressively.

The supported version-one provider route is direct Proton session access.
`protonmail-ai auth login` starts Proton's session-fork flow, generates a fresh
short-lived QR/manual-code handoff, and waits for approval from an already
authenticated Proton session.

As a convenience, it may open the normal Proton Account site so the browser can
act as the origin: the user signs in there and enters the target code through
Proton's own **Sign in on another device** UI. The CLI never reads browser state
or receives the account password or second factor. After approval, it stores
only the resulting revocable session and key authority required to unlock the
mailbox locally.

The child client identity is the third-party `Other` identity used by Proton's
Mail session SDK, not a borrowed `ios-mail`, `android-mail`, or `web-mail` ID.
A browser wrapper can be added if Proton publishes a third-party Mail desktop
identity; until then the QR/manual-code flow is the honest direct handoff.

## Intended command surface

The completed binary has one installation and several explicit modes:

```text
protonmail-ai auth login       Direct QR/manual-code session fork
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
- No Playwright, bundled Chromium, browser-profile scraping, or official-client
  impersonation is accepted as a login mechanism.
- Account passwords, handoff secrets, session material, message bodies, and
  attachments must never appear in logs or repository fixtures.
- Secrets belong in an operating-system credential store or an explicitly
  approved runtime secret source, never in repository configuration.

## Workspace

```text
src/
  mail/auth/adapter-outbound/  Proton session-fork handoff boundary.
  mail/auth/domain/            Secret-free authentication session state rules.
  mail/capability/contract/  Serialized, versioned public tool contract.
  mail/capability/domain/    Provider-neutral capability and safety rules.
  mail/runtime/composition/  One binary for CLI, MCP, auth, and server modes.
docs/todo/open/          Typed work records for delegated implementation.
tests/                   Product tests outside implementation directories.
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

Every member crate inherits dependencies from root `[workspace.dependencies]`.
External dependency versions are declared only there and track the newest stable
release supported by the pinned Rust toolchain. The repository test suite
rejects member-local dependency versions, paths, or Git sources. The dated
registry check lives in
[`verified-latest.mdc`](docs/dependencies/verified-latest.mdc).

## Independence

This is an independent community project. It is not affiliated with, endorsed
by, or sponsored by Proton AG. Proton and Proton Mail are trademarks of their
respective owners.

## License

`protonmail-ai` is currently licensed under GPL-3.0-only so that any future,
explicitly reviewed adaptation from Proton's GPL-3.0 `WebClients` repository
remains license-compatible. The tracked scaffold does not currently vendor the
local reference corpus or claim that research material as original code.

This choice is purely regulatory, not ideological. Like Linux, this project is
built to be executed and used: for end users, the license changes nothing and
usage remains entirely free. Code reuse is restricted under GPL terms, but
the source code itself is secondary to the functional tool.

Rather than pretending that future implementation must be clean-room,
`WebClients` remains an admissible, auditable source under GPL terms. If future
development proves that dependency completely unnecessary, the project may be
re-licensed under MIT.

Third-party material retains its original license and attribution.
