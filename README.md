# protonmail-ai

**Proton Mail automation for AI agents, designed as a security boundary rather
than a credential shortcut.**

`protonmail-ai` is a local-first Rust project for using Proton Mail through a
CLI, the Model Context Protocol (MCP), or an explicitly configured remote
service. The premise is simple: an AI client should never need your Proton
password, and *send mail* should never look like *read mail*.

> [!IMPORTANT]
> This repository is an early scaffold. It does not authenticate to Proton,
> expose an MCP server, or modify mail yet. It can already generate prefilled
> Proton Mail web-composer URLs with `mail compose-url`. Follow
> [`TODO.md`](TODO.md) for the remaining implementation plan.

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

- [`connectivity.mdc`](docs/architecture/connectivity.mdc) selects the
  user-controlled Proton Mail web application as the primary Free-plan path,
  keeps Bridge out of the runtime, and leaves direct session-fork as an optional
  protocol track behind its own authorization gate;
- [`provider-client-registration.mdc`][provider-registration]
  records the current blocker for the optional direct API/session-fork path;
  it no longer blocks the primary web UI adapter;
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

The intended version-one provider route is Proton Mail's ordinary web
application in a dedicated project browser profile. Login remains visible and
manual in Proton's own UI; automation begins only after the expected signed-in
Mail state is present. This route is designed for Free-plan users and does not
require Mail Bridge or a third-party direct API client identity.

The direct session-fork implementation remains an optional protocol track. Its
live networking stays fail-closed until Proton documents or issues a suitable
third-party Mail identity. The project will not substitute `ios-mail`,
`android-mail`, `web-mail`, or another Proton-owned ID to bypass that check.


## Available now: visible dedicated-profile login

`protonmail-ai auth login` opens Proton Mail in a project-owned Chromium profile
for visible, manual sign-in. On Linux the profile lives under
`$XDG_DATA_HOME/protonmail-ai/browser-profile`, falling back to
`$HOME/.local/share/protonmail-ai/browser-profile` when XDG data home is absent
or invalid. The project and profile directories are restricted to mode `0700`.

The launcher does not accept an arbitrary profile path, attach to an existing
browser profile, enable remote debugging, or read password, second-factor,
CAPTCHA, recovery, cookie, or web-storage values. Profile and project-directory
symlinks fail closed. `PROTONMAIL_AI_BROWSER` may explicitly select the browser
executable; otherwise a supported Chromium-family executable is discovered on
`PATH`.

This command currently launches the safe login surface only. Managed automation
uses a separate exclusive lease and refuses to start while Chromium's
`SingletonLock` identifies a live local Chrome-family process or foreign host.
The
project never deletes Chromium's singleton lock. Its own lease contains only a
PID and Linux process start-time tick value, so it carries no account/session
material and can safely recover a dead owner.

The adapter now also defines the post-login readiness contract: a page is
considered authenticated Mail only when its normalized browser origin is
`https://mail.proton.me` and the expected Mail shell is visible. Proton Account
login/challenge pages, foreign hosts, missing shell state, and unexpected
blockers all fail closed. A browser driver still has to extract those semantic
signals and drive real mailbox workflows; that remains in `web-ui-adapter`.

## Available now: prefilled web composer

The binary can generate Proton Mail's own web-composer handoff without
accessing a mailbox or sending anything:

```text
protonmail-ai mail compose-url --to RECIPIENT \
  --subject "Interview follow-up" --body-file ./message.txt
```

The result is a `https://mail.proton.me/inbox/#mailto=...` URL. Open it in an
already signed-in Proton Mail browser session to get a prefilled composer. The
pinned WebClients implementation accepts To, Cc, Bcc, subject, and body fields;
this command preserves `+` aliases, Unicode, and body line breaks.

`--body-file` is preferred for longer messages so the body does not need to be
placed directly in the command arguments. Bodies are bounded to 16 KiB. The
generated URL itself still contains the composition data, so treat it like
message content: do not put it in logs or bug reports.

`--body-file` is a human CLI boundary and is not an MCP file-read capability.
This handoff creates no
send side effect; the current user must still review the composer and choose
Send.

## Intended command surface

The completed binary has one installation and several explicit modes:

```text
protonmail-ai auth login       Open dedicated profile for visible login
protonmail-ai mail compose-url Prefilled Proton Mail web composer URL
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
- The primary web adapter may automate only a dedicated project browser
  profile after visible manual login; it never attaches to a personal profile
  or automates password, 2FA, CAPTCHA, recovery, or security-key input.
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
  mail/web/adapter-outbound/   Dedicated web profile and semantic UI gate.
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

[provider-registration]: docs/architecture/provider-client-registration.mdc
