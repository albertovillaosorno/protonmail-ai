# protonmail-ai TODO

Only unfinished work appears here. Each item links to the typed record that owns
its dependencies, constraints, acceptance criteria, and evidence. Complete one
record at a time; a compiling placeholder is not completion.

## Completion invariant

An empty TODO means the released binary has been installed from scratch,
authenticated through Proton's visible login flow, configured in a real MCP
client, and used against an opt-in live account for every advertised capability.
Mocks, schemas, or a compiling transport alone can never satisfy that invariant.

## P0 — Authority, architecture, and safety

### TODO - Select the supported connectivity architecture

Decide and prove the interactive browser-login route, Bridge compatibility, and
direct API boundary behind one provider-neutral mail contract.

[architecture-and-auth](docs/todo/open/architecture-and-auth.mdc)

### TODO - Complete the credential and side-effect threat model

Define secret storage, redaction, trust boundaries, failure modes, confirmation
policy, and recovery behavior before handling real mail.

[security-model](docs/todo/open/security-model.mdc)

### TODO - Freeze the Gmail-parity MCP contract

Specify tool schemas, pagination, stable identifiers, annotations, error
semantics, and capability boundaries independently of the provider adapter.

[tool-contract](docs/todo/open/tool-contract.mdc)

## P1 — Working local mail path

### TODO - Implement interactive authentication and session custody

Open Proton's normal login flow, let the user complete all challenges, keep the
result out of MCP traffic, and support status, expiry, refresh, and revocation.

[interactive-auth-and-session](docs/todo/open/interactive-auth-and-session.mdc)

### TODO - Implement the browser-session Proton adapter

Use the accepted authenticated browser boundary as the primary provider path,
with bounded requests, typed failures, capability detection, and no DOM scraping
where a stable authenticated protocol boundary is available.

[browser-session-adapter](docs/todo/open/browser-session-adapter.mdc)

### TODO - Implement the Proton Mail Bridge adapter

Build the local IMAP/SMTP adapter with TLS policy, credential isolation,
timeouts, bounded concurrency, and provider-neutral conversion.

[bridge-adapter](docs/todo/open/bridge-adapter.mdc)

### TODO - Implement read-only mailbox workflows

Deliver list, search, message, thread, header, attachment, label, and folder
queries before any write capability is enabled.

[read-workflows](docs/todo/open/read-workflows.mdc)

### TODO - Implement draft and send workflows

Separate draft construction from send, reply, reply-all, and forward, with
explicit side-effect controls and idempotency behavior.

[draft-and-send](docs/todo/open/draft-and-send.mdc)

### TODO - Implement reversible mailbox actions

Add read state, labels, archive, move, trash, and restore before considering
permanent deletion.

[mailbox-actions](docs/todo/open/mailbox-actions.mdc)

### TODO - Implement mailbox change observation

Expose bounded waiting and resumable change cursors without aggressive polling,
silent gaps, or an always-running public service.

[mailbox-events](docs/todo/open/mailbox-events.mdc)

## P2 — Productization and evidence

### TODO - Implement the local MCP transport

Expose the accepted contract over stdio by default, with no implicit public
listener and with capability-aware tool annotations.

[mcp-transport](docs/todo/open/mcp-transport.mdc)

### TODO - Implement the CLI and one-command local setup

Complete the human CLI, diagnostics, authentication lifecycle, and MCP-client
setup in the same installable binary.

[cli-and-setup](docs/todo/open/cli-and-setup.mdc)

### TODO - Implement the explicit remote service

Add an opt-in authenticated remote transport with TLS, tenancy isolation,
revocation, rate limits, and a proven cloud deployment path.

[remote-service](docs/todo/open/remote-service.mdc)

### TODO - Build synthetic and opt-in integration evidence

Create deterministic fake-server coverage and a separately gated live-account
suite that cannot run accidentally.

[integration-evidence](docs/todo/open/integration-evidence.mdc)

### TODO - Package and document the first release

Provide reproducible binaries, checksums, install instructions, Codex setup,
upgrade behavior, and an explicit compatibility matrix.

[release-packaging](docs/todo/open/release-packaging.mdc)
