# protonmail-ai TODO

Only unfinished work appears here. Each item links to the typed record that owns
its dependencies, constraints, acceptance criteria, and evidence. Complete one
record at a time; a compiling placeholder is not completion.

## Completion invariant

An empty TODO means the released binary has been installed from scratch,
authenticated through the primary user-controlled provider flow, configured in
a real MCP client, and used against an opt-in live account for every advertised
capability.
Mocks, schemas, or a compiling transport alone can never satisfy that invariant.

A first supported local release does not require optional direct-API or remote
service records to be complete when those modes are not advertised. The empty
TODO invariant is stronger: it means the full tracked roadmap is complete.

## P1 — Working local mail path

### TODO - Implement the user-controlled Proton Mail web adapter

Use Proton Mail's ordinary web application with a dedicated project browser
profile and visible manual login. This is the primary Free-plan path and does
not require Mail Bridge or a third-party direct API identity.

[web-ui-adapter](docs/todo/open/web-ui-adapter.mdc)

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

## P2 — Optional direct protocol, productization, and evidence

### TODO - Track a third-party Proton Mail client identity

Keep the optional direct API/session-fork path fail-closed unless Proton later
documents or issues a third-party Mail identity. This no longer blocks the
primary Free-plan web UI path.

[provider-client-identity](docs/todo/open/provider-client-identity.mdc)

### TODO - Implement optional QR/manual-code session-fork authentication

Implement the direct session-fork flow only when a valid third-party Mail
identity exists. This is an optional protocol path, not a prerequisite for the
primary local product.

[interactive-auth-and-session](docs/todo/open/interactive-auth-and-session.mdc)

### TODO - Implement the optional direct-session Proton adapter

Use fork-established Proton authority for direct protocol access when available,
without making it a prerequisite for Free-plan users.

[direct-session-adapter](docs/todo/open/direct-session-adapter.mdc)

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

Create deterministic fake-provider coverage and a separately gated live-account
suite that cannot run accidentally.

[integration-evidence](docs/todo/open/integration-evidence.mdc)

### TODO - Package and document the first release

Provide reproducible binaries, checksums, install instructions, Codex setup,
upgrade behavior, and an explicit compatibility matrix.

[release-packaging](docs/todo/open/release-packaging.mdc)
