# protonmail-ai TODO

Only unfinished work appears here. Each item links to the typed record that owns
its dependencies, constraints, acceptance criteria, and evidence. Complete one
record at a time; a compiling placeholder is not completion.

## P0 — Authority, architecture, and safety

### TODO - Select the supported connectivity architecture

Decide and prove the initial Proton Mail Bridge route, explicitly separating it
from any future direct Proton API adapter.

[architecture-and-auth](docs/todo/open/architecture-and-auth.mdc)

### TODO - Pin provenance and license evidence

Capture immutable revisions and file-level origin rules for every admissible
reference before external code is adapted.

[provenance-and-licenses](docs/todo/open/provenance-and-licenses.mdc)

### TODO - Complete the credential and side-effect threat model

Define secret storage, redaction, trust boundaries, failure modes, confirmation
policy, and recovery behavior before handling real mail.

[security-model](docs/todo/open/security-model.mdc)

### TODO - Freeze the Gmail-parity MCP contract

Specify tool schemas, pagination, stable identifiers, annotations, error
semantics, and capability boundaries independently of the provider adapter.

[tool-contract](docs/todo/open/tool-contract.mdc)

### TODO - Complete Jig repository onboarding

Promote a reviewed repository-specific Jig policy after the Rust scaffold and
documentation surfaces are stable.

[jig-onboarding](docs/todo/open/jig-onboarding.mdc)

## P1 — Working local mail path

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

## P2 — Productization and evidence

### TODO - Implement the local MCP transport

Expose the accepted contract over stdio by default, with no implicit public
listener and with capability-aware tool annotations.

[mcp-transport](docs/todo/open/mcp-transport.mdc)

### TODO - Build synthetic and opt-in integration evidence

Create deterministic fake-server coverage and a separately gated live-account
suite that cannot run accidentally.

[integration-evidence](docs/todo/open/integration-evidence.mdc)

### TODO - Package and document the first release

Provide reproducible binaries, checksums, install instructions, Codex setup,
upgrade behavior, and an explicit compatibility matrix.

[release-packaging](docs/todo/open/release-packaging.mdc)
