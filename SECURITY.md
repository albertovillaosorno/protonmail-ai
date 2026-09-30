# Security policy

## Current status

There is no supported release yet. The repository is a non-operational scaffold
and must not be connected to a production mailbox.

## Reporting

Please report suspected vulnerabilities privately to
`avillaosorno@protonmail.com`. Do not include real credentials, session tokens,
private messages, or attachments in the initial report.

## Credential rules

- Proton account passwords are never accepted by the MCP process.
- Bridge credentials must remain local and be loaded from an approved secret
  source at runtime.
- Secret values must be redacted structurally before diagnostics are emitted.
- Tests use synthetic accounts and messages only.
- Live integration tests are opt-in, isolated, and excluded from default test
  commands.

## Side effects

Read, draft, send, and destructive operations are distinct capabilities.
Permanent deletion is disabled until the tool contract, confirmation policy,
and recovery behavior have dedicated tests.
