# Agent operating contract

## Start here

Read `README.md`, `TODO.md`, `SECURITY.md`, and `THIRD_PARTY_NOTICES.md` before
editing. This repository begins as a scaffold, not as a working mail client.

## Work selection

1. Select one open record linked from `TODO.md` whose dependencies are complete.
2. Keep the change inside that record's scope.
3. Add the acceptance evidence named by the record.
4. Move a completed record from `docs/todo/open/` to `docs/todo/completed/` and
   remove it from `TODO.md` only when every criterion is satisfied.
5. Do not mark a task complete because a placeholder compiles.
6. Do not declare the product complete until the root TODO is empty and the
   installed release passes the redacted live-account acceptance path through a
   real MCP client. Internal APIs, mocks, and schema tests are insufficient.

All commits must use the configured Conventional Commit grammar and include an
exact DCO `Signed-off-by: Name <email>` trailer. Use `git commit -s`; never
invent another person's sign-off.

## Non-negotiable boundaries

- Never commit account credentials, fork handoff secrets, cookies, access or
  refresh tokens, session blobs, private keys, real messages, or attachments.
- Never log message bodies or secret-bearing protocol payloads.
- Keep read, draft, send, and destructive capabilities separate.
- Default to local stdio transport and loopback-only test infrastructure.
- Treat the user-controlled Proton Mail web application as the primary
  version-one provider boundary for Free-plan users.
- Keep the optional direct Mail API/session-fork path disabled until Proton
  documents or issues a third-party client identity; never reuse a Proton-owned
  Mail client ID.
- A `ThirdPartyIdentityCandidate` proves only negative validation; never treat
  it as provider approval or as permission to enable live HTTP.
- `ProviderProfile::live_auth_supported()` must stay derived from the typed
  provider-authorization snapshot; never reintroduce an independent live flag.
- Every optional direct-API Proton request must carry an `Approved`
  `ProviderRequestIdentity`; that transport must obtain app-version and API
  base only through live accessors and reject `None` before network I/O.
- Treat environment-supplied credentials as an explicit, less-recommended
  deployment fallback; never accept them through MCP tool arguments.
- Do not copy from `reference/` without recording the exact source, revision,
  file-level origin, license, and modifications in `THIRD_PARTY_NOTICES.md`.
- GPL WebClients-derived code must retain compatible licensing and attribution.
- Test fixtures must be synthetic.
- Web-composer handoff URLs may contain recipients, subject, and body text;
  emit them only on explicit user request and never treat them as safe logs.
- `mail compose-url --body-file` is a human CLI file-read boundary; never
  expose an arbitrary body-file path as an MCP tool argument.
- A web UI adapter may automate only a dedicated project browser profile after
  visible user-controlled login. Never attach to an existing personal profile,
  automate password/2FA/CAPTCHA/recovery input, or export cookies/web storage.
- Keep one installable `protonmail-ai` binary with explicit `auth`, `mail`,
  `mcp`, and `serve` modes; do not create separately installed products.
- Keep external authentication handoff, provider access, application workflows,
  and transports as distinct boundaries even though they ship in one binary.
- Declare every reusable Cargo dependency in root `[workspace.dependencies]`;
  member crates must inherit it with `workspace = true`.
- When a workspace dependency needs a version, pin the newest stable release
  compatible with the pinned Rust toolchain and verify it manually before
  committing. Do not add abbreviated or intentionally stale version ranges.
- Dependabot, Renovate, and equivalent automated dependency-update bots are
  prohibited in this repository. Keep dependency updates explicit and reviewed.

## Validation

Run the narrowest relevant checks while iterating, then before handoff run:

```sh
CARGO_TARGET_DIR=.cache/cargo-target cargo fmt --all --check
CARGO_TARGET_DIR=.cache/cargo-target cargo clippy --workspace \
  --all-targets --all-features
CARGO_TARGET_DIR=.cache/cargo-target cargo test --workspace
jig check --root .
```
