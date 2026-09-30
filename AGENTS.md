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

## Non-negotiable boundaries

- Never commit account credentials, Bridge credentials, cookies, access or
  refresh tokens, session blobs, private keys, real messages, or attachments.
- Never log message bodies or secret-bearing protocol payloads.
- Keep read, draft, send, and destructive capabilities separate.
- Default to local stdio transport and loopback-only test infrastructure.
- Do not copy from `reference/` without recording the exact source, revision,
  file-level origin, license, and modifications in `THIRD_PARTY_NOTICES.md`.
- GPL WebClients-derived code must retain compatible licensing and attribution.
- Test fixtures must be synthetic.
- Avoid unaudited browser automation as an authentication shortcut.

## Validation

Run the narrowest relevant checks while iterating, then before handoff run:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features
cargo test --workspace
jig check --root .
```

If Jig onboarding is still open, use its advisory mode and report that fact;
do not fabricate repository policy merely to make validation green.
