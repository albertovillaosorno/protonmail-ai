# Contributing

This project is in architecture-first bootstrap. Contributions should complete
one typed record linked from `TODO.md` instead of adding disconnected features.

Before opening a change:

1. preserve the security boundaries in `AGENTS.md`;
2. record third-party provenance before adapting external code;
3. keep fixtures synthetic;
4. add tests that prove the relevant acceptance criteria;
5. run the validation commands documented in `AGENTS.md`.

Every commit must use the configured Conventional Commit grammar and certify
the Developer Certificate of Origin with an exact `Signed-off-by: Name
<email>` trailer. The ordinary command is:

```sh
git commit -s -m "type(scope): concise description" \
  -m "Explain the reason for the change."
```

Jig's `commit-msg` hook rejects a malformed subject, a missing or malformed
sign-off, an empty body, and body or subject lines beyond the configured limit.

By contributing, you agree that your contribution is licensed under
GPL-3.0-only.
