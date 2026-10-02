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
The project never deletes Chromium's singleton lock. Its own lease contains only
a PID and Linux process start-time tick value, so it carries no account/session
material and can safely recover a dead owner.

Managed automation now launches the same dedicated profile with Chromium's
private `--remote-debugging-pipe`, inherited only as child file descriptors 3
and 4. It never opens a remote-debugging TCP port. Responses are bounded and
timed out, and provider discovery accepts exactly one Proton Mail/Account page.

The driver re-checks that page from its execution context by evaluating only
`location.protocol`, `location.hostname`, and `location.port`; it never requests
storage, cookies, message data, or authentication values for this check. A
redirect between discovery and verification becomes typed origin drift and
fails closed.

Mail-shell readiness is now translation independent. After the origin check,
the driver reads the DOM root identity and asks Chromium accessibility for only
four roles: `navigation`, `search`, `dialog`, and `alertdialog`. It does not
request the full accessibility tree or use accessible names. Navigation and
search must both be visible, while either dialog role blocks readiness.

The first read-only mailbox slice now takes a stable snapshot of the currently
visible Mail page. It requires a ready Mail shell, reads content-free list state
before and after row projection, and returns data only when provider row IDs are
unchanged in the same order. The snapshot contains only opaque row ID, visible
subject, displayed correspondent addresses, unread state, and observable paging
state; it does not read message bodies or hidden React/Redux state.

Loading, skeleton rows, duplicate IDs, an unproven zero-row state, list changes,
and origin drift all fail closed. Empty subject is valid. Snapshot `Debug`
formatting redacts row IDs, subjects, and addresses so ordinary diagnostics do
not accidentally disclose mailbox metadata.

The adapter now has a narrower message-only proof for provider states where
WebClients itself forces individual-message rendering: Drafts, All drafts, Sent,
All sent, Deleted, and active searches. The browser execution context reduces
its own route/search state to two booleans; pathname, hash, search terms, and
opened-element IDs are never returned over CDP for this proof.

`read_visible_message_page` requires that proof before the visible-row snapshot
and again afterward. Ordinary Inbox/Archive/etc. remain `Unknown`, because the
user's Conversation grouping preference can change their semantics.

For proven message-mode pages, `read_next_visible_message_page` can advance one
page through Mail's locale-independent `pagination-row:go-to-next-page` button.
It requires an explicit current page, an enabled Next control, a successful
control recheck at click time, message mode throughout the transition, and a
settled page number exactly one greater than before. Origin drift, control
drift, page jumps, or missing current-page evidence fail closed.
This changes only the visible browser page; it does not target a mailbox
mutation control.

The adapter can now prove the visible Mail sort without changing it. It opens
`filter-dropdown:show-filters` only when needed, reads `aria-pressed` from the
four locale-independent sort test IDs, and restores the menu only when the
adapter opened it. It never clicks a sort option. `toolbar:sort-new-to-old`
therefore proves the provider's semantic newest-first selection.

Mailbox and label inventory now has a separate passive path. The driver captures
Mail's complete browser-owned system-folder, custom-folder, and message-label
catalog once, reduces it to bounded provider metadata, and can page the retained
immutable snapshot locally without another provider read. Continuation cursors
are authenticated and confidential, and bind account, browser generation,
catalog kind, page size, snapshot boundary, and next offset. Starting a newer
chain of the same kind expires the older snapshot; mailbox and label snapshots
remain independent.

This is adapter-level paging evidence, not yet a public `list_mailboxes` or
`list_labels` wire implementation. Raw system-folder `Name` is provider
metadata: current WebClients builds localized system-folder display text
separately with `ttag`.

Single-message reads now have a separate content-minimizing response boundary.
Current WebClients loads an uncached message with exact
`GET mail/v4/messages/{messageID}`; the adapter can classify that lifecycle and
project only bounded message/conversation identity, envelope recipients,
subject,
provider time/read state, label IDs, MIME type, and attachment descriptors.

That projector deliberately drops message body, raw and parsed headers, password
fields, key packets, signatures, attachment bytes, and unrelated provider
fields.
It is not yet a public `get_message` implementation: WebClients can satisfy an
already-cached body without issuing the detail GET, and plaintext body/header
and
attachment-decryption paths still need independently bounded browser evidence.

That still is not enough to advertise provider-neutral `list_messages`. The
public contract requires `received_at` descending, ID ascending as the tie
breaker, and a cursor-bound snapshot. The visible DOM date remains localized,
but the bounded Network projection now supplies numeric `Message.Time`, which
WebClients itself treats as the message receive time, and reconciles it to the
stable rendered IDs.

The adapter now has an explicit diagnostic Network observation for proven
message-mode pages. It enables CDP Network tracking with request POST-body
capture disabled, caps each retained response body at 256 KiB, reloads the page,
and classifies unsolicited events inline without queueing them. Only one exact
`GET /api/mail/v4/messages` request that reaches HTTP 200 JSON and
`loadingFinished` may be selected; `Network.getResponseBody` is then projected
immediately to message ID, numeric `Time`, provider `Order`, and total. Encoded,
malformed, oversized, redirected, or ambiguous observations fail closed, and
Network tracking is disabled before mode and origin are revalidated.

The adapter also has a provider-neutral reconciliation model for combining
non-overlapping observed list batches with a stable visible message-ID sequence.
`VisibleMessagePageSnapshot::reconcile_metadata` now supplies that sequence
straight from the already stable message-mode snapshot, so arbitrary caller IDs
cannot substitute for rendered evidence. It preserves visible-row order, allows
extra prefetched provider IDs, and fails closed for duplicate visible IDs,
overlapping provider batches, missing visible metadata, or an explicit-empty
contradiction. `Debug` output exposes only the reconciled row count.

The driver can now couple those pieces in one diagnostic call; its Network
observer recognizes WebClients-shaped initial requests (`Page`, `PageSize`,
`Limit`, `Sort`, and `Desc`) and the one anchor continuation used by the current
two-batch query loop. Recognized provider sort keys are reduced to `Time`,
`SnoozeTime`, or `Size`; direction is reduced to one boolean, while all
remaining non-pagination query pairs are compared through per-capture randomized
fingerprints so label/search/filter drift fails closed without retaining query
terms and request/response context must agree; if batch 1 fills its sanitized
`Limit`, the continuation's numeric
`Anchor` and bounded `AnchorID` must equal batch 1's last projected message
`Time` and ID before its body is read. `Network.getResponseBody` keeps
classifying Network events inline while the continuation starts, then captures
batch 2 before disabling Network. The initial zero-based request `Page` is
retained as numeric metadata and must match the stable visible page's one-based
pagination evidence before reconciliation; an absent page number is accepted
only for request page zero with no Next control; a fresh stable visible
message-page snapshot in the same target session is then reconciled only
against the first serialized batch because WebClients assigns its continuation
batch to page `N+1`; prefetched IDs can validate continuation integrity but
cannot satisfy visible page `N` metadata coverage.

This removes the machine-readable receive-time blocker without changing the
public capability decision; visible “Newest first” does not itself prove the
provider request is `Sort=Time&Desc=1`: current WebClients maps Inbox/Snoozed to
`SnoozeTime`, while Scheduled can reverse the `Time` direction. Readiness now
consumes the sanitized Network ordering evidence: exact
`Sort=Time&Desc=1` clears the temporary provider-sort blocker, while
`SnoozeTime`, ascending `Time`, or any non-newest visible sort remains gated.
For declared `Time` ordering, projected rows are also checked for monotonic
`Time` and provider `Order` within and across captured batches, so a query/body
ordering contradiction fails closed; the initial response `Total` must also
cover the zero-based page offset and exact captured batch lengths, while
continuation `Total` values remain ignored because WebClients treats them as
anchor-affected. Provider `Order` remains validation evidence rather than the
contract tie-break; for page 0, however, the adapter can bound ID normalization
when the result fits one batch or batch 2 starts at a different `Time`, while a
same-time boundary keeps the tie-break blocker and immutable snapshot evidence
remains required in every case.

Snapshot research now also has a separate bounded projection for Mail's legacy
core event loop. Exact core-v5 event responses are reduced to opaque request and
response watermarks plus settled/refresh and mailbox-change-presence state;
event
payload contents never escape that boundary. Its same-session CDP classifier
tracks only exact core-v5 GET lifecycles and fails closed on redirects, bad
responses, request failure, lifecycle drift, or bounded-capacity exhaustion.
This is not wired into list readiness until passive before/after capture
ordering
and server guarantees are proven.

The relevant sort/date/order files remain byte-identical in current WebClients
`main@c51e81b3730a5e1084586b383d837947f7636c16` and the pinned research
snapshot,
so this refusal is based on current provider behavior rather than stale source.
The adapter still does not claim `list_threads`; broader read/composer/mutation
workflows remain open.

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
