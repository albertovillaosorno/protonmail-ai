# Third-party notices

## Distribution boundary

The initial public repository contains original Rust scaffold code and no
vendored third-party implementation. A local, Git-ignored `reference/` directory
contains research snapshots. Those snapshots are not part of the repository,
release artifacts, or project license grant.

Before any external code is incorporated, record the exact upstream URL,
immutable revision, source paths, destination paths, original license, retained
copyright notices, and substantive modifications here.

## Local reference inventory

### Proton WebClients

- Upstream: <https://github.com/ProtonMail/WebClients>
- Revision: `74773f0b10cc31d32e43e82c061da5d75fef96ce`
- License: GPL-3.0
- Initial use: protocol and behavior research only

### amotivv ProtonMail MCP

- Upstream: <https://github.com/amotivv/protonmail-mcp>
- Revision: `fdca87e7a0615c21a2b7a4b411e39c93399ab7ec`
- License: MIT
- Initial use: MCP surface research only

### millsymills ProtonMail MCP

- Upstream: <https://github.com/millsymills-com/protonmail-mcp>
- Revision: `8fdcb76d2f503a0bee874c2db518da36ceef22fe`
- License: MIT
- Initial use: direct-client and MCP research only

### Barhatch ProtonMail MCP Server

- Upstream: <https://github.com/barhatch/protonmail-mcp-server>
- Revision: `653322c7cf5987b004fcbbd8ea0b3d6db874d5eb`
- License: MIT
- Initial use: Bridge and MCP research only

### googlarz Proton Mail Bridge Client

- Upstream: <https://github.com/googlarz/proton-mail-bridge-client>
- Revision: `47fc10007d7e84ce55cd5321e8b3bf9409025880`
- License: MIT
- Initial use: Bridge workflow research only

### robotben ProtonMail MCP

- Upstream: <https://github.com/robotben/protonmail-mcp>
- Revision: `dc638cc367323f81d50c07e53db4e4beabf56f33`
- License: MIT, declared in `package.json` and the README
- Initial use: tool-taxonomy research only
- Local license receipt: upstream omits a `LICENSE` file, so the standard MIT
  text was added locally with `Copyright (c) 2025 Ben Larson`, matching the
  original commit author and year. This receipt documents upstream intent; it
  is not represented as an upstream-authored file.

### roman Proton CLI

- Upstream: <https://github.com/roman-16/proton-cli>
- Revision: `1d5f0a54f215388743ef1b13044661896a4828f7`
- License: MIT
- Initial use: Proton protocol research only

### Seth Bangert Proton Mail MCP

- Upstream: <https://github.com/sethbang/proton-mail-mcp>
- Revision: `db671d9592f85b3b4f4ae6c32a27021258332abc`
- License: MIT
- Initial use: safety and workflow research only

### Chromium DevTools pipe

- Upstream: <https://github.com/chromium/chromium>
- Revision: `e972c575b9a075ab5dcadddf269d60bb23d4af35`
- License: BSD-3-Clause
- Initial use: DevTools pipe descriptor/framing and CDP Network behavior
  research only
- Verified files: `components/devtools/devtools_pipe/devtools_pipe.h` and
  `content/browser/devtools/devtools_pipe_handler.cc`

### svgrepus Proton Mail MCP

- Upstream: <https://github.com/svgrepus/proton-mail-mcp>
- Revision: `1e40387ce6ce0d5a76f6c1682176d4c2b1376c6d`
- License: MIT
- Initial use: MCP research only


## Distributed runtime dependencies

### command-fds

- Upstream: <https://github.com/google/command-fds>
- Version: `0.3.3`
- License: Apache-2.0
- Use: unchanged Cargo dependency for mapping the private Chromium DevTools
  pipe onto child file descriptors 3 and 4.

### nix

- Upstream: <https://github.com/nix-rust/nix>
- Version: `0.31.3`
- License: MIT
- Use: unchanged Cargo dependency with the `fs` feature for safe
  descriptor-relative attachment output operations such as `openat`, `linkat`,
  and `unlinkat`.

## Reference verification

On 2026-09-29 every retained upstream file was compared with the recursive
GitHub tree for its pinned revision using Git blob identifiers. All retained
files matched. The only excluded local file was the documented `robotben`
`LICENSE` receipt, which is intentionally absent upstream.

The exact retained-file counts and verification metadata are tracked in
`docs/provenance/sources.txt`. The snapshots remain intentionally pruned and
Git-ignored; this verification does not make them distributed product source.

## Provenance policy

`docs/provenance/files.txt` classifies every governed file under `src/` and
`tests/`. A file is `original` when its expression originates in this project,
`fact-informed` when only protocol or behavior facts came from an external
source, and `adapted` when external expression was copied or modified.

Protocol facts and copied expression are deliberately different categories.
Learning that a field, endpoint, state transition, or interoperability rule
exists does not copy expression; translating or modifying source text or code
does, and therefore requires an `adapted` record.

An `adapted` or `fact-informed` row must identify the source and immutable
revision, plus the source path. An `adapted` row must also record the upstream
license and a meaningful modification note instead of treating `reference/` as
implicit provenance.

Before an adapted file can ship, its source row must name a tracked
`distribution_license` containing the upstream license text. The corresponding
copyright and attribution must also appear in this notice; ignored files under
`reference/` never satisfy a distribution obligation by themselves.

The repository-level provenance test requires every governed implementation and
test file to have exactly one classification. It also verifies immutable source
revisions, human-readable notices, and the license evidence required before any
adapted expression can enter the product.

## License choice

The project is GPL-3.0-only so future, explicitly reviewed adaptation of Proton
WebClients GPL-3.0 material remains possible. MIT-licensed material may be
incorporated under GPL-3.0-only while its original notices and license terms are
preserved for the incorporated portions.
