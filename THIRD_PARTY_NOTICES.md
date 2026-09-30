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
- License: GPL-3.0
- Initial use: protocol and behavior research only

### amotivv ProtonMail MCP

- Upstream: <https://github.com/amotivv/protonmail-mcp>
- License: MIT
- Initial use: MCP surface research only

### millsymills ProtonMail MCP

- Upstream: <https://github.com/millsymills-com/protonmail-mcp>
- License: MIT
- Initial use: direct-client and MCP research only

### Barhatch ProtonMail MCP Server

- Upstream: <https://github.com/barhatch/protonmail-mcp-server>
- License: MIT
- Initial use: Bridge and MCP research only

### googlarz Proton Mail Bridge Client

- Upstream: <https://github.com/googlarz/proton-mail-bridge-client>
- License: MIT
- Initial use: Bridge workflow research only

### robotben ProtonMail MCP

- Upstream: <https://github.com/robotben/protonmail-mcp>
- Observed revision: `dc638cc367323f81d50c07e53db4e4beabf56f33`
- License: MIT (declared in `package.json` and the README)
- Local license receipt: upstream omits a `LICENSE` file, so the standard MIT
  text was added locally with `Copyright (c) 2025 Ben Larson`, matching the
  original commit author and year. This receipt documents upstream intent; it
  is not represented as an upstream-authored file.
- Initial use: tool-taxonomy research only

### roman Proton CLI

- Upstream: <https://github.com/roman-16/proton-cli>
- License: MIT
- Initial use: Proton protocol research only

### Seth Bangert Proton Mail MCP

- Upstream: <https://github.com/sethbang/proton-mail-mcp>
- License: MIT
- Initial use: safety and workflow research only

### svgrepus Proton Mail MCP

- Upstream: <https://github.com/svgrepus/proton-mail-mcp>
- License: MIT
- Initial use: MCP research only

Except for the robotben receipt above, the local snapshots currently lack
immutable revision receipts. They are not admissible sources for copied code
until the provenance task in `TODO.md` pins and verifies them. The snapshots are
also intentionally pruned: product source, dependency/build manifests,
licenses, scripts, tests in source form, and useful documentation remain;
repository automation, lint/format configuration, localization payloads, and
large binary assets do not.

## License choice

The project is GPL-3.0-only so future, explicitly reviewed adaptation of Proton
WebClients GPL-3.0 material remains possible. MIT-licensed material may be
incorporated under GPL-3.0-only while its original notices and license terms are
preserved for the incorporated portions.
