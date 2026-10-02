// Copyright:
//   - Copyright © 2026 Alberto Villa Osorno.
// SPDX-License-Identifier:
//   - GPL-3.0-only
// Confidential:
//   - false
// License-File:
//   - LICENSE
//
// Boundary-Contract:
// - Owns:
//   - Reusable local runtime composition helpers shared by CLI and MCP modes.
// - Must-Not:
//   - Own provider semantics, credentials, or mailbox business rules.
// - Allows:
//   - Enforce local filesystem and process boundaries around accepted
//     workflows.
// - Split-When:
//   - A runtime helper becomes independently deployable or provider-specific.
// - Merge-When:
//   - Runtime composition no longer needs a reusable library boundary.
// - Summary:
//   - Exposes local runtime safety primitives without widening provider access.
// - Description:
//   - Keeps provider-neutral local side-effect enforcement outside mail
//     domains.
// - Usage:
//   - Imported by runtime integration tests and future accepted workflows.
// - Defaults:
//   - No provider access, listener, authentication, or mailbox mutation.
//

//! Reusable local runtime composition primitives.

#![forbid(unsafe_code)]

mod attachment_output;

pub use attachment_output::AttachmentFileOutput;
pub use attachment_output::AttachmentFileOutputError;
pub use attachment_output::AttachmentFileOutputRoot;
