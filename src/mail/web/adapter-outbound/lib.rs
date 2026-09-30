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
//   - Proton Mail web-profile custody and semantic UI safety policy.
// - Must-Not:
//   - Read personal browser profiles, automate login challenges, or expose
//     browser session state outside the adapter.
// - Allows:
//   - Launch a dedicated visible profile and gate mailbox UI targets.
// - Split-When:
//   - Browser-driver integration and UI policy require independent ownership.
// - Merge-When:
//   - One reviewed outbound adapter owns all web-provider behavior.
// - Summary:
//   - Defines the Free-plan Proton Mail web adapter boundary.
// - Description:
//   - Keeps browser session custody and semantic side-effect gates out of the
//     runtime composition root.
// - Usage:
//   - Runtime composition invokes the adapter after explicit human CLI actions.
// - Defaults:
//   - No mailbox read, mutation, send, or browser-debugging connection.
//

//! User-controlled Proton Mail web adapter.

#![forbid(unsafe_code)]

mod driver;
mod lease;
mod policy;
mod profile;

pub use driver::ProviderPage;
pub use driver::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};
pub use lease::{AutomationProfileLease, ProfileLeaseError};
pub use policy::authorize_ui_target;
pub use policy::{AuthSurface, AuthenticatedMailSurface, PageOrigin};
pub use policy::{UiEvidence, UiGateError, UiTarget, WebSurface};
pub use profile::{DedicatedBrowserProfile, WebLoginError, WebLoginPlan};
