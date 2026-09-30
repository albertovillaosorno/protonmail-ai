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
//   - Proton Mail QR session-fork target handoff framing.
// - Must-Not:
//   - Collect Proton credentials, impersonate first-party client IDs, or log
//     handoff secrets.
// - Allows:
//   - Generate target-side entropy and format the QR/manual-code payload.
// - Split-When:
//   - Network polling or fork-payload decryption needs independent ownership.
// - Merge-When:
//   - One reviewed authentication adapter owns the complete session-fork flow.
// - Summary:
//   - Builds third-party Proton Mail session-fork handoff payloads.
// - Description:
//   - Uses the Mail SDK third-party client identity and Proton QR payload
//     shape.
// - Usage:
//   - Create after GET /auth/v4/sessions/forks returns a user code.
// - Defaults:
//   - SDK default child client identity is `Other`; live use is disabled.
//

//! Proton Mail target-side QR session-fork handoff framing.

#![forbid(unsafe_code)]

mod protocol;

pub use protocol::{AnonymousSession, ForkChallenge, ForkPayloadDecoder};
pub use protocol::{ForkPoll, ForkSession, KeyPassword, ProtocolError};
pub use protocol::{ProviderProfile, RequestMethod, RequestSpec};

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use zeroize::Zeroizing;

/// Unversioned child client default used by Proton's Mail session SDK.
pub const SDK_DEFAULT_CLIENT_ID: &str = "Other";

const QR_VERSION: u8 = 0;
const SECRET_LEN: usize = 32;

/// A displayable QR/manual-code handoff payload.
///
/// The value embeds a short-lived encryption key. Call [`Self::expose`] only
/// at the explicit user-facing handoff boundary.
pub struct HandoffPayload(String);

impl HandoffPayload {
    /// Exposes the handoff value for QR rendering or deliberate user copy.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for HandoffPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HandoffPayload([REDACTED])")
    }
}

/// Failure while preparing a target-side session-fork handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffError {
    /// The provider user code is empty or incompatible with colon framing.
    InvalidUserCode,
    /// The operating system could not provide cryptographic randomness.
    EntropyUnavailable,
}

/// Target-side state needed while waiting for the host device to approve login.
pub struct TargetHandoff {
    secret: Zeroizing<[u8; SECRET_LEN]>,
    user_code: String,
}

impl TargetHandoff {
    /// Creates a fresh third-party target handoff from Proton's user code.
    ///
    /// # Errors
    ///
    /// Returns [`HandoffError::InvalidUserCode`] when colon framing would be
    /// ambiguous, or [`HandoffError::EntropyUnavailable`] when secure random
    /// bytes cannot be obtained from the operating system.
    pub fn new<T>(user_code: T) -> Result<Self, HandoffError>
    where
        T: Into<String>,
    {
        let user_code = user_code.into();
        if user_code.is_empty() || user_code.contains(':') {
            return Err(HandoffError::InvalidUserCode);
        }

        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        if let Err(_error) = getrandom::fill(secret.as_mut()) {
            return Err(HandoffError::EntropyUnavailable);
        }

        Ok(Self { secret, user_code })
    }

    /// Returns a redaction-aware QR/manual-code payload.
    #[must_use]
    pub fn payload(&self) -> HandoffPayload {
        let encoded_secret = STANDARD.encode(self.secret.as_ref());
        HandoffPayload(format!(
            "{QR_VERSION}:{}:{encoded_secret}:{SDK_DEFAULT_CLIENT_ID}",
            self.user_code
        ))
    }

    /// Consumes the handoff and transfers exclusive key ownership to the
    /// authenticated fork-payload decoder.
    #[must_use]
    pub fn into_decoder(self) -> ForkPayloadDecoder {
        ForkPayloadDecoder::new(self.secret)
    }
}

impl fmt::Debug for TargetHandoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TargetHandoff")
            .field("user_code", &self.user_code)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}
