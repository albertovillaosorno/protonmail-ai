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
//   - Provider client-identity candidate validation before live Mail auth.
// - Must-Not:
//   - Claim provider authorization, contact Proton, or accept first-party IDs.
// - Allows:
//   - Reject known unsafe identities and preserve candidate identity strings.
// - Split-When:
//   - Provider-issued registration metadata gains an independent lifecycle.
// - Merge-When:
//   - Provider identity becomes inseparable from outbound transport policy.
// - Summary:
//   - Prevents SDK defaults and first-party Mail IDs from becoming live IDs.
// - Description:
//   - Validates syntax and known-negative identity evidence without asserting
//     that an otherwise valid candidate has been approved by Proton.
// - Usage:
//   - Use while reviewing a proposed third-party identity from Proton.
// - Defaults:
//   - No candidate is considered authorized by this module.
//

//! Fail-closed candidate validation for Proton Mail client identity.

const SDK_DEFAULT_ID: &str = "Other";
// Pinned WebClients evidence: packages/shared/lib/constants.ts and the fork
// authentication tests at revision 74773f0b10cc31d32e43e82c061da5d75fef96ce.
const FIRST_PARTY_MAIL_IDS: [&str; 6] = [
    "web-mail",
    "windows-mail",
    "macos-mail",
    "linux-mail",
    "ios-mail",
    "android-mail",
];

/// A syntactically plausible third-party identity candidate.
///
/// This type proves only negative checks. Construction does **not** prove that
/// Proton has authorized the identity for live Mail authentication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThirdPartyIdentityCandidate {
    app_version: String,
    child_client_id: String,
}

impl ThirdPartyIdentityCandidate {
    /// Validates a proposed app version and fork child client ID.
    ///
    /// # Errors
    ///
    /// Returns an error for unversioned, malformed, SDK-default, or known
    /// first-party Mail identities.
    pub fn try_new<AppVersion, ChildClientId>(
        app_version: AppVersion,
        child_client_id: ChildClientId,
    ) -> IdentityResult<Self>
    where
        AppVersion: Into<String>,
        ChildClientId: Into<String>,
    {
        let app_version = app_version.into();
        let child_client_id = child_client_id.into();

        validate_field(&app_version)?;
        validate_field(&child_client_id)?;
        validate_versioned_app(&app_version)?;
        reject_reserved(&app_version, &child_client_id)?;

        Ok(Self {
            app_version,
            child_client_id,
        })
    }

    /// Returns the proposed `x-pm-appversion` value.
    #[must_use]
    pub fn app_version(&self) -> &str {
        &self.app_version
    }

    /// Returns the proposed child client ID for session-fork framing.
    #[must_use]
    pub fn child_client_id(&self) -> &str {
        &self.child_client_id
    }
}

/// Identity-candidate validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientIdentityError {
    /// An identity field is empty, padded, or contains a framing-unsafe byte.
    InvalidSyntax,
    /// The app identity does not contain an explicit version after `@`.
    MissingVersion,
    /// The SDK fallback `Other` was proposed for live use.
    SdkDefault,
    /// A known Proton-owned Mail client identity was proposed.
    FirstPartyMail,
}

type IdentityResult<T> = Result<T, ClientIdentityError>;

fn validate_field(value: &str) -> IdentityResult<()> {
    let invalid = value.is_empty()
        || !value.is_ascii()
        || value.trim() != value
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || value.contains(':');
    if invalid {
        return Err(ClientIdentityError::InvalidSyntax);
    }
    Ok(())
}

fn validate_versioned_app(app_version: &str) -> IdentityResult<()> {
    let Some((name, version)) = app_version.split_once('@') else {
        return Err(ClientIdentityError::MissingVersion);
    };
    if name.is_empty() || version.is_empty() || version.contains('@') {
        return Err(ClientIdentityError::InvalidSyntax);
    }
    Ok(())
}

fn reject_reserved(app_version: &str, child_id: &str) -> IdentityResult<()> {
    let app_name = app_version
        .split_once('@')
        .map_or(app_version, |(name, _version)| name);
    if eq_ignore_ascii_case(app_name, SDK_DEFAULT_ID)
        || eq_ignore_ascii_case(child_id, SDK_DEFAULT_ID)
    {
        return Err(ClientIdentityError::SdkDefault);
    }
    let app_is_first_party = is_first_party_mail_id(app_name);
    let child_is_first_party = is_first_party_mail_id(child_id);
    if app_is_first_party || child_is_first_party {
        return Err(ClientIdentityError::FirstPartyMail);
    }
    Ok(())
}

fn is_first_party_mail_id(value: &str) -> bool {
    FIRST_PARTY_MAIL_IDS
        .iter()
        .any(|known| eq_ignore_ascii_case(value, known))
}

const fn eq_ignore_ascii_case(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}
