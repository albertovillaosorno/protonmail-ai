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

/// Provider authorization state for direct Proton Mail authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderAuthorizationStatus {
    /// No provider-issued third-party Mail identity is recorded.
    Blocked,
    /// Provider evidence authorizes a complete third-party Mail identity.
    Approved,
}

/// Complete provider-approved identity and its non-secret evidence metadata.
///
/// Values of this type can only come from the repository's current provider
/// authorization policy after candidate and evidence validation succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovedMailIdentity<'evidence> {
    app_version: &'evidence str,
    child_client_id: &'evidence str,
    api_base: &'evidence str,
    fork_payload_version: u8,
    desktop_login_path: &'evidence str,
    approval_reference: &'evidence str,
    approved_on: &'evidence str,
}

impl<'evidence> ApprovedMailIdentity<'evidence> {
    /// Returns the provider-approved `x-pm-appversion` value.
    #[must_use]
    pub const fn app_version(&self) -> &'evidence str {
        self.app_version
    }

    /// Returns the provider-approved session-fork child client ID.
    #[must_use]
    pub const fn child_client_id(&self) -> &'evidence str {
        self.child_client_id
    }

    /// Returns the provider-approved API base.
    #[must_use]
    pub const fn api_base(&self) -> &'evidence str {
        self.api_base
    }

    /// Returns the provider-approved encrypted fork-payload version.
    #[must_use]
    pub const fn fork_payload_version(&self) -> u8 {
        self.fork_payload_version
    }

    /// Returns the provider-approved interactive desktop-login path.
    #[must_use]
    pub const fn desktop_login_path(&self) -> &'evidence str {
        self.desktop_login_path
    }

    /// Returns the non-secret provider-approval evidence reference.
    #[must_use]
    pub const fn approval_reference(&self) -> &'evidence str {
        self.approval_reference
    }

    /// Returns the date recorded for provider approval.
    #[must_use]
    pub const fn approved_on(&self) -> &'evidence str {
        self.approved_on
    }
}

/// Non-secret snapshot of the repository's current provider authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderAuthorizationSnapshot<'evidence> {
    status: ProviderAuthorizationStatus,
    evidence_reviewed_on: &'evidence str,
    evidence_reference: &'evidence str,
    approved_identity: Option<ApprovedMailIdentity<'evidence>>,
}

impl ProviderAuthorizationSnapshot<'static> {
    /// Returns the repository's current provider-authorization snapshot.
    #[must_use]
    pub fn current() -> Self {
        CURRENT_AUTHORIZATION.snapshot()
    }
}

impl<'evidence> ProviderAuthorizationSnapshot<'evidence> {
    /// Returns whether provider evidence is blocked or approved.
    #[must_use]
    pub const fn status(&self) -> ProviderAuthorizationStatus {
        self.status
    }

    /// Returns when the public provider evidence was last reviewed.
    #[must_use]
    pub const fn evidence_reviewed_on(&self) -> &'evidence str {
        self.evidence_reviewed_on
    }

    /// Returns the non-secret repository evidence reference.
    #[must_use]
    pub const fn evidence_reference(&self) -> &'evidence str {
        self.evidence_reference
    }

    /// Returns the complete approved identity when validation succeeds.
    #[must_use]
    pub const fn approved(&self) -> Option<ApprovedMailIdentity<'evidence>> {
        self.approved_identity
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthorizationPolicy {
    status: ProviderAuthorizationStatus,
    evidence_reviewed_on: &'static str,
    evidence_reference: &'static str,
    app_version: Option<&'static str>,
    child_client_id: Option<&'static str>,
    api_base: Option<&'static str>,
    fork_payload_version: Option<u8>,
    login_path: Option<&'static str>,
    approval_ref: Option<&'static str>,
    approved_on: Option<&'static str>,
}

const CURRENT_AUTHORIZATION: AuthorizationPolicy = AuthorizationPolicy {
    status: ProviderAuthorizationStatus::Blocked,
    evidence_reviewed_on: "2026-09-30",
    evidence_reference: "docs/architecture/provider-client-registration.mdc",
    app_version: None,
    child_client_id: None,
    api_base: None,
    fork_payload_version: None,
    login_path: None,
    approval_ref: None,
    approved_on: None,
};

impl AuthorizationPolicy {
    fn snapshot(self) -> ProviderAuthorizationSnapshot<'static> {
        let approved_identity = self.approved_identity();
        let status = if approved_identity.is_some() {
            ProviderAuthorizationStatus::Approved
        } else {
            ProviderAuthorizationStatus::Blocked
        };
        ProviderAuthorizationSnapshot {
            status,
            evidence_reviewed_on: self.evidence_reviewed_on,
            evidence_reference: self.evidence_reference,
            approved_identity,
        }
    }

    fn approved_identity(self) -> Option<ApprovedMailIdentity<'static>> {
        if self.status != ProviderAuthorizationStatus::Approved {
            return None;
        }

        let app_version = self.app_version?;
        let child_client_id = self.child_client_id?;
        validate_field(app_version).ok()?;
        validate_field(child_client_id).ok()?;
        validate_versioned_app(app_version).ok()?;
        reject_reserved(app_version, child_client_id).ok()?;

        validate_date(self.evidence_reviewed_on)?;
        validate_evidence_field(self.evidence_reference)?;
        let api_base = validate_api_base(self.api_base?)?;
        let fork_payload_version = self.fork_payload_version?;
        if !(1..=3).contains(&fork_payload_version) {
            return None;
        }
        let login_path = validate_login_path(self.login_path?)?;
        let approval_ref = validate_evidence_field(self.approval_ref?)?;
        let approved_on = validate_date(self.approved_on?)?;

        Some(ApprovedMailIdentity {
            app_version,
            child_client_id,
            api_base,
            fork_payload_version,
            desktop_login_path: login_path,
            approval_reference: approval_ref,
            approved_on,
        })
    }
}

fn validate_evidence_field(value: &str) -> Option<&str> {
    let invalid = value.is_empty()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace());
    (!invalid).then_some(value)
}

fn validate_api_base(value: &str) -> Option<&str> {
    let value = validate_evidence_field(value)?;
    value.starts_with("https://").then_some(value)
}

fn validate_login_path(value: &str) -> Option<&str> {
    let value = validate_evidence_field(value)?;
    value.starts_with('/').then_some(value)
}

const fn is_date_byte((index, byte): (usize, u8)) -> bool {
    index == 4 || index == 7 || byte.is_ascii_digit()
}

fn validate_date(value: &str) -> Option<&str> {
    let bytes = value.as_bytes();
    let valid = bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes.iter().copied().enumerate().all(is_date_byte);
    valid.then_some(value)
}

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
