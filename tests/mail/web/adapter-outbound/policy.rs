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
//   - Synthetic evidence for semantic web-adapter action gating.
// - Must-Not:
//   - Access a browser, live mailbox, credential, DOM, or network.
// - Allows:
//   - Prove state, capability, authority, and target combinations fail closed.
// - Split-When:
//   - Browser fixtures need independent page-state parsing evidence.
// - Merge-When:
//   - A broader adapter conformance suite owns the same invariants.
// - Summary:
//   - Verifies read/mutation/send separation before UI interaction.
// - Description:
//   - Exercises synthetic mailbox, composer, login, challenge, and drift
//     states.
// - Usage:
//   - Run through the `mail_web_adapter` integration-test target.
// - Defaults:
//   - Synthetic deterministic policy checks only.
//

//! Semantic Proton Mail web-adapter action-gate tests.

use mail_capability_domain::planned_capabilities;
use mail_capability_domain::{ActionGrant as Grant, Capability, SafetyClass};
use mail_web_adapter::AuthenticatedMailSurface as MailSurface;
use mail_web_adapter::PageOrigin as Origin;
use mail_web_adapter::WebSurface;
use mail_web_adapter::authorize_ui_target as gate;
use mail_web_adapter::{AuthSurface as Auth, UiEvidence as Evidence};
use mail_web_adapter::{UiGateError, UiTarget as Target};

const fn account(auth: Auth) -> Evidence {
    Evidence::new(Origin::ProtonAccount, false, false, auth, false)
}

const fn mail(shell: bool, composer: bool, blocker: bool) -> Evidence {
    Evidence::new(Origin::ProtonMail, shell, composer, Auth::None, blocker)
}

const fn foreign_mail_shape() -> Evidence {
    Evidence::new(Origin::Other, true, false, Auth::None, false)
}

const fn mailbox() -> Evidence {
    mail(true, false, false)
}

const fn composer() -> Evidence {
    mail(true, true, false)
}

#[test]
fn page_state_fails_closed_for_login_challenge_and_drift() {
    let login = account(Auth::Login);
    let challenge = account(Auth::Challenge);
    let drift = mail(false, false, false);
    let blocker = mail(true, false, true);

    assert_eq!(login.surface(), WebSurface::SignedOut);
    assert_eq!(challenge.surface(), WebSurface::AuthenticationChallenge);
    assert_eq!(drift.surface(), WebSurface::Incompatible);
    assert_eq!(blocker.surface(), WebSurface::Incompatible);

    let search = Capability::new("search_messages", SafetyClass::ReadOnly);
    for evidence in [login, challenge, drift, blocker] {
        let target = Target::SearchControl;
        let result = gate(evidence, search, Grant::Observe, target);
        assert!(result.is_err());
    }
}

#[test]
fn authentication_fields_are_not_targetable_controls() {
    let forbidden = [
        "password",
        "two_factor",
        "otp",
        "captcha",
        "recovery",
        "security_key",
        "cookie",
        "session",
    ];
    for target in Target::all() {
        for term in forbidden {
            assert!(!target.name().contains(term));
        }
    }
}

#[test]
fn every_read_only_capability_rejects_mutation_and_send_targets() {
    let forbidden_targets = [
        Target::ArchiveControl,
        Target::ComposeButton,
        Target::DiscardDraftControl,
        Target::DraftEditor,
        Target::LabelControl,
        Target::MarkControl,
        Target::MoveControl,
        Target::SendButton,
        Target::TrashControl,
    ];
    for cap in planned_capabilities()
        .iter()
        .filter(|item| item.safety() == SafetyClass::ReadOnly)
    {
        for target in forbidden_targets {
            let result = gate(mailbox(), *cap, Grant::Observe, target);
            assert!(result.is_err());
        }
    }
}

#[test]
fn draft_and_send_targets_require_distinct_capability_and_grant() {
    let create = Capability::new("create_draft", SafetyClass::Reversible);
    let send = Capability::new("send_draft", SafetyClass::ExternalSideEffect);

    assert_eq!(
        gate(
            mailbox(),
            create,
            Grant::ReversibleChange,
            Target::ComposeButton,
        ),
        Ok(())
    );
    assert_eq!(
        gate(
            composer(),
            send,
            Grant::ExternalSideEffect,
            Target::SendButton,
        ),
        Ok(())
    );
    assert_eq!(
        gate(
            composer(),
            create,
            Grant::ReversibleChange,
            Target::SendButton,
        ),
        Err(UiGateError::SafetyMismatch)
    );
    assert_eq!(
        gate(
            composer(),
            send,
            Grant::ReversibleChange,
            Target::SendButton,
        ),
        Err(UiGateError::Unauthorized)
    );
}

#[test]
fn send_requires_composer_surface() {
    let send = Capability::new("send_draft", SafetyClass::ExternalSideEffect);
    let result = gate(
        mailbox(),
        send,
        Grant::ExternalSideEffect,
        Target::SendButton,
    );
    assert_eq!(result, Err(UiGateError::SurfaceMismatch));
}

#[test]
fn capability_specific_target_mismatch_is_rejected() {
    let archive = Capability::new("archive", SafetyClass::Reversible);
    let result = gate(
        mailbox(),
        archive,
        Grant::ReversibleChange,
        Target::ComposeButton,
    );
    assert_eq!(result, Err(UiGateError::TargetMismatch));
}

#[test]
fn destructive_capability_has_no_ui_target() {
    let delete = Capability::new("delete_messages", SafetyClass::Destructive);
    for target in Target::all() {
        let result = gate(mailbox(), delete, Grant::ReversibleChange, *target);
        assert!(result.is_err());
    }
}

#[test]
fn every_non_destructive_capability_has_a_semantic_target() {
    for cap in planned_capabilities()
        .iter()
        .filter(|item| item.safety() != SafetyClass::Destructive)
    {
        let grant = cap
            .safety()
            .required_grant()
            .expect("non-destructive capability must have a grant");
        let covered = Target::all().iter().any(|target| {
            [mailbox(), composer()]
                .iter()
                .any(|evidence| gate(*evidence, *cap, grant, *target).is_ok())
        });
        assert!(covered, "missing semantic target for {}", cap.name());
    }
}

#[test]
fn provider_origin_classification_rejects_spoofed_hosts() {
    assert_eq!(
        Origin::from_location("https:", "mail.proton.me"),
        Origin::ProtonMail
    );
    assert_eq!(
        Origin::from_location("https:", "account.proton.me"),
        Origin::ProtonAccount
    );
    assert_eq!(
        Origin::from_location("https:", "MAIL.PROTON.ME"),
        Origin::ProtonMail
    );
    for (protocol, hostname) in [
        ("http:", "mail.proton.me"),
        ("https:", "mail.proton.me.evil.example"),
        ("https:", "proton.me"),
        ("file:", ""),
    ] {
        assert_eq!(Origin::from_location(protocol, hostname), Origin::Other);
    }
}

#[test]
fn authenticated_mail_requires_mail_origin_and_shell() {
    assert_eq!(mailbox().authenticated_mail(), Ok(MailSurface::Mailbox));
    assert_eq!(composer().authenticated_mail(), Ok(MailSurface::Composer));

    let fake_mail = foreign_mail_shape();
    // jig-ignore-next-line: canonical rustfmt line.
    let account_shell = Evidence::new(Origin::ProtonAccount, true, false, Auth::None, false);
    assert_eq!(
        fake_mail.authenticated_mail(),
        Err(UiGateError::ProviderShapeMismatch)
    );
    assert_eq!(
        account_shell.authenticated_mail(),
        Err(UiGateError::ProviderShapeMismatch)
    );
}
