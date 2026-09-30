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
//   - Synthetic regression evidence for Bridge connection policy.
// - Must-Not:
//   - Open sockets, use Bridge credentials, or access a real mailbox.
// - Allows:
//   - Validate loopback, port, TLS-mode, and endpoint separation rules.
// - Split-When:
//   - Network integration tests need independent fixtures.
// - Merge-When:
//   - Another deterministic suite fully owns Bridge policy validation.
// - Summary:
//   - Proves unsafe Bridge endpoint configuration fails closed.
// - Description:
//   - Exercises pure Bridge policy without external systems.
// - Usage:
//   - Run through the workspace test gate.
// - Defaults:
//   - Synthetic loopback-only values.
//

//! Proton Mail Bridge connection-policy regression tests.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use mail_bridge_adapter::{CertificatePolicy, Endpoint, EndpointError};
use mail_bridge_adapter::{Policy, PolicyError, TransportSecurity};

#[test]
fn bridge_endpoints_must_be_loopback() {
    let public = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let result = Endpoint::new(public, 1143);

    assert_eq!(result, Err(EndpointError::NotLoopback));
}

#[test]
fn bridge_endpoints_reject_port_zero() {
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let result = Endpoint::new(loopback, 0);

    assert_eq!(result, Err(EndpointError::ZeroPort));
}

#[test]
fn ipv4_and_ipv6_loopback_are_accepted() {
    let ipv4 = Endpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1143);
    let ipv6 = Endpoint::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1025);

    assert!(ipv4.is_ok());
    assert!(ipv6.is_ok());
}

#[test]
fn imap_and_smtp_must_use_distinct_listeners() {
    let endpoint = Endpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1143);
    let endpoint = endpoint.expect("synthetic loopback endpoint must be valid");
    let policy = Policy::new(
        endpoint,
        endpoint,
        TransportSecurity::StartTls,
        CertificatePolicy::ExplicitBridgeTrust,
    );

    assert_eq!(policy, Err(PolicyError::DuplicateEndpoints));
}

#[test]
fn secure_bridge_modes_are_explicit() {
    let imap = Endpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1143);
    let smtp = Endpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1025);
    let imap = imap.expect("synthetic IMAP endpoint must be valid");
    let smtp = smtp.expect("synthetic SMTP endpoint must be valid");

    for transport in [TransportSecurity::StartTls, TransportSecurity::Tls] {
        let policy = Policy::new(
            imap,
            smtp,
            transport,
            CertificatePolicy::OperatingSystemTrust,
        );
        let policy = policy.expect("distinct loopback endpoints must be valid");
        assert_eq!(policy.transport(), transport);
        assert_eq!(policy.imap(), imap);
        assert_eq!(policy.smtp(), smtp);
    }
}
