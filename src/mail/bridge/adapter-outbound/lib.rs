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
//   - Proton Mail Bridge loopback endpoint and secure transport policy.
// - Must-Not:
//   - Open sockets, read credentials, trust certificates, or speak IMAP/SMTP.
// - Allows:
//   - Reject unsafe endpoint and transport configuration before adapter I/O.
// - Split-When:
//   - Endpoint identity and TLS policy gain independent change cadence.
// - Merge-When:
//   - A single Bridge adapter boundary fully owns these pure validations.
// - Summary:
//   - Defines fail-closed local Bridge connection policy.
// - Description:
//   - Ensures Bridge traffic remains loopback-only and encrypted.
// - Usage:
//   - Bridge adapters validate discovered settings before opening a connection.
// - Defaults:
//   - No endpoint or transport mode is assumed implicitly.
//

//! Proton Mail Bridge endpoint and secure transport policy.

#![forbid(unsafe_code)]

use std::net::IpAddr;

/// Certificate validation strategy accepted for a local Bridge connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificatePolicy {
    /// Trust a Bridge certificate that the user explicitly approved or pinned.
    ExplicitBridgeTrust,
    /// Use the operating-system trust store when Bridge's certificate is there.
    OperatingSystemTrust,
}

/// One validated local Bridge endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Endpoint {
    address: IpAddr,
    port: u16,
}

impl Endpoint {
    /// Returns the validated loopback address.
    #[must_use]
    pub const fn address(self) -> IpAddr {
        self.address
    }

    /// Creates one loopback-only, nonzero-port endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointError::NotLoopback`] for non-local addresses and
    /// [`EndpointError::ZeroPort`] for port zero.
    pub const fn new(addr: IpAddr, port: u16) -> Result<Self, EndpointError> {
        if !addr.is_loopback() {
            return Err(EndpointError::NotLoopback);
        }
        if port == 0 {
            return Err(EndpointError::ZeroPort);
        }
        Ok(Self {
            address: addr,
            port,
        })
    }

    /// Returns the validated port.
    #[must_use]
    pub const fn port(self) -> u16 {
        self.port
    }
}

/// Bridge endpoint validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointError {
    /// The supplied address can leave the local host.
    NotLoopback,
    /// Port zero cannot identify a Bridge listener.
    ZeroPort,
}

/// Fully validated Bridge connection policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy {
    certificate: CertificatePolicy,
    imap: Endpoint,
    smtp: Endpoint,
    transport: TransportSecurity,
}

impl Policy {
    /// Returns the accepted certificate policy.
    #[must_use]
    pub const fn certificate(self) -> CertificatePolicy {
        self.certificate
    }

    /// Returns the IMAP endpoint.
    #[must_use]
    pub const fn imap(self) -> Endpoint {
        self.imap
    }

    /// Creates a complete secure Bridge policy.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::DuplicateEndpoints`] when IMAP and SMTP resolve
    /// to
    /// the same listener.
    pub fn new(
        imap: Endpoint,
        smtp: Endpoint,
        transport: TransportSecurity,
        certificate: CertificatePolicy,
    ) -> Result<Self, PolicyError> {
        if imap.address == smtp.address && imap.port == smtp.port {
            return Err(PolicyError::DuplicateEndpoints);
        }
        Ok(Self {
            certificate,
            imap,
            smtp,
            transport,
        })
    }

    /// Returns the SMTP endpoint.
    #[must_use]
    pub const fn smtp(self) -> Endpoint {
        self.smtp
    }

    /// Returns the secure connection mode selected in Bridge.
    #[must_use]
    pub const fn transport(self) -> TransportSecurity {
        self.transport
    }
}

/// Bridge connection policy validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    /// IMAP and SMTP cannot be the same local listener.
    DuplicateEndpoints,
}

/// Secure client-to-Bridge connection mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportSecurity {
    /// Upgrade the local connection with STARTTLS.
    StartTls,
    /// Establish TLS from the first byte.
    Tls,
}
