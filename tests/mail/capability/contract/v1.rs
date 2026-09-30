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
//   - Golden serialization evidence for the version-one mail tool contract.
// - Must-Not:
//   - Access providers, credentials, networks, or mailbox data.
// - Allows:
//   - Round-trip and compare the versioned contract fixture.
// - Split-When:
//   - A new incompatible contract version requires independent evidence.
// - Merge-When:
//   - Contract serialization is fully owned by another deterministic gate.
// - Summary:
//   - Verifies the frozen machine-readable tool contract.
// - Description:
//   - Prevents accidental schema, hint, identifier, limit, or error drift.
// - Usage:
//   - Run through the workspace test gate.
// - Defaults:
//   - Synthetic local-only execution.
//

//! Golden serialization checks for the version-one mail tool contract.

use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use mail_capability_domain::contract_v1::{contract, from_json, to_json};
use mail_capability_domain::planned_capabilities;

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..")
}

#[test]
fn contract_matches_golden_fixture() -> Result<(), Box<dyn Error>> {
    let expected = contract();
    let serialized = to_json(&expected)?;
    let encoded = format!("{serialized}\n");
    let fixture = repository_root().join("docs/contract/tool-contract-v1.json");

    if env::var_os("UPDATE_CONTRACT_FIXTURE").is_some() {
        fs::create_dir_all(fixture.parent().ok_or("fixture has no parent")?)?;
        fs::write(&fixture, &encoded)?;
    }

    let golden = fs::read_to_string(&fixture)?;
    if golden != encoded {
        return Err("golden contract fixture drifted".into());
    }

    let decoded = from_json(&golden)?;
    if decoded != expected {
        return Err("contract failed JSON round trip".into());
    }
    Ok(())
}

#[test]
fn contract_and_capability_inventory_match() {
    let contract = contract();
    let contract_names = contract
        .tools
        .iter()
        .map(|tool| tool.capability.as_str())
        .collect::<Vec<_>>();
    let capability_names = planned_capabilities()
        .iter()
        .map(|capability| capability.name())
        .collect::<Vec<_>>();

    assert_eq!(
        contract_names, capability_names,
        "contract and planned capability inventory must remain identical"
    );
}
