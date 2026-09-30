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
//   - Repository provenance policy evidence for governed source and tests.
// - Must-Not:
//   - Read ignored reference content, network state, or live credentials.
// - Allows:
//   - Validate tracked provenance manifests and governed file coverage.
// - Split-When:
//   - Provenance validation grows beyond source and license policy.
// - Merge-When:
//   - Another repository gate fully owns file-level provenance validation.
// - Summary:
//   - Verifies source provenance coverage and license obligations.
// - Description:
//   - Rejects unclassified governed files and incomplete external origins.
// - Usage:
//   - Run through the workspace test gate.
// - Defaults:
//   - Local-only validation with no ignored reference dependency.
//

//! Repository provenance and third-party license policy checks.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const SOURCE_FIELDS: &[&str] = &[
    "id",
    "upstream",
    "revision",
    "license",
    "reference_root",
    "usage",
    "verified_files",
    "verification",
    "verified_at",
    "local_only",
    "distribution_license",
];

const FILE_FIELDS: &[&str] = &[
    "path",
    "origin",
    "source_id",
    "source_path",
    "source_revision",
    "source_license",
    "destination_license",
    "modifications",
];

type Record = BTreeMap<String, String>;

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..")
}

fn parse_manifest(path: &Path, section: &str) -> Vec<Record> {
    let path_label = path.display().to_string();
    let content = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {path_label}: {error}"));
    let expected_header = format!("[{section}]");
    let mut records = Vec::new();

    for block in content
        .split("\n\n")
        .filter(|block| !block.trim().is_empty())
    {
        let mut lines = block.lines();
        assert_eq!(
            lines.next(),
            Some(expected_header.as_str()),
            "unexpected manifest section in {}",
            path.display()
        );

        let mut record = Record::new();
        for line in lines {
            let Some((key, value)) = line.split_once('=') else {
                panic!("malformed manifest line: {line}");
            };
            assert!(
                record.insert(key.to_owned(), value.to_owned()).is_none(),
                "duplicate key {key} in {}",
                path.display()
            );
        }
        records.push(record);
    }

    records
}

fn require_fields(record: &Record, fields: &[&str], context: &str) {
    let actual = record.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = fields.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(actual, expected, "unexpected fields for {context}");
    for field in fields {
        assert!(
            !record[*field].is_empty(),
            "empty field {field} for {context}"
        );
    }
}

fn collect_files(root: &Path, directory: &Path, output: &mut BTreeSet<String>) {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) => panic!("directory read failed: {error}"),
    };
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| {
            panic!("failed to read entry in {}: {error}", directory.display())
        });
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, output);
        } else if path.is_file() {
            let relative = path
                .strip_prefix(root)
                .unwrap_or_else(|error| panic!("path outside root: {error}"));
            output.insert(relative.to_string_lossy().replace('\\', "/"));
        }
    }
}

fn dependency_section(header: &str) -> bool {
    matches!(
        header,
        "[dependencies]" | "[dev-dependencies]" | "[build-dependencies]"
    ) || (header.starts_with("[target.")
        && (header.ends_with(".dependencies]")
            || header.ends_with(".dev-dependencies]")
            || header.ends_with(".build-dependencies]")))
}

fn dependency_line_is_inherited(trimmed: &str) -> bool {
    let dotted = trimmed.ends_with(".workspace = true");
    let inline = trimmed.contains("workspace = true");
    dotted || inline
}

fn ignorable_manifest_line(active: bool, trimmed: &str) -> bool {
    !active || trimmed.is_empty() || trimmed.starts_with('#')
}

fn numeric_version_part(part: &&str) -> bool {
    !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit())
}

fn validate_workspace_manifest(manifest: &Path, content: &str) {
    let mut inherited_section = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            assert!(
                !trimmed.starts_with("[dependencies.")
                    && !trimmed.starts_with("[dev-dependencies.")
                    && !trimmed.starts_with("[build-dependencies."),
                "{} must inherit dependencies from the workspace",
                manifest.display()
            );
            inherited_section = dependency_section(trimmed);
            continue;
        }
        if ignorable_manifest_line(inherited_section, trimmed) {
            continue;
        }
        let inherited = dependency_line_is_inherited(trimmed);
        assert!(
            inherited,
            "{} has a non-workspace dependency declaration: {trimmed}",
            manifest.display()
        );
    }
}

fn validate_workspace_dependencies(root: &Path) {
    let mut tracked = BTreeSet::new();
    collect_files(root, &root.join("src"), &mut tracked);
    let manifests = tracked
        .iter()
        .filter(|path| path.ends_with("Cargo.toml"))
        .collect::<Vec<_>>();
    assert!(
        !manifests.is_empty(),
        "workspace must contain member manifests"
    );

    for relative in manifests {
        let manifest = root.join(relative);
        let label = manifest.display().to_string();
        let content = fs::read_to_string(&manifest)
            .unwrap_or_else(|error| panic!("failed to read {label}: {error}"));
        validate_workspace_manifest(&manifest, &content);
    }
}

fn exact_stable_version(value: &str) -> bool {
    let Some(version) = value.strip_prefix('=') else {
        return false;
    };
    let parts = version.split('.').collect::<Vec<_>>();
    let numeric = parts.iter().all(numeric_version_part);
    parts.len() == 3 && numeric
}

fn validate_workspace_dependency_versions(root_manifest: &str) {
    let mut workspace_dependencies = false;

    for line in root_manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            workspace_dependencies = trimmed == "[workspace.dependencies]";
            continue;
        }
        if ignorable_manifest_line(workspace_dependencies, trimmed) {
            continue;
        }
        if trimmed.contains("path =") {
            continue;
        }

        let table_version = trimmed.split_once("version = \"");
        let version = if let Some((_, value)) = table_version {
            value.split('"').next().unwrap_or_default()
        } else if let Some((_, value)) = trimmed.split_once("= \"") {
            value.split('"').next().unwrap_or_default()
        } else {
            ""
        };
        assert!(
            exact_stable_version(version),
            "workspace dependency needs exact stable x.y.z: {trimmed}"
        );
    }
}

fn validate_no_dependency_bots(root: &Path) {
    for relative in [
        ".github/dependabot.yml",
        ".github/dependabot.yaml",
        "renovate.json",
        ".renovaterc",
        ".renovaterc.json",
    ] {
        assert!(
            !root.join(relative).exists(),
            "automated dependency-update bots are prohibited: {relative}"
        );
    }
}

fn validate_sources(root: &Path, notices: &str) -> BTreeMap<String, Record> {
    let sources_path = root.join("docs/provenance/sources.txt");
    let source_records = parse_manifest(&sources_path, "source");
    let mut sources = BTreeMap::new();

    for record in source_records {
        require_fields(&record, SOURCE_FIELDS, "source record");
        let id = record["id"].clone();
        assert!(
            record["upstream"].starts_with("https://github.com/"),
            "source {id} must use a canonical GitHub URL"
        );
        let revision = &record["revision"];
        let correct_length = revision.len() == 40;
        let hexadecimal = revision.chars().all(|ch| ch.is_ascii_hexdigit());
        assert!(
            correct_length && hexadecimal,
            "source {id} must use a full immutable commit"
        );
        let usage = record["usage"].as_str();
        let supported = usage == "research-only" || usage == "incorporated";
        assert!(supported, "source {id} has an unsupported usage");
        assert_eq!(record["verification"], "git-blob-tree-match");
        assert!(
            record["verified_files"]
                .parse::<usize>()
                .is_ok_and(|count| count > 0),
            "source {id} must record a positive verified file count"
        );
        assert!(
            notices.contains(&record["upstream"]) && notices.contains(revision),
            "source {id} must be pinned in THIRD_PARTY_NOTICES.md"
        );
        let license_notice = format!("- License: {}", record["license"]);
        assert!(
            notices.contains(&license_notice),
            "source {id} must name its license in THIRD_PARTY_NOTICES.md"
        );
        if record["usage"] == "incorporated" {
            assert_ne!(
                record["distribution_license"], "-",
                "incorporated source {id} needs tracked license evidence"
            );
        }
        assert!(
            sources.insert(id.clone(), record).is_none(),
            "duplicate source id: {id}"
        );
    }

    sources
}

fn validate_files(root: &Path, sources: &BTreeMap<String, Record>) {
    let files_path = root.join("docs/provenance/files.txt");
    let file_records = parse_manifest(&files_path, "file");
    let mut classified = BTreeSet::new();

    for record in &file_records {
        require_fields(record, FILE_FIELDS, "file record");
        let path = &record["path"];
        assert!(
            classified.insert(path.clone()),
            "duplicate file provenance record: {path}"
        );
        assert_eq!(record["destination_license"], "GPL-3.0-only");

        match record["origin"].as_str() {
            "original" => {
                assert_eq!(record["source_id"], "project");
                assert_eq!(record["source_path"], "-");
                assert_eq!(record["source_revision"], "-");
                assert_eq!(record["source_license"], "-");
            }
            "fact-informed" | "adapted" => {
                let source_id = &record["source_id"];
                let source = sources
                    .get(source_id)
                    .unwrap_or_else(|| panic!("unknown source {source_id}"));
                assert_ne!(record["source_path"], "-");
                assert_eq!(record["source_revision"], source["revision"]);
                assert_eq!(record["source_license"], source["license"]);

                if record["origin"] == "adapted" {
                    assert_eq!(source["usage"], "incorporated");
                    assert_ne!(
                        record["modifications"], "original-project-code",
                        "adapted file {path} needs a real modification note"
                    );
                    let license_path = &source["distribution_license"];
                    assert_ne!(
                        license_path, "-",
                        "adapted source {source_id} needs license evidence"
                    );
                    assert!(
                        root.join(license_path).is_file(),
                        "distribution license for {source_id} is missing"
                    );
                }
            }
            origin => panic!("unsupported provenance origin {origin}: {path}"),
        }

        assert_ne!(record["modifications"], "-");
        assert!(
            root.join(path).is_file(),
            "classified file is missing: {path}"
        );
    }

    let mut governed = BTreeSet::new();
    collect_files(root, &root.join("src"), &mut governed);
    collect_files(root, &root.join("tests"), &mut governed);
    assert_eq!(
        governed, classified,
        "every governed source and test file needs one provenance record"
    );
}

#[test]
fn governed_files_have_complete_provenance() {
    let root = repository_root();
    let notices = fs::read_to_string(root.join("THIRD_PARTY_NOTICES.md"))
        .expect("THIRD_PARTY_NOTICES.md must be readable");
    let sources = validate_sources(&root, &notices);
    validate_files(&root, &sources);
}

#[test]
fn workspace_members_inherit_all_dependencies() {
    validate_workspace_dependencies(&repository_root());
}

#[test]
#[should_panic(expected = "non-workspace dependency declaration")]
fn workspace_dependency_policy_rejects_member_local_versions() {
    let manifest = Path::new("synthetic/Cargo.toml");
    let content = "[dependencies]\nserde = \"=1.0.229\"\n";
    validate_workspace_manifest(manifest, content);
}

#[test]
fn root_workspace_dependencies_use_exact_versions() {
    let root = repository_root();
    let path = root.join("Cargo.toml");
    let manifest = fs::read_to_string(path);
    let manifest = manifest.expect("root Cargo.toml must be readable");
    validate_workspace_dependency_versions(&manifest);
}

#[test]
#[should_panic(expected = "exact stable x.y.z")]
fn workspace_dependency_policy_rejects_vague_versions() {
    let manifest = "[workspace.dependencies]\nserde = \"1\"\n";
    validate_workspace_dependency_versions(manifest);
}

#[test]
fn automated_dependency_update_bots_are_prohibited() {
    validate_no_dependency_bots(&repository_root());
}
