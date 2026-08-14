use super::{
    BoundaryGitEntryKind, IntentionalBoundaryRepositoryInventory,
    read_intentional_boundary_git_blob, validate_intentional_boundary_repository_inventory,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub const INTENTIONAL_BOUNDARY_SOURCE_CENSUS_SCHEMA_VERSION: u32 = 1;
const SOURCE_CENSUS_CONTRACT: &str = "sniffbench-intentional-boundary-source-census-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryMethodCensusEntry {
    pub parser_unit_id: String,
    pub symbol_name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub source_sha256: String,
    pub is_exported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySourceFile {
    pub repository_path: String,
    pub object_id: String,
    pub byte_length: u64,
    pub source_sha256: String,
    pub language: String,
    pub methods: Vec<IntentionalBoundaryMethodCensusEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySourceCensus {
    pub schema_version: u32,
    pub census_contract: String,
    pub repository: String,
    pub revision: String,
    pub inventory_sha256: String,
    pub tracked_entry_count: usize,
    pub source_files: Vec<IntentionalBoundarySourceFile>,
    pub source_file_count: usize,
    pub method_count: usize,
    pub census_sha256: String,
}

pub fn census_intentional_boundary_repository(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Result<IntentionalBoundarySourceCensus, String> {
    validate_intentional_boundary_repository_inventory(repository, revision, root, inventory)?;
    if inventory
        .tracked_entries
        .iter()
        .any(|entry| entry.kind == BoundaryGitEntryKind::Gitlink)
    {
        return Err(
            "intentional-boundary source census does not support Gitlinks in the immutable tree"
                .to_string(),
        );
    }

    let mut source_files = Vec::new();
    for entry in &inventory.tracked_entries {
        let extension = Path::new(&entry.repository_path)
            .extension()
            .and_then(|value| value.to_str());
        let Some(adapter) = extension.and_then(crate::languages::get_adapter) else {
            continue;
        };
        if !matches!(
            entry.kind,
            BoundaryGitEntryKind::RegularBlob | BoundaryGitEntryKind::ExecutableBlob
        ) {
            return Err(format!(
                "intentional-boundary supported source is not a regular Git blob: {}",
                entry.repository_path
            ));
        }
        let expected_length = entry.byte_length.ok_or_else(|| {
            format!(
                "intentional-boundary source has no committed byte length: {}",
                entry.repository_path
            )
        })?;
        let committed_bytes =
            read_intentional_boundary_git_blob(root, &entry.object_id, expected_length)?;
        let worktree_bytes =
            fs::read(root.join(Path::new(&entry.repository_path))).map_err(|error| {
                format!(
                    "failed to read intentional-boundary source {}: {error}",
                    entry.repository_path
                )
            })?;
        if worktree_bytes != committed_bytes {
            return Err(format!(
                "intentional-boundary source bytes differ from committed Git blob: {}",
                entry.repository_path
            ));
        }
        let parsed = crate::parser::parse_source_checked(&entry.repository_path, &committed_bytes)
            .map_err(|error| {
                format!(
                    "failed to parse committed intentional-boundary source {}: {error}",
                    entry.repository_path
                )
            })?;
        if parsed.language != adapter.name {
            return Err(format!(
                "intentional-boundary parser language changed for {}",
                entry.repository_path
            ));
        }
        let mut parser_unit_ids = BTreeSet::new();
        let methods = parsed
            .methods
            .into_iter()
            .map(|method| {
                let source_sha256 = sha256(method.source.as_bytes());
                let parser_unit_id = format!(
                    "{}:{}:{}:{}:{}",
                    entry.repository_path,
                    method.name,
                    method.start_line,
                    method.end_line,
                    source_sha256
                );
                if !parser_unit_ids.insert(parser_unit_id.clone()) {
                    return Err(format!(
                        "intentional-boundary parser repeated unit identity {parser_unit_id}"
                    ));
                }
                Ok(IntentionalBoundaryMethodCensusEntry {
                    parser_unit_id,
                    symbol_name: method.name,
                    start_line: method.start_line,
                    end_line: method.end_line,
                    source_sha256,
                    is_exported: method.is_exported,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        source_files.push(IntentionalBoundarySourceFile {
            repository_path: entry.repository_path.clone(),
            object_id: entry.object_id.clone(),
            byte_length: expected_length,
            source_sha256: sha256(&committed_bytes),
            language: adapter.name,
            methods,
        });
    }
    source_files.sort_by(|left, right| left.repository_path.cmp(&right.repository_path));
    let method_count = source_files.iter().map(|file| file.methods.len()).sum();
    let mut census = IntentionalBoundarySourceCensus {
        schema_version: INTENTIONAL_BOUNDARY_SOURCE_CENSUS_SCHEMA_VERSION,
        census_contract: SOURCE_CENSUS_CONTRACT.to_string(),
        repository: inventory.repository.clone(),
        revision: inventory.revision.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        tracked_entry_count: inventory.tracked_entries.len(),
        source_file_count: source_files.len(),
        method_count,
        source_files,
        census_sha256: String::new(),
    };
    census.census_sha256 = compute_census_sha256(&census)?;
    Ok(census)
}

pub fn validate_intentional_boundary_source_census(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    census: &IntentionalBoundarySourceCensus,
) -> Result<(), String> {
    let expected = census_intentional_boundary_repository(repository, revision, root, inventory)?;
    if census != &expected {
        return Err("intentional-boundary source census changed".to_string());
    }
    Ok(())
}

fn compute_census_sha256(census: &IntentionalBoundarySourceCensus) -> Result<String, String> {
    let bytes = serde_json::to_vec(&(
        census.schema_version,
        &census.census_contract,
        &census.repository,
        &census.revision,
        &census.inventory_sha256,
        census.tracked_entry_count,
        &census.source_files,
        census.source_file_count,
        census.method_count,
    ))
    .map_err(|error| format!("failed to commit intentional-boundary source census: {error}"))?;
    Ok(sha256(&bytes))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::benchmark::inventory_intentional_boundary_repository;
    use std::process::Command;
    use tempfile::TempDir;

    fn git(root: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    fn repository() -> (TempDir, String) {
        let root = tempfile::tempdir().unwrap();
        git(root.path(), &["init", "--quiet"]);
        git(root.path(), &["config", "user.name", "SniffBench"]);
        git(
            root.path(),
            &["config", "user.email", "bench@example.invalid"],
        );
        git(
            root.path(),
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/example/census.git",
            ],
        );
        fs::create_dir_all(root.path().join("src/generated")).unwrap();
        fs::create_dir_all(root.path().join("tests")).unwrap();
        fs::write(
            root.path().join("src/lib.rs"),
            "pub fn production() -> u8 { 1 }\n",
        )
        .unwrap();
        fs::write(
            root.path().join("src/generated/model.rs"),
            "pub fn generated() -> u8 { 2 }\n",
        )
        .unwrap();
        fs::write(
            root.path().join("tests/value.rs"),
            "#[test] fn behavior() { assert_eq!(1, 1); }\n",
        )
        .unwrap();
        fs::write(root.path().join("README.md"), "fixture\n").unwrap();
        git(root.path(), &["add", "."]);
        git(root.path(), &["commit", "--quiet", "-m", "fixture"]);
        let revision = git(root.path(), &["rev-parse", "HEAD"]);
        (root, revision)
    }

    #[test]
    fn censuses_every_supported_committed_source_without_walker_roles() {
        let (root, revision) = repository();
        let inventory = inventory_intentional_boundary_repository(
            "github.com/example/census",
            &revision,
            root.path(),
        )
        .unwrap();

        let census = census_intentional_boundary_repository(
            "github.com/example/census",
            &revision,
            root.path(),
            &inventory,
        )
        .unwrap();

        assert_eq!(census.tracked_entry_count, 4);
        assert_eq!(census.source_file_count, 3);
        assert_eq!(census.method_count, 3);
        assert_eq!(
            census
                .source_files
                .iter()
                .map(|file| file.repository_path.as_str())
                .collect::<Vec<_>>(),
            ["src/generated/model.rs", "src/lib.rs", "tests/value.rs"]
        );
        validate_intentional_boundary_source_census(
            "github.com/example/census",
            &revision,
            root.path(),
            &inventory,
            &census,
        )
        .unwrap();
    }

    #[test]
    fn parser_consumes_the_verified_blob_bytes_not_a_separate_read() {
        let source = b"pub fn exact() -> u8 { 1 }\n";
        let parsed = crate::parser::parse_source_checked("src/lib.rs", source).unwrap();

        assert_eq!(parsed.source.as_bytes(), source);
        assert_eq!(parsed.methods.len(), 1);
        assert_eq!(parsed.methods[0].name, "exact");
    }

    #[test]
    fn replay_rejects_census_tampering() {
        let (root, revision) = repository();
        let inventory = inventory_intentional_boundary_repository(
            "github.com/example/census",
            &revision,
            root.path(),
        )
        .unwrap();
        let mut census = census_intentional_boundary_repository(
            "github.com/example/census",
            &revision,
            root.path(),
            &inventory,
        )
        .unwrap();
        census.source_files[0].methods[0].is_exported = false;

        assert!(
            validate_intentional_boundary_source_census(
                "github.com/example/census",
                &revision,
                root.path(),
                &inventory,
                &census,
            )
            .unwrap_err()
            .contains("changed")
        );
    }
}
